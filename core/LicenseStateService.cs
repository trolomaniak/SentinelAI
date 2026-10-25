using SentinelAI.Core.Persistence;
using SentinelAI.Licensing;

namespace SentinelAI.Core;

public sealed record LicenseStatus(
    string Mode,
    LicenseCapabilities Capabilities,
    DateTimeOffset? LastSuccessfulValidationUtc,
    DateTimeOffset? FullModeUntil,
    DateTimeOffset EffectiveUtc,
    bool ClockRollbackDetected,
    IReadOnlyList<string> EnabledFeatures);

/// <summary>
/// MVP-3 pilot license status: unavailable (this build has no pilot keys), none, invalid, scheduled, active, ending
/// (the last seven days), or ended. Evaluated at the effective time, so turning the clock back cannot extend a pilot.
/// </summary>
public sealed record PilotLicenseView(string State, string? Customer, DateTimeOffset? StartsUtc, DateTimeOffset? ExpiresUtc,
    int? DaysLeft, DateTimeOffset EffectiveUtc, PilotContact? Contact);
public enum PilotKeyOutcome { Accepted, Invalid, Expired, Unavailable }
public sealed record PilotKeyResult(PilotKeyOutcome Outcome, PilotLicenseView Status);
public sealed record PilotKeyRequest(string? Key)
{
    public override string ToString() => nameof(PilotKeyRequest);
}

/// <summary>Local licensing policy. Monitoring never depends on a successful renewal.</summary>
public sealed class LicenseStateService(
    LicenseVerificationOptions options,
    EnrollmentStore enrollments,
    LicenseStateStore store,
    LicenseClock clock,
    ILicenseLeaseClient client,
    PilotLicenseOptions pilot)
{
    public static readonly TimeSpan PilotWarningPeriod = TimeSpan.FromDays(7);

    private readonly SemaphoreSlim _stateGate = new(1, 1);
    private readonly SemaphoreSlim _renewalGate = new(1, 1);
    private int _recovering;

    public bool Configured => client.Configured;

    public async Task<LicenseStatus> GetAsync(CancellationToken cancellationToken = default)
    {
        await _stateGate.WaitAsync(cancellationToken);
        try
        {
            var state = await ObserveAsync(cancellationToken);
            var identity = await enrollments.GetCoreIdentityAsync(cancellationToken);
            return Snapshot(state, options.Verifier.Authenticate(state.Lease,
                identity.OrganizationId, identity.CoreInstallationId), Volatile.Read(ref _recovering) != 0);
        }
        finally { _stateGate.Release(); }
    }

    public async Task<LicenseStatus> RenewAsync(CancellationToken cancellationToken = default)
    {
        await _renewalGate.WaitAsync(cancellationToken);
        Interlocked.Exchange(ref _recovering, 1);
        try
        {
            // Network I/O is outside the state lock: status and local monitoring remain available.
            var identity = await enrollments.GetCoreIdentityAsync(cancellationToken);
            var token = client.Configured ? await client.FetchAsync(identity, cancellationToken) : null;
            await _stateGate.WaitAsync(cancellationToken);
            try
            {
                var state = await LoadAsync(cancellationToken);
                var reading = clock.Observe(state.HighWaterUtc);
                var authenticated = options.Verifier.Authenticate(token,
                    identity.OrganizationId, identity.CoreInstallationId);
                // Only signature- and identity-authenticated server time can advance the floor.
                // A replay never resets receipt time or extends the signed seven-day deadline.
                if (authenticated is { } candidate &&
                    (state.LastSuccessfulValidationUtc is null || candidate.Claims.IssuedAt >= state.LastSuccessfulValidationUtc))
                {
                    reading = clock.Observe(candidate.Claims.IssuedAt > reading.UtcNow
                        ? candidate.Claims.IssuedAt : reading.UtcNow);
                    if (candidate.Claims.FullModeUntil > reading.UtcNow)
                    {
                        state = state with
                        {
                            Lease = token,
                            LastSuccessfulValidationUtc = candidate.Claims.IssuedAt,
                            LastAttemptSucceeded = true
                        };
                    }
                    else state = state with { LastAttemptSucceeded = false };
                }
                else state = state with { LastAttemptSucceeded = false };

                state = state with
                {
                    HighWaterUtc = reading.UtcNow,
                    ClockRollbackDetected = state.ClockRollbackDetected || reading.RollbackDetected
                };
                await store.SaveAsync(state, cancellationToken);
                var retained = options.Verifier.Authenticate(state.Lease,
                    identity.OrganizationId, identity.CoreInstallationId);
                return Snapshot(state, retained, recovering: false);
            }
            finally { _stateGate.Release(); }
        }
        finally
        {
            Interlocked.Exchange(ref _recovering, 0);
            _renewalGate.Release();
        }
    }

    public async Task<PilotLicenseView> GetPilotAsync(CancellationToken cancellationToken = default)
    {
        await _stateGate.WaitAsync(cancellationToken);
        try { return PilotView(await ObserveAsync(cancellationToken)); }
        finally { _stateGate.Release(); }
    }

    /// <summary>Stores a key that is valid now or later, replacing the current one; an expired or invalid key changes nothing.</summary>
    public async Task<PilotKeyResult> SetPilotKeyAsync(string key, CancellationToken cancellationToken = default)
    {
        await _stateGate.WaitAsync(cancellationToken);
        try
        {
            var state = await ObserveAsync(cancellationToken);
            if (!pilot.Configured) return new(PilotKeyOutcome.Unavailable, PilotView(state));
            var result = pilot.Verifier.Verify(key, state.HighWaterUtc);
            if (result.Status is PilotLicenseStatus.Invalid or PilotLicenseStatus.Expired)
                return new(result.Status == PilotLicenseStatus.Expired ? PilotKeyOutcome.Expired : PilotKeyOutcome.Invalid, PilotView(state));
            state = state with { PilotKey = key.Trim(' ', '\t', '\r', '\n') };
            await store.SaveAsync(state, cancellationToken);
            return new(PilotKeyOutcome.Accepted, PilotView(state));
        }
        finally { _stateGate.Release(); }
    }

    private PilotLicenseView PilotView(LicenseStoredState state)
    {
        var now = state.HighWaterUtc;
        if (!pilot.Configured) return new("unavailable", null, null, null, null, now, pilot.Contact);
        if (state.PilotKey is null) return new("none", null, null, null, null, now, pilot.Contact);
        var result = pilot.Verifier.Verify(state.PilotKey, now);
        if (result.Claims is not { } claims) return new("invalid", null, null, null, null, now, pilot.Contact);
        var (name, daysLeft) = result.Status switch
        {
            PilotLicenseStatus.NotYetValid => ("scheduled", (int?)null),
            PilotLicenseStatus.Expired => ("ended", 0),
            _ => (claims.ExpiresAt - now <= PilotWarningPeriod ? "ending" : "active", (int)Math.Ceiling((claims.ExpiresAt - now).TotalDays))
        };
        return new(name, claims.Customer, claims.IssuedAt, claims.ExpiresAt, daysLeft, now, pilot.Contact);
    }

    // Reads the persisted state and advances the effective time; the clock floor is saved before any decision.
    private async Task<LicenseStoredState> ObserveAsync(CancellationToken cancellationToken)
    {
        var state = await LoadAsync(cancellationToken);
        var reading = clock.Observe(state.HighWaterUtc);
        state = state with
        {
            HighWaterUtc = reading.UtcNow,
            ClockRollbackDetected = state.ClockRollbackDetected || reading.RollbackDetected
        };
        await store.SaveAsync(state, cancellationToken);
        return state;
    }

    private async Task<LicenseStoredState> LoadAsync(CancellationToken cancellationToken) =>
        await store.LoadAsync(cancellationToken) ?? new(null, null, DateTimeOffset.MinValue, false, false);

    private static LicenseStatus Snapshot(LicenseStoredState state, AuthenticatedLease? lease, bool recovering)
    {
        // Persisted unsigned metadata cannot move a signed lease's validation baseline.
        var trusted = lease is not null && state.LastSuccessfulValidationUtc == lease.Claims.IssuedAt;
        var expires = trusted ? lease!.Claims.FullModeUntil : (DateTimeOffset?)null;
        var mode = LicenseStateMachine.Evaluate(state.HighWaterUtc, state.LastSuccessfulValidationUtc,
            expires, trusted, state.LastAttemptSucceeded, recovering);
        var capabilities = LicenseStateMachine.Capabilities(state.HighWaterUtc, state.LastSuccessfulValidationUtc,
            expires, trusted, state.LastAttemptSucceeded, recovering);
        IReadOnlyList<string> features = trusted && capabilities.PremiumFeatures
            ? lease!.Claims.EnabledFeatures : Array.Empty<string>();
        return new(mode switch
        {
            LicenseMode.Full => "FULL",
            LicenseMode.Grace => "GRACE",
            LicenseMode.Recovering => "RECOVERING",
            _ => "SAFE_MODE"
        }, capabilities, trusted ? state.LastSuccessfulValidationUtc : null,
            expires, state.HighWaterUtc, state.ClockRollbackDetected, features);
    }
}
