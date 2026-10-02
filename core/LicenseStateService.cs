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

/// <summary>Local licensing policy. Monitoring never depends on a successful renewal.</summary>
public sealed class LicenseStateService(
    LicenseVerificationOptions options,
    EnrollmentStore enrollments,
    LicenseStateStore store,
    LicenseClock clock,
    ILicenseLeaseClient client)
{
    private readonly SemaphoreSlim _stateGate = new(1, 1);
    private readonly SemaphoreSlim _renewalGate = new(1, 1);
    private int _recovering;

    public bool Configured => client.Configured;

    public async Task<LicenseStatus> GetAsync(CancellationToken cancellationToken = default)
    {
        await _stateGate.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadAsync(cancellationToken);
            var reading = clock.Observe(state.HighWaterUtc);
            state = state with
            {
                HighWaterUtc = reading.UtcNow,
                ClockRollbackDetected = state.ClockRollbackDetected || reading.RollbackDetected
            };
            await store.SaveAsync(state, cancellationToken);
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
