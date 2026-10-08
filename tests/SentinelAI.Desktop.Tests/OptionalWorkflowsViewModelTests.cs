using SentinelAI.Contracts.Ai;
using SentinelAI.Desktop.Foundation;

internal static class OptionalWorkflowsViewModelTests
{
    private static int _assertions;
    internal static async Task<int> RunAsync()
    {
        await LicenseAsync();
        await AiAsync();
        Console.WriteLine($"Desktop optional workflows: {_assertions} assertions passed.");
        return _assertions;
    }

    private static LicenseStatus Snapshot(string mode, IReadOnlyList<string>? features = null) => new(mode,
        new(true, true, true, true, true, mode != "SAFE_MODE"), null, null,
        new DateTimeOffset(2026, 10, 8, 0, 0, 0, TimeSpan.Zero), false,
        features ?? (mode == "SAFE_MODE" ? [] : ["cloud_ai"]));

    private static async Task LicenseAsync()
    {
        var client = new LicenseClient();
        using var vm = new LicenseViewModel(client);
        Check(vm.Status is null && !vm.CanRenew && vm.CanRefresh && client.Reads == 0, "License construction must not make a request or invent state.");
        await vm.RenewAsync();
        Check(client.Renewals == 0, "Unknown license allowed a renewal.");
        foreach (var mode in new[] { "FULL", "GRACE", "SAFE_MODE", "RECOVERING" })
        {
            var features = mode == "SAFE_MODE" ? new List<string>() : new List<string> { "cloud_ai", "Feature-2" };
            client.Read = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Success, Snapshot(mode, features)));
            await vm.RefreshAsync();
            Check(vm.State == LicenseState.Ready && vm.ModeText == mode && vm.Status!.Capabilities.LocalDetectionRules,
                "License mode or local baseline differed from Core.");
            Check(vm.CanRenew == (mode != "RECOVERING") && vm.Status!.Capabilities.PremiumFeatures == (mode != "SAFE_MODE"),
                "RECOVERING or Safe Mode permissions were inferred incorrectly.");
            features.Add("injected");
            Check(!vm.FeaturesText.Contains("injected", StringComparison.Ordinal), "License display retained mutable service-owned feature data.");
        }
        foreach (var mode in new[] { "FULL", "GRACE", "SAFE_MODE" })
        {
            client.Read = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Success, Snapshot("FULL")));
            await vm.RefreshAsync();
            client.Renew = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Success, Snapshot(mode)));
            await vm.RenewAsync();
            Check(vm.ModeText == mode && vm.RenewalStatusText.Contains(mode, StringComparison.Ordinal), "Renewal ignored Core's resulting mode.");
            Check(mode == "FULL" || vm.RenewalStatusText.Contains("without restoring FULL", StringComparison.Ordinal), "A failed completed renewal claimed success.");
        }
        foreach (var outcome in new[] { LicenseRequestOutcome.Indeterminate, LicenseRequestOutcome.InvalidResponse, LicenseRequestOutcome.TooLarge })
        {
            await vm.RefreshAsync();
            client.Renew = _ => Task.FromResult(new LicenseRequestResult(outcome));
            var before = client.Renewals;
            await vm.RenewAsync();
            Check(vm.RequiresRefresh && !vm.CanRenew && vm.Status is null, "An uncertain renewal could be replayed.");
            await vm.RenewAsync();
            Check(client.Renewals == before + 1, "Renewal was automatically repeated.");
            await vm.RefreshAsync();
            Check(!vm.RequiresRefresh && vm.CanRenew, "Explicit refresh did not resolve the renewal gate.");
        }
        foreach (var outcome in new[] { LicenseRequestOutcome.Unavailable, LicenseRequestOutcome.Throttled, LicenseRequestOutcome.UntrustedConnection })
        {
            await vm.RefreshAsync();
            client.Renew = _ => Task.FromResult(new LicenseRequestResult(outcome));
            await vm.RenewAsync();
            Check(vm.State == LicenseState.Unavailable && !vm.CanRenew && vm.ErrorText.Length > 0,
                "Unavailable renewal retained unverified permissions.");
        }
        client.Read = _ => Task.FromException<LicenseRequestResult>(new Exception("synthetic-secret-lease-body"));
        await vm.RefreshAsync();
        Check(!vm.ErrorText.Contains("synthetic-secret", StringComparison.Ordinal), "Private exception text reached licensing output.");
        var held = new TaskCompletionSource<LicenseRequestResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken heldToken = default;
        client.Read = token => { heldToken = token; return held.Task; };
        var old = vm.RefreshAsync();
        Check(ReferenceEquals(old, vm.RefreshAsync()) && vm.IsBusy, "Concurrent reads did not join one bounded operation.");
        var expiries = 0;
        vm.SessionExpired += (_, _) => expiries++;
        vm.Clear();
        Check(heldToken.IsCancellationRequested && vm.Status is null, "Session clearing did not cancel licensing.");
        client.Read = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Success, Snapshot("GRACE")));
        await vm.RefreshAsync();
        held.SetResult(new(LicenseRequestOutcome.Unauthenticated));
        await old.WaitAsync(TimeSpan.FromSeconds(3));
        Check(expiries == 0 && vm.ModeText == "GRACE", "An old 401 expired a fresh workspace.");
        client.Read = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Unauthenticated));
        await vm.RefreshAsync();
        Check(expiries == 1 && vm.Status is null && vm.State == LicenseState.NotLoaded, "Current 401 did not clear licensing and expire the session.");
        vm.Dispose();
        Check(!vm.CanRefresh && !vm.CanRenew, "Disposed license view still accepted actions.");
        await vm.RefreshAsync();
    }

    private static AlertDetail Alert(Guid id, long version = 1) => new(
        new(id, Guid.NewGuid(), "synthetic-endpoint", "SA-FW-001", "Firewall", "high", "open",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, version), "Local reason",
        [new("securityPosture.domainFirewallEnabled", AlertEvidenceKind.Boolean, false)], "Review", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, [], 0);
    private static readonly AiExplanation Analysis = new("<script>literal</script>", "Local impact",
        ["Inspect the local configuration."], ["Review before changing configuration."], "medium", "Synthetic evidence only.");

    private static async Task AiAsync()
    {
        var client = new AiClient();
        using var vm = new AiExplanationViewModel(client);
        var first = Alert(Guid.NewGuid());
        vm.SetAlert(first);
        vm.SetAvailability(true);
        Check(!vm.CloudRequestsEnabled && !vm.CanExplain && client.Calls == 0, "AI requests require explicit session consent.");
        await vm.ExplainAsync();
        Check(client.Calls == 0, "Disabled AI sent a request.");
        vm.CloudRequestsEnabled = true;
        vm.SetAvailability(null);
        Check(!vm.CanExplain && vm.State == AiExplanationState.AvailabilityUnknown, "Unknown license permission enabled AI.");
        vm.SetAvailability(false);
        Check(!vm.CanExplain && vm.State == AiExplanationState.Disabled, "Safe Mode enabled AI.");
        vm.SetAvailability(true);
        Check(vm.CanExplain && client.Calls == 0, "Enabling consent made an automatic request.");
        await vm.ExplainAsync();
        Check(vm.HasAnalysis && vm.Label == "AI assistive analysis" && vm.Analysis!.Explanation == Analysis.Explanation && client.LastId == first.Alert.AlertId,
            "Explicit selected-alert analysis lost its literal assistive output.");
        vm.SetAlert(first);
        Check(vm.HasAnalysis, "Unchanged alert notifications unnecessarily erased analysis.");
        vm.SetAlert(Alert(first.Alert.AlertId, 2));
        Check(!vm.HasAnalysis && vm.CanExplain, "New alert version retained obsolete analysis.");
        foreach (var outcome in new[] { AiExplanationOutcome.Unavailable, AiExplanationOutcome.Throttled, AiExplanationOutcome.InvalidResponse,
            AiExplanationOutcome.UntrustedConnection, AiExplanationOutcome.Disabled, AiExplanationOutcome.Unsupported, AiExplanationOutcome.NotFound })
        {
            vm.SetAlert(Alert(Guid.NewGuid()));
            vm.SetAvailability(true);
            client.Answer = _ => Task.FromResult(new AiExplanationResult(outcome));
            var before = client.Calls;
            await vm.ExplainAsync();
            Check(!vm.HasAnalysis && vm.ErrorText.Length > 0 && client.Calls == before + 1, "AI failure displayed analysis or retried.");
            Check(vm.StatusText.Contains("Local", StringComparison.Ordinal), "AI failure did not explain continued local security availability.");
        }
        vm.SetAlert(first);
        vm.SetAvailability(true);
        client.Answer = _ => Task.FromException<AiExplanationResult>(new Exception("synthetic-gateway-key"));
        await vm.ExplainAsync();
        Check(!vm.ErrorText.Contains("synthetic-gateway", StringComparison.Ordinal), "AI exception text exposed private material.");
        var held = new TaskCompletionSource<AiExplanationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken heldToken = default;
        client.Answer = token => { heldToken = token; return held.Task; };
        var old = vm.ExplainAsync();
        Check(ReferenceEquals(old, vm.ExplainAsync()) && vm.IsBusy, "Concurrent AI actions did not join the explicit request.");
        vm.CloudRequestsEnabled = false;
        Check(heldToken.IsCancellationRequested && !vm.HasAnalysis && !vm.CanExplain, "Disabling AI did not cancel and clear the request.");
        vm.CloudRequestsEnabled = true;
        var second = Alert(Guid.NewGuid());
        vm.SetAlert(second);
        client.Answer = _ => Task.FromResult(new AiExplanationResult(AiExplanationOutcome.Success, Analysis));
        await vm.ExplainAsync();
        held.SetResult(new(AiExplanationOutcome.Success, Analysis with { Explanation = "obsolete" }));
        await old.WaitAsync(TimeSpan.FromSeconds(3));
        Check(vm.SelectedAlertId == second.Alert.AlertId && vm.Analysis!.Explanation != "obsolete", "Obsolete AI overwrote a new alert.");
        vm.SetAlert(null);
        Check(vm.CloudRequestsEnabled && !vm.HasAnalysis && vm.SelectedAlertId is null, "Navigation must clear AI content while keeping the session setting.");
        vm.SetAlert(first with { Evidence = [] });
        Check(!vm.IsSupportedAlert && !vm.CanExplain, "Unsupported evidence enabled AI.");
        vm.SetAlert(first with { Alert = first.Alert with { RuleId = "unsupported" } });
        Check(!vm.IsSupportedAlert, "Unknown rule enabled cloud requests.");
        vm.SetAlert(first);
        var expiry = 0;
        vm.SessionExpired += (_, _) => expiry++;
        held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Answer = _ => held.Task;
        old = vm.ExplainAsync();
        vm.Clear();
        vm.SetAlert(second); vm.SetAvailability(true); vm.CloudRequestsEnabled = true;
        held.SetResult(new(AiExplanationOutcome.Unauthenticated));
        await old.WaitAsync(TimeSpan.FromSeconds(3));
        Check(expiry == 0 && vm.SelectedAlertId == second.Alert.AlertId && vm.CanExplain, "Old AI 401 expired a fresh workspace.");
        client.Answer = _ => Task.FromResult(new AiExplanationResult(AiExplanationOutcome.Unauthenticated));
        await vm.ExplainAsync();
        Check(expiry == 1 && !vm.CloudRequestsEnabled && vm.SelectedAlertId is null, "Current AI 401 did not clear session consent and selection.");
        vm.Dispose();
        Check(!vm.CanExplain && !vm.HasAnalysis && !vm.CloudRequestsEnabled, "Closing retained AI output or session consent.");
        await vm.ExplainAsync();
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); _assertions++; }
    private sealed class LicenseClient : ILicenseClient
    {
        internal int Reads, Renewals;
        internal Func<CancellationToken, Task<LicenseRequestResult>> Read = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Success, Snapshot("FULL")));
        internal Func<CancellationToken, Task<LicenseRequestResult>> Renew = _ => Task.FromResult(new LicenseRequestResult(LicenseRequestOutcome.Unavailable));
        public Task<LicenseRequestResult> GetLicenseAsync(CancellationToken token) { Reads++; return Read(token); }
        public Task<LicenseRequestResult> RenewLicenseAsync(CancellationToken token) { Renewals++; return Renew(token); }
    }
    private sealed class AiClient : IAiExplanationClient
    {
        internal int Calls; internal Guid LastId;
        internal Func<CancellationToken, Task<AiExplanationResult>> Answer = _ => Task.FromResult(new AiExplanationResult(AiExplanationOutcome.Success, Analysis));
        public Task<AiExplanationResult> ExplainAlertAsync(Guid id, CancellationToken token) { Calls++; LastId = id; return Answer(token); }
    }
}
