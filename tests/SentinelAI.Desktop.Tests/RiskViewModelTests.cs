using System.Globalization;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Scoring;

internal static class RiskViewModelTests
{
    private static int assertions;
    private static readonly DateTimeOffset Observation = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private const string Literal = "<script>literal</script> {Binding Password} https://example.invalid";
    private static readonly ScoringPolicySnapshot Policy = new("risk-test", Map(("info", 1m), ("low", 5m), ("medium", 15m), ("high", 25m), ("critical", 50m)),
        1m, Map(("firewall.disabled", 0.5m)), Map(("low", 0.75m), ("standard", 1m), ("high", 1.5m), ("critical", 2m)),
        Map(("isolated", 0.75m), ("internal", 1m), ("internet", 1.5m), ("unknown", 1m)),
        Map(("open", 1m), ("investigating", 1m), ("accepted", 1m), ("resolved", 0m)), 7, 30, 0.75m, 0.5m, 5m, 20m,
        new Dictionary<string, string> { ["firewall.disabled"] = "FW", ["uac.disabled"] = "UAC" }, 100);

    public static async Task<int> RunAsync()
    {
        PresentationTests();
        await RankedPagingAsync();
        await ReadStatesAsync();
        await ShrinkingPageAsync();
        await CorrectionReadRacesAsync();
        await DetailConcurrencyAsync();
        await SessionAndDisposeRacesAsync();
        Console.WriteLine($"Desktop risk: {assertions} assertions passed.");
        return assertions;
    }

    private static void PresentationTests()
    {
        var summary = Summary(1) with { EndpointName = Literal, RawScore = 0.375m, Score = 0, HighestContributorReason = Literal };
        var row = new EndpointRiskRow(summary, 51);
        Check(row.Rank == 51 && row.Score == 0 && row.RawScore == 0.375m && row.RawScoreText == "0.375", "A positive raw score was rounded away or risk rank was recomputed.");
        Check(row.EndpointName == Literal && row.HighestContributorReason == Literal && row.InventoryState == "current" && row.SignalCoverage == "partial", "Core text/coverage was altered or interpreted.");
        Check(new EndpointRiskRow(summary with { InventoryCollectedUtc = null, Coverage = MissingCoverage() }, 1).InventoryCollectedText == "Unknown / not reported", "Missing inventory was replaced by an inferred observation.");
        var organization = new OrganizationRiskPresentation(Page(0, 1, summary) with
        {
            Organization = Organization(1) with { Score = 0, Explanation = Literal, HighestRiskEndpointIdsTruncated = true, HighestRiskEndpointCount = 7 },
            Policy = Policy with { Version = Literal }
        });
        Check(organization.Score == 0 && organization.Explanation == Literal && Fact(organization.PolicyFacts, "Policy version") == Literal, "Organization score, explanation or policy text was computed/treated as markup.");
        foreach (var (label, expected) in new[]
        {
            ("Endpoints", "1"), ("Observed endpoints", "1"), ("Missing inventory", "0"),
            ("Unknown signal coverage", "0"), ("Partial signal coverage", "1"), ("Stale inventory", "0"),
            ("Open alerts", "3"), ("Investigating alerts", "2"), ("Accepted alerts", "1"), ("Resolved alerts", "4"),
            ("Highest-risk endpoint count", "7"), ("Highest-risk IDs truncated", "True"), ("Method", "maximum")
        }) Check(Fact(organization.Facts, label) == expected, $"Organization fact '{label}' was missing or inferred.");
        Check(Fact(organization.Facts, "Highest-risk endpoint IDs") == Id(1).ToString("D"), "Highest-risk representative IDs lost their public identity.");
        Check(Fact(organization.Facts, "Score interpretation").Contains("zero score does not establish", StringComparison.Ordinal), "A zero score lacked its protection/coverage limitation.");
        foreach (var (label, expected) in new[]
        {
            ("Inventory freshness (hours)", "12"), ("Fresh observation age (days)", "7"), ("Aging observation age (days)", "30"),
            ("Default confidence weight", "1"), ("Confidence override: firewall.disabled", "0.5"),
            ("Severity points: critical", "50"), ("Asset multiplier: critical", "2"),
            ("Exposure multiplier: internet", "1.5"), ("Remaining risk: accepted", "1"), ("Remaining risk: resolved", "0"),
            ("Aging multiplier", "0.75"), ("Old multiplier", "0.5"), ("Correlation points per extra group", "5"),
            ("Maximum correlation base bonus", "20"), ("Correlation group: firewall.disabled", "FW")
        }) Check(Fact(organization.PolicyFacts, label) == expected, $"Policy fact '{label}' was rounded, omitted or confused with coverage freshness.");

        var contribution = Contribution(1001);
        var detail = Detail(1) with
        {
            EndpointName = Literal,
            Risk = Detail(1).Risk with { RawScore = 150.1234567890123456789012345m, Explanation = Literal, Contributions = new[] { contribution } },
            Alerts = new[] { Alert(1001) with { Title = Literal, Reason = Literal } },
            Coverage = Coverage() with { Caution = Literal }
        };
        var presentation = new EndpointRiskPresentation(detail);
        Check(presentation.EndpointId == Id(1) && presentation.Name == Literal && presentation.Explanation == Literal && presentation.Saturated && presentation.Score == 100, "Endpoint identity/explanation or Core saturation/score was altered.");
        Check(presentation.RawScore == detail.Risk.RawScore && Fact(presentation.Facts, "Raw score") == "150.1234567890123456789012345", "Core decimal raw score lost precision.");
        foreach (var (label, expected) in new[]
        {
            ("Asset criticality", "critical"), ("Asset criticality source", "userDeclared"), ("Asset criticality multiplier", "2"),
            ("Declared exposure", "internet"), ("Exposure source", "userDeclared"), ("Exposure multiplier", "1.5"),
            ("Correlation groups", "FW, UAC"), ("Correlation base bonus", "20"), ("Correlation bonus", "60"), ("Saturated", "True")
        }) Check(Fact(presentation.Facts, label) == expected, $"Endpoint factor '{label}' was not exposed exactly.");
        Check(Fact(presentation.CoverageFacts, "Coverage caution") == Literal && Fact(presentation.CoverageFacts, "Known rule signals") == "7" && Fact(presentation.CoverageFacts, "Total rule signals") == "13", "Coverage values/caution were discarded.");
        var factor = presentation.Contributions.Single();
        Check(ReferenceEquals(factor.Source, contribution) && factor.Title == Literal && factor.Reason == Literal, "Contribution factors were recomputed or mapped to the wrong alert's text.");
        foreach (var (label, expected) in new[]
        {
            ("Alert ID", Id(1001).ToString("D")), ("Rule ID", "firewall.disabled"), ("Title", Literal), ("Reason", Literal),
            ("Severity", "critical"), ("Status", "accepted"), ("Age (days)", "10.125"), ("Age band", "aging"),
            ("Future timestamp clamped", "False"), ("Severity points", "50"), ("Confidence weight", "0.5"),
            ("Confidence source", "ruleOverride"), ("Asset multiplier", "2"), ("Exposure multiplier", "1.5"),
            ("Age multiplier", "0.75"), ("Remaining risk multiplier", "1"), ("Points before status effect", "56.25"),
            ("Status reduction", "0"), ("Contribution", "56.25"), ("Correlation group", "FW"),
            ("Latest snapshot confirmed", "True"), ("Correlation eligible", "False")
        }) Check(Fact(factor.Factors, label) == expected, $"Contribution factor '{label}' lost its authoritative value.");
        Check(factor.Contribution == 56.25m && factor.ContributionText == "56.25" && factor.Factors.Count == 23, "Not all deterministic contribution factors were exposed.");
        var resolved = new RiskContributionRow(contribution with { Status = "resolved", RemainingRiskMultiplier = 0m, MitigationReduction = 56.25m, Contribution = 0m }, null);
        Check(Fact(resolved.Factors, "Remaining risk multiplier") == "0" && Fact(resolved.Factors, "Status reduction") == "56.25" && resolved.Contribution == 0m && resolved.Title == "Unknown / not reported", "Status reduction or absent public alert text was inferred.");
        var missing = new EndpointRiskPresentation(detail with { InventoryCollectedUtc = null, Coverage = MissingCoverage(), Risk = detail.Risk with { Context = new("standard", "unknown", null, "policyDefault", "policyDefault"), CorrelatedGroups = Array.Empty<string>(), Contributions = Array.Empty<AlertRiskContribution>() }, Alerts = Array.Empty<RiskAlertView>() });
        Check(Fact(missing.CoverageFacts, "Inventory state") == "missing" && Fact(missing.CoverageFacts, "Signal coverage") == "unknown" && Fact(missing.Facts, "Declared exposure") == "unknown", "Missing coverage or declared exposure was guessed from posture.");
        Check(Fact(missing.Facts, "Asset criticality source") == "policyDefault" && Fact(missing.Facts, "Exposure source") == "policyDefault" && Fact(missing.Facts, "Latest scoring inventory") == "Unknown / not reported" && Fact(missing.Facts, "Correlation groups") == "None", "Default context, missing timestamp or empty correlation was obscured.");
        Check(((ICollection<DisplayFact>)presentation.Facts).IsReadOnly && ((ICollection<DisplayFact>)presentation.CoverageFacts).IsReadOnly && ((ICollection<DisplayFact>)presentation.PolicyFacts).IsReadOnly && ((ICollection<RiskContributionRow>)presentation.Contributions).IsReadOnly && ((ICollection<DisplayFact>)factor.Factors).IsReadOnly, "The view can mutate Risk facts or contributing factors.");
        var culture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("pl-PL");
            var localized = new EndpointRiskRow(summary with { EvaluatedUtc = Observation.ToOffset(TimeSpan.FromHours(3)) }, 1);
            Check(localized.EvaluatedText == "2026-10-04 12:00:00 UTC" && localized.RawScoreText == "0.375", "Risk timestamps/decimals became locale-dependent or lost explicit UTC.");
        }
        finally { CultureInfo.CurrentCulture = culture; }
        Throws<ArgumentNullException>(() => _ = new EndpointRiskRow(null!, 1), "Null risk summary was accepted.");
        Throws<ArgumentNullException>(() => _ = new EndpointRiskPresentation(null!), "Null risk detail was accepted.");
        Throws<ArgumentNullException>(() => _ = new RiskContributionRow(null!, null), "Null contribution was accepted.");
    }

    private static async Task RankedPagingAsync()
    {
        var client = new ControlledClient();
        using var vm = new RiskViewModel(client);
        Check(vm.ListState == RiskListState.NotLoaded && vm.VisibleEndpoints.Count == 0 && vm.Organization is null && vm.CanRefresh, "Risk began with fabricated scores.");
        var changes = new List<string?>();
        vm.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
        var task = vm.RefreshAsync();
        Check(vm.IsLoading && !vm.CanRefresh && !task.IsCompleted && ReferenceEquals(task, vm.RefreshAsync()) && client.Pages.Count == 1, "Risk refresh blocked or failed to coalesce concurrent calls.");
        Check(client.Pages[0].Offset == 0 && client.Pages[0].Limit == 50, "Risk did not request a bounded initial server page.");
        var ranked = Enumerable.Range(1, 50).Reverse().Select(number => Summary(number) with { EndpointName = $"host{number:D3}", Score = number, RawScore = number + 0.123m }).ToArray();
        client.Pages[0].Complete(Page(0, 121, ranked));
        await Done(task);
        Check(vm.ListState == RiskListState.Ready && vm.TotalEndpoints == 121 && vm.TotalPages == 3 && vm.PageNumber == 1 && vm.VisibleEndpoints.Count == 50, "Risk page/count state was incorrect.");
        Check(vm.VisibleEndpoints.Select(row => row.EndpointId).SequenceEqual(ranked.Select(row => row.EndpointId)) && vm.VisibleEndpoints[0].Rank == 1 && vm.VisibleEndpoints[^1].Rank == 50, "Native Risk reordered or reranked Core's server page.");
        Check(vm.CanNextPage && !vm.CanPreviousPage && changes.Contains(nameof(vm.VisibleEndpoints)) && changes.Contains(nameof(vm.Organization)) && changes.Contains(nameof(vm.IsLoading)), "Risk paging/binding notifications were missing.");
        Check(((ICollection<EndpointRiskRow>)vm.VisibleEndpoints).IsReadOnly && vm.Organization!.Score == 100, "Current risk page was mutable or organization score was averaged from the page.");
        vm.SelectedEndpoint = vm.VisibleEndpoints[0];
        Throws<ArgumentException>(() => vm.SelectedEndpoint = new EndpointRiskRow(Summary(99), 1), "A row outside the current page was selected.");
        task = vm.NextPageAsync();
        Check(client.Pages[^1].Offset == 50 && client.Pages[^1].Limit == 50 && vm.SelectedEndpoint is null, "Next page reused the selection or failed to send offset/limit.");
        client.Pages[^1].Complete(Page(50, 121, Enumerable.Range(51, 50).Select(Summary).ToArray()));
        await Done(task);
        Check(vm.PageIndex == 1 && vm.VisibleEndpoints[0].Rank == 51 && vm.VisibleEndpoints[^1].Rank == 100 && vm.CanPreviousPage && vm.CanNextPage, "Global rank/paging on the middle page was incorrect.");
        task = vm.NextPageAsync();
        client.Pages[^1].Complete(Page(100, 121, Enumerable.Range(101, 21).Select(Summary).ToArray()));
        await Done(task);
        Check(vm.PageNumber == 3 && vm.VisibleEndpoints.Count == 21 && !vm.CanNextPage, "The final Core page was not bounded correctly.");
        var calls = client.Pages.Count;
        await Done(vm.NextPageAsync());
        Check(client.Pages.Count == calls, "Next fetched beyond the final page.");
        task = vm.PreviousPageAsync();
        Check(client.Pages[^1].Offset == 50, "Previous did not request the prior server offset.");
        client.Pages[^1].Complete(Page(50, 121, Enumerable.Range(51, 50).Select(Summary).ToArray()));
        await Done(task);
        task = vm.RefreshAsync();
        Check(client.Pages[^1].Offset == 0, "Explicit Risk refresh did not reset paging.");
        client.Pages[^1].Complete(Page(0, 0));
        await Done(task);
        Check(vm.ListState == RiskListState.Empty && vm.Organization is not null && vm.PageNumber == 0 && !vm.CanNextPage && !vm.CanPreviousPage && vm.ListStatusText.Contains("not a security assurance", StringComparison.Ordinal), "An empty organization hid its zero-score limitations or fabricated endpoint data.");
    }

    private static async Task ReadStatesAsync()
    {
        foreach (var outcome in new[] { RiskReadOutcome.Unavailable, RiskReadOutcome.UntrustedConnection, RiskReadOutcome.InvalidResponse, RiskReadOutcome.TooLarge })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var task = vm.RefreshAsync();
            client.Pages[0].Reply(outcome);
            await Done(task);
            Check(vm.ListState == RiskListState.Unavailable && vm.VisibleEndpoints.Count == 0 && vm.Organization is null && vm.ErrorText.Length > 0 && vm.CanRefresh, $"{outcome} failed to produce a safe retryable state.");
        }
        foreach (var invalid in new[]
        {
            Page(1, 1, Summary(1)), Page(0, 1, Summary(1)) with { Limit = 200 },
            Page(0, 2, Summary(1), Summary(1)), Page(0, 1, Summary(1) with { Score = 101 }),
            Page(0, 1, Summary(1) with { RawScore = -1m }), Page(0, 1, Summary(1)) with { Total = -1 },
            Page(0, 1, Summary(1)) with { Organization = Organization(2) },
            Page(0, 1),
            Page(0, 51, Enumerable.Range(1, 51).Select(Summary).ToArray())
        })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var task = vm.RefreshAsync();
            client.Pages[0].Complete(invalid);
            await Done(task);
            Check(vm.ListState == RiskListState.Unavailable && vm.VisibleEndpoints.Count == 0, "Wrong offset/limit, duplicate identity, invalid score/count or oversized page was accepted.");
        }
        var active = new ControlledClient();
        using var viewModel = new RiskViewModel(active);
        var failure = viewModel.RefreshAsync();
        active.Pages[^1].Fail(new IOException("private transport diagnostic"));
        await Done(failure);
        Check(!viewModel.ErrorText.Contains("private transport diagnostic", StringComparison.Ordinal) && viewModel.CanRefresh, "Risk leaked a transport exception or blocked recovery.");
        await Seed(viewModel, active, Summary(1));
        await Done(viewModel.OpenEndpointAsync(Id(999)));
        Check(viewModel.DetailState == RiskDetailState.NotFound && active.Details.Count == 0, "An arbitrary endpoint outside the ranked page triggered a read.");
        var detailTask = viewModel.OpenEndpointAsync(Id(1));
        Check(viewModel.IsLoadingDetail && !viewModel.CanRefreshDetail && ReferenceEquals(detailTask, viewModel.RefreshDetailAsync()), "Detail requests failed to coalesce or expose loading.");
        active.Details[^1].Reply(RiskReadOutcome.NotFound);
        await Done(detailTask);
        Check(viewModel.DetailState == RiskDetailState.NotFound && viewModel.Detail is null && viewModel.CanRefreshDetail, "A removed endpoint did not have an explicit retryable detail state.");
        detailTask = viewModel.RefreshDetailAsync();
        active.Details[^1].Complete(Detail(2));
        await Done(detailTask);
        Check(viewModel.DetailState == RiskDetailState.Unavailable && viewModel.Detail is null, "Risk accepted a detail for a different endpoint.");
        detailTask = viewModel.RefreshDetailAsync();
        active.Details[^1].Complete(Detail(1) with { Risk = Detail(1).Risk with { EndpointId = Id(2) } });
        await Done(detailTask);
        Check(viewModel.DetailState == RiskDetailState.Unavailable, "Risk accepted nested scoring results for a different endpoint.");
        detailTask = viewModel.RefreshDetailAsync();
        var missing = Detail(1) with { InventoryCollectedUtc = null, Coverage = MissingCoverage(), Alerts = Array.Empty<RiskAlertView>(), Risk = Detail(1).Risk with { Score = 0, RawScore = 0m, Saturated = false, Contributions = Array.Empty<AlertRiskContribution>() } };
        active.Details[^1].Complete(missing);
        await Done(detailTask);
        Check(viewModel.DetailState == RiskDetailState.Ready && viewModel.Detail!.Contributions.Count == 0 && viewModel.DetailStatusText.Contains("Review coverage", StringComparison.Ordinal), "No-inventory/no-contribution endpoint was mistaken for absent data or safety.");
        Check(viewModel.VisibleEndpoints.Single().Score == 100 && Fact(viewModel.Detail!.Facts, "Endpoint score") == "0", "Refreshing detail recomputed or rewrote the earlier ranked-list evaluation snapshot.");
        viewModel.CloseDetail();
        Check(!viewModel.IsShowingDetail && viewModel.Detail is null && !viewModel.CanRefreshDetail && viewModel.VisibleEndpoints.Count == 1, "Back erased the ranked list or retained sensitive detail state.");
    }

    private static async Task ShrinkingPageAsync()
    {
        var client = new ControlledClient();
        using var vm = new RiskViewModel(client);
        var first = vm.RefreshAsync();
        client.Pages[^1].Complete(Page(0, 51, Enumerable.Range(1, 50).Select(Summary).ToArray()));
        await Done(first);
        var next = vm.NextPageAsync();
        client.Pages[^1].Complete(Page(50, 50));
        await Until(() => client.Pages.Count == 3);
        Check(client.Pages[^1].Offset == 0 && client.Pages[^1].Limit == 50, "A shrinking fleet did not correct its stale final-page offset.");
        client.Pages[^1].Complete(Page(0, 50, Enumerable.Range(1, 50).Select(Summary).ToArray()));
        await Done(next);
        Check(vm.PageNumber == 1 && vm.TotalPages == 1 && !vm.CanNextPage && !vm.CanPreviousPage && client.Pages.Count == 3, "Shrinking fleet paging showed an impossible page or chased unbounded corrections.");

        first = vm.RefreshAsync();
        client.Pages[^1].Complete(Page(0, 101, Enumerable.Range(1, 50).Select(Summary).ToArray()));
        await Done(first);
        next = vm.NextPageAsync();
        client.Pages[^1].Complete(Page(50, 0));
        await Until(() => client.Pages.Count == 6);
        Check(client.Pages[^1].Offset == 0, "A fleet shrinking to zero retained a stale offset.");
        client.Pages[^1].Complete(Page(0, 0));
        await Done(next);
        Check(vm.ListState == RiskListState.Empty && vm.PageNumber == 0 && !vm.CanPreviousPage, "An empty corrected page retained stale navigation.");
    }

    private static async Task DetailConcurrencyAsync()
    {
        foreach (var staleOutcome in new[] { RiskReadOutcome.Success, RiskReadOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            await Seed(vm, client, Summary(1), Summary(2));
            var old = vm.OpenEndpointAsync(Id(1));
            var oldRequest = client.Details[^1];
            var current = vm.OpenEndpointAsync(Id(2));
            Check(oldRequest.Token.IsCancellationRequested && !current.IsCompleted && vm.IsLoadingDetail, "Opening a different endpoint did not cancel the old detail request.");
            if (staleOutcome == RiskReadOutcome.Success) oldRequest.Complete(Detail(1));
            else oldRequest.Reply(staleOutcome);
            await Done(old);
            Check(vm.IsLoadingDetail && vm.Detail is null && expired == 0, "Stale detail restored old data or expired the current request.");
            client.Details[^1].Complete(Detail(2));
            await Done(current);
            Check(vm.Detail!.EndpointId == Id(2) && vm.DetailState == RiskDetailState.Ready, "The newer endpoint detail was not preserved.");
            var refresh = vm.RefreshDetailAsync();
            var pending = client.Details[^1];
            vm.CloseDetail();
            Check(pending.Token.IsCancellationRequested && vm.Detail is null && vm.DetailState == RiskDetailState.None, "Back did not cancel/clear pending detail.");
            pending.Reply(RiskReadOutcome.Unauthenticated);
            await Done(refresh);
            Check(expired == 0 && vm.DetailState == RiskDetailState.None && vm.VisibleEndpoints.Count == 2, "A closed detail's late 401 expired the visible risk list.");
            var open = vm.OpenEndpointAsync(Id(1));
            var oldDetail = client.Details[^1];
            var list = vm.RefreshAsync();
            Check(oldDetail.Token.IsCancellationRequested && !vm.IsShowingDetail && vm.IsLoading, "List refresh failed to cancel the old detail evaluation.");
            oldDetail.Complete(Detail(1));
            await Done(open);
            client.Pages[^1].Complete(Page(0, 1, Summary(2)));
            await Done(list);
            Check(vm.Detail is null && vm.VisibleEndpoints.Single().EndpointId == Id(2), "An old detail survived a newer ranked-list evaluation.");
        }
    }

    private static async Task CorrectionReadRacesAsync()
    {
        var beforeCorrection = new ControlledClient();
        using (var vm = new RiskViewModel(beforeCorrection))
        {
            var first = vm.RefreshAsync();
            beforeCorrection.Pages[^1].Complete(Page(0, 51, Enumerable.Range(1, 50).Select(Summary).ToArray()));
            await Done(first);
            var stale = vm.NextPageAsync();
            var oldPage = beforeCorrection.Pages[^1];
            vm.Clear();
            var current = vm.RefreshAsync();
            oldPage.Complete(Page(50, 50));
            await Done(stale);
            Check(beforeCorrection.Pages.Count == 3 && vm.IsLoading, "An obsolete shrinking page started a corrective request after sign-out.");
            beforeCorrection.Pages[^1].Complete(Page(0, 1, Summary(3)));
            await Done(current);
        }
        foreach (var staleOutcome in new[] { RiskReadOutcome.Success, RiskReadOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var first = vm.RefreshAsync();
            client.Pages[^1].Complete(Page(0, 51, Enumerable.Range(1, 50).Select(Summary).ToArray()));
            await Done(first);
            var stale = vm.NextPageAsync();
            client.Pages[^1].Complete(Page(50, 50));
            await Until(() => client.Pages.Count == 3);
            var correction = client.Pages[^1];
            vm.Clear();
            var current = vm.RefreshAsync();
            Check(correction.Token.IsCancellationRequested, "Sign-out failed to cancel a pending corrective page read.");
            if (staleOutcome == RiskReadOutcome.Success) correction.Complete(Page(0, 1, Summary(1)));
            else correction.Reply(staleOutcome);
            await Done(stale);
            Check(vm.IsLoading && vm.VisibleEndpoints.Count == 0 && expired == 0, "A prior session's corrected page restored data or expired the new session.");
            client.Pages[^1].Complete(Page(0, 1, Summary(3)));
            await Done(current);
            Check(vm.VisibleEndpoints.Single().EndpointId == Id(3) && client.Pages.Count == 4, "A corrected page replaced new-session rows or produced additional reads.");
        }

        var changing = new ControlledClient();
        using var bounded = new RiskViewModel(changing);
        var load = bounded.RefreshAsync();
        changing.Pages[^1].Complete(Page(0, 151, Enumerable.Range(1, 50).Select(Summary).ToArray()));
        await Done(load);
        load = bounded.NextPageAsync();
        changing.Pages[^1].Complete(Page(50, 151, Enumerable.Range(51, 50).Select(Summary).ToArray()));
        await Done(load);
        load = bounded.NextPageAsync();
        changing.Pages[^1].Complete(Page(100, 100));
        await Until(() => changing.Pages.Count == 4);
        Check(changing.Pages[^1].Offset == 50, "A removed third page did not correct to the last valid second page.");
        changing.Pages[^1].Complete(Page(50, 50));
        await Done(load);
        Check(changing.Pages.Count == 4 && bounded.ListState == RiskListState.Unavailable && bounded.PageNumber == 0 && bounded.CanRefresh, "Repeated membership changes caused an unbounded correction loop or impossible page label.");
    }

    private static async Task SessionAndDisposeRacesAsync()
    {
        foreach (var staleOutcome in new[] { RiskReadOutcome.Success, RiskReadOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = vm.RefreshAsync();
            var oldPage = client.Pages[^1];
            vm.Clear();
            Check(oldPage.Token.IsCancellationRequested && vm.ListState == RiskListState.NotLoaded && vm.Organization is null && vm.VisibleEndpoints.Count == 0, "Sign-out did not cancel and erase current Risk state.");
            var current = vm.RefreshAsync();
            if (staleOutcome == RiskReadOutcome.Success) oldPage.Complete(Page(0, 1, Summary(1)));
            else oldPage.Reply(staleOutcome);
            await Done(old);
            Check(vm.IsLoading && vm.VisibleEndpoints.Count == 0 && expired == 0, "An old list response restored data or expired a replacement session.");
            client.Pages[^1].Complete(Page(0, 1, Summary(2)));
            await Done(current);
            var detail = vm.OpenEndpointAsync(Id(2));
            var oldDetail = client.Details[^1];
            vm.Clear();
            current = vm.RefreshAsync();
            client.Pages[^1].Complete(Page(0, 1, Summary(3)));
            await Done(current);
            if (staleOutcome == RiskReadOutcome.Success) oldDetail.Complete(Detail(2));
            else oldDetail.Reply(staleOutcome);
            await Done(detail);
            Check(oldDetail.Token.IsCancellationRequested && vm.Detail is null && vm.VisibleEndpoints.Single().EndpointId == Id(3) && expired == 0, "A prior-session detail changed a new session or raised stale expiration.");
        }
        foreach (var expireDetail in new[] { false, true })
        {
            var client = new ControlledClient();
            using var vm = new RiskViewModel(client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            Task task;
            if (expireDetail)
            {
                await Seed(vm, client, Summary(1));
                task = vm.OpenEndpointAsync(Id(1));
                client.Details[^1].Reply(RiskReadOutcome.Unauthenticated);
            }
            else
            {
                task = vm.RefreshAsync();
                client.Pages[^1].Reply(RiskReadOutcome.Unauthenticated);
            }
            await Done(task);
            Check(expired == 1 && vm.ListState == RiskListState.NotLoaded && vm.DetailState == RiskDetailState.None && vm.VisibleEndpoints.Count == 0 && vm.Organization is null && vm.Detail is null && vm.TotalEndpoints == 0 && vm.ErrorText.Length == 0, "Current-session 401 failed to clear Risk and notify its authentication owner once.");
            Check(client.DisposeCalls == 0, "Session expiration disposed the shared authentication client.");
        }
        foreach (var disposeDetail in new[] { false, true })
        {
            var client = new ControlledClient();
            var vm = new RiskViewModel(client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            Task task;
            Deferred<RiskPage>? page = null;
            Deferred<EndpointRiskDetail>? detail = null;
            if (disposeDetail)
            {
                await Seed(vm, client, Summary(1));
                vm.SelectedEndpoint = vm.VisibleEndpoints[0];
                task = vm.OpenEndpointAsync(Id(1));
                detail = client.Details[^1];
            }
            else { task = vm.RefreshAsync(); page = client.Pages[^1]; }
            vm.Dispose();
            Check((page?.Token ?? detail!.Token).IsCancellationRequested && vm.VisibleEndpoints.Count == 0 && vm.SelectedEndpoint is null && vm.Organization is null && vm.Detail is null && !vm.CanRefresh && !vm.CanRefreshDetail, "Disposal failed to cancel and wipe Risk state.");
            if (page is not null) page.Reply(RiskReadOutcome.Unauthenticated);
            else detail!.Reply(RiskReadOutcome.Unauthenticated);
            await Done(task);
            await Done(vm.RefreshAsync());
            await Done(vm.OpenEndpointAsync(Id(1)));
            await Done(vm.RefreshDetailAsync());
            vm.Clear(); vm.Dispose();
            Check(expired == 0 && client.DisposeCalls == 0 && vm.ListState == RiskListState.NotLoaded && vm.DetailState == RiskDetailState.None, "Disposed Risk revived data, raised stale expiration or disposed its shared owner.");
        }
    }

    private static async Task Seed(RiskViewModel vm, ControlledClient client, params EndpointRiskSummary[] endpoints)
    {
        var task = vm.RefreshAsync();
        client.Pages[^1].Complete(Page(0, endpoints.Length, endpoints));
        await Done(task);
    }
    private static string Fact(IReadOnlyList<DisplayFact> facts, string label) => facts.Single(fact => fact.Label == label).Value;
    private static IReadOnlyDictionary<string, decimal> Map(params (string Key, decimal Value)[] values) => values.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    private static Guid Id(int number) => Guid.ParseExact(number.ToString("x32", CultureInfo.InvariantCulture), "N");
    private static RiskCoverage Coverage() => new("current", "partial", 7, 13, "Missing or unknown observations have no score; a zero score is not a security assurance.");
    private static RiskCoverage MissingCoverage() => new("missing", "unknown", 0, 13, "No inventory reported; a zero score is not a security assurance.");
    private static EndpointRiskSummary Summary(int number) => new(Id(number), $"host-{number}", Observation, 100, 150.125m, Coverage(), 1, "Configured firewall disabled", Observation);
    private static OrganizationRiskView Organization(int total) => new(total == 0 ? 0 : 100, total, total == 0 ? Array.Empty<Guid>() : new[] { Id(1) }, total == 0 ? 0 : 1, false, "maximum", "Maximum current endpoint score; a zero score is not proof of protection.", Observation, total, 0, 0, total, 0, new(3, 2, 1, 4));
    private static RiskPage Page(int offset, int total, params EndpointRiskSummary[] endpoints) => new(Organization(total), endpoints, total, offset, 50, Policy, 12);
    private static AlertRiskContribution Contribution(int number) => new(Id(number), "firewall.disabled", "critical", "accepted", Observation, 10.125m, "aging", false, 50m, 0.5m, "ruleOverride", 2m, 1.5m, 0.75m, 1m, 56.25m, 0m, 56.25m, "FW", true, false);
    private static RiskAlertView Alert(int number) => new(Id(number), "firewall.disabled", "Configured firewall disabled", "critical", "accepted", Observation, "Configured Domain firewall disabled");
    private static EndpointRiskDetail Detail(int number) => new(Id(number), $"host-{number}", Observation,
        new EndpointRiskScore(Id(number), 100, 150.125m, true, Observation, new("critical", "internet", Observation, "userDeclared", "userDeclared"), 2m, 1.5m, new[] { Contribution(1001) }, new[] { "FW", "UAC" }, 20m, 60m, "Current findings and declared context; zero does not prove protection."),
        Coverage(), new[] { Alert(1001) }, Policy, 12);
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }
    private static void Throws<T>(Action action, string message) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new InvalidOperationException(message);
    }
    private static async Task Done(Task task) => await task.WaitAsync(TimeSpan.FromSeconds(5));
    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline) throw new TimeoutException("Expected Risk client request did not start.");
            await Task.Delay(1);
        }
    }
    private class Deferred<T>(CancellationToken token)
    {
        private readonly TaskCompletionSource<RiskReadResult<T>> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken Token { get; } = token;
        public Task<RiskReadResult<T>> Task => completion.Task;
        public void Complete(T value) => completion.SetResult(new(RiskReadOutcome.Success, value));
        public void Reply(RiskReadOutcome outcome) => completion.SetResult(new(outcome));
        public void Fail(Exception error) => completion.SetException(error);
    }
    private sealed class PageRequest(int offset, int limit, CancellationToken token) : Deferred<RiskPage>(token)
    {
        public int Offset { get; } = offset;
        public int Limit { get; } = limit;
    }
    private sealed class DetailRequest(Guid endpointId, CancellationToken token) : Deferred<EndpointRiskDetail>(token)
    {
        public Guid EndpointId { get; } = endpointId;
    }
    private sealed class ControlledClient : IRiskClient, IDisposable
    {
        private readonly object gate = new();
        private readonly List<PageRequest> pages = [];
        private readonly List<DetailRequest> details = [];
        public IReadOnlyList<PageRequest> Pages { get { lock (gate) return pages.ToArray(); } }
        public IReadOnlyList<DetailRequest> Details { get { lock (gate) return details.ToArray(); } }
        public int DisposeCalls { get; private set; }
        public Task<RiskReadResult<RiskPage>> GetRiskPageAsync(int offset, int limit, CancellationToken cancellationToken)
        {
            var request = new PageRequest(offset, limit, cancellationToken);
            lock (gate) pages.Add(request);
            return request.Task;
        }
        public Task<RiskReadResult<EndpointRiskDetail>> GetEndpointRiskDetailAsync(Guid endpointId, CancellationToken cancellationToken)
        {
            var request = new DetailRequest(endpointId, cancellationToken);
            lock (gate) details.Add(request);
            return request.Task;
        }
        public void Dispose() => DisposeCalls++;
    }
}
