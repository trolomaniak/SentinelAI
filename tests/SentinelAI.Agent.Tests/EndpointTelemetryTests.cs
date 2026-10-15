using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Agent;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core.Persistence;

/// <summary>
/// Endpoint telemetry (TASK-029): contract, normalization, bounded collection, the delivery worker and real Core
/// delivery. Synthetic values only (S-1-5-21-1000-1000-1000-* SIDs, test-only application names). Windows runs also
/// collect from the real platform sources; <see cref="RunNativeAcceptanceAsync"/> compares them with Windows' own tools.
/// </summary>
internal static class EndpointTelemetryTests
{
    private const string Collected = TelemetryAvailability.Collected;
    private const string DomainSid = "S-1-5-21-1000-1000-1000";
    private static readonly DateTimeOffset Now = new(2026, 5, 4, 12, 0, 0, TimeSpan.Zero);
    private static int _checks;

    public static async Task<int> RunAsync(string testDirectory)
    {
        _checks = 0;
        VerifyContract();
        VerifyNormalization();
        VerifySoftwareBounds();
        await VerifyBoundedCollectionAsync();
        await VerifyWorkerScheduleAsync();
        await VerifyWorkerClockStepAsync();
        await VerifyUploaderAsync();
        await VerifyDeliveryToCoreAsync(testDirectory);
        if (OperatingSystem.IsWindows())
        {
            await VerifyPlatformCollectionAsync();
        }

        return _checks;
    }

    // A1: the contract accepts complete, consistent reports only and bounds the request.
    private static void VerifyContract()
    {
        var report = Benign(Guid.NewGuid());
        Ensure(EndpointTelemetryContract.IsValid(report, Now), "A benign synthetic report must be valid.");
        var json = JsonSerializer.Serialize(report, EndpointTelemetryContract.Json);
        var roundTrip = JsonSerializer.Deserialize<EndpointTelemetryReport>(json, EndpointTelemetryContract.Json)!;
        Ensure(JsonSerializer.Serialize(roundTrip, EndpointTelemetryContract.Json) == json, "The report must round-trip exactly.");
        Ensure(!json.Contains("null", StringComparison.Ordinal), "Unknown values must be omitted from the wire form, not sent as values.");

        var invalid = new (string Name, EndpointTelemetryReport Report)[]
        {
            ("schema version", report with { SchemaVersion = 2 }),
            ("empty endpoint", report with { EndpointId = Guid.Empty }),
            ("local offset", report with { CollectedUtc = new DateTimeOffset(2026, 5, 4, 14, 0, 0, TimeSpan.FromHours(2)) }),
            ("future", report with { CollectedUtc = Now.AddMinutes(6) }),
            ("value in an uncollected section", report with { BitLocker = new BitLockerTelemetry(TelemetryAvailability.AccessDenied, "off") }),
            ("unknown availability", report with { Antivirus = new AntivirusTelemetry("partial") }),
            ("unknown vocabulary", report with { Defender = new DefenderTelemetry(Collected, "aggressive") }),
            ("negative signature age", report with { Defender = new DefenderTelemetry(Collected, SignatureAgeDays: -1) }),
            ("administrators without count", report with { LocalAdministrators = new LocalAdministratorsTelemetry(Collected, null, []) }),
            ("administrators listed beyond the count", report with
            {
                LocalAdministrators = new LocalAdministratorsTelemetry(Collected, 0, [new($"{DomainSid}-500")])
            }),
            ("administrators listed below the bound", report with
            {
                LocalAdministrators = new LocalAdministratorsTelemetry(Collected, 3, [new($"{DomainSid}-500")])
            }),
            ("administrator name instead of SID", report with
            {
                LocalAdministrators = new LocalAdministratorsTelemetry(Collected, 1, [new("Administrator")])
            }),
            ("duplicate administrator", report with
            {
                LocalAdministrators = new LocalAdministratorsTelemetry(Collected, 2, [new($"{DomainSid}-500"), new($"{DomainSid}-500")])
            }),
            ("service outside the catalog", report with
            {
                Services = new SecurityServicesTelemetry(Collected, [new("Spooler", ServiceRunStates.Running)])
            }),
            ("duplicate service", report with
            {
                Services = new SecurityServicesTelemetry(Collected, [new("EventLog"), new("EventLog")])
            }),
            ("absent service with a start type", report with
            {
                Services = new SecurityServicesTelemetry(Collected, [new("Sense", ServiceRunStates.NotInstalled, ServiceStartTypes.Auto)])
            }),
            ("collected services without items", report with { Services = new SecurityServicesTelemetry(Collected) }),
            ("software without total", report with { Software = new InstalledSoftwareTelemetry(Collected, []) }),
            ("software truncation flag", report with { Software = new InstalledSoftwareTelemetry(Collected, [], 1, Truncated: false) }),
            ("software beyond total", report with { Software = new InstalledSoftwareTelemetry(Collected, [new("test-only-a"), new("test-only-b")], 1) }),
            ("software counts while uncollected", report with { Software = new InstalledSoftwareTelemetry(TelemetryAvailability.Unavailable, SkippedCount: 1) }),
            ("software name with a control character", report with
            {
                Software = new InstalledSoftwareTelemetry(Collected, [new("test-only\u0001")], 1)
            }),
            ("update result after collection", report with
            {
                WindowsUpdate = new WindowsUpdateTelemetry(Collected, Collected, LastSuccessfulSearchUtc: Now.AddDays(2))
            }),
            ("update values while uncollected", report with
            {
                WindowsUpdate = new WindowsUpdateTelemetry(TelemetryAvailability.AccessDenied, Collected, "disabled")
            })
        };
        foreach (var (name, candidate) in invalid)
        {
            Ensure(!EndpointTelemetryContract.IsValid(candidate, Now), $"The contract accepted an invalid report: {name}.");
        }

        Ensure(EndpointTelemetryContract.IsValid(report with
        {
            LocalAdministrators = new LocalAdministratorsTelemetry(Collected, 200,
                Enumerable.Range(1, 64).Select(index => new LocalAdministratorMember($"{DomainSid}-{1000 + index}")).ToArray())
        }, Now), "A bounded member prefix with the full count must be valid.");

        // Size proof: every other value at its largest plus the whole application budget stays within Core's request bound.
        var worst = WorstCase(Guid.NewGuid());
        var bytes = JsonSerializer.SerializeToUtf8Bytes(worst, EndpointTelemetryContract.Json).Length;
        var listBytes = JsonSerializer.SerializeToUtf8Bytes(worst.Software.Items, EndpointTelemetryContract.Json).Length;
        var bound = bytes - listBytes + EndpointTelemetryContract.SoftwareByteBudget;
        Ensure(EndpointTelemetryContract.IsValid(worst, Now) && listBytes <= EndpointTelemetryContract.SoftwareByteBudget &&
               bound <= EndpointTelemetryContract.MaxRequestBytes,
            $"The worst-case report must be valid and its upper bound ({bound} bytes) within {EndpointTelemetryContract.MaxRequestBytes} bytes.");
        Console.WriteLine($"Endpoint telemetry request upper bound: {bound} of {EndpointTelemetryContract.MaxRequestBytes} bytes.");
    }

    // A2: raw Windows values map to the closed vocabularies; anything unrecognized is Unknown.
    private static void VerifyNormalization()
    {
        Ensure(EndpointTelemetryNormalizer.BitLockerProtection(0) == "off" && EndpointTelemetryNormalizer.BitLockerProtection(1) == "on" &&
               EndpointTelemetryNormalizer.BitLockerProtection(2) is null && EndpointTelemetryNormalizer.BitLockerProtection("1") is null &&
               EndpointTelemetryNormalizer.BitLockerProtection(null) is null, "BitLocker protection status mapping is wrong.");
        Ensure(Enumerable.Range(0, 6).Select(value => EndpointTelemetryNormalizer.BitLockerConversion(value))
                   .SequenceEqual(BitLockerConversionStates.All) && EndpointTelemetryNormalizer.BitLockerConversion(6) is null &&
               EndpointTelemetryNormalizer.BitLockerConversion(-1) is null, "BitLocker conversion status mapping is wrong.");
        Ensure(EndpointTelemetryNormalizer.SecurityCenterHealth(0) == "good" && EndpointTelemetryNormalizer.SecurityCenterHealth(2) == "poor" &&
               EndpointTelemetryNormalizer.SecurityCenterHealth(3) == "snooze" && EndpointTelemetryNormalizer.SecurityCenterHealth(4) is null,
            "Security Center health mapping is wrong.");
        Ensure(EndpointTelemetryNormalizer.DefenderRunningMode("Normal") == "normal" &&
               EndpointTelemetryNormalizer.DefenderRunningMode("EDR Block Mode") == "edrBlock" &&
               EndpointTelemetryNormalizer.DefenderRunningMode("SxS Passive Mode") == "sxsPassive" &&
               EndpointTelemetryNormalizer.DefenderRunningMode("Not running") is null && EndpointTelemetryNormalizer.DefenderRunningMode(1) is null,
            "Defender running mode mapping is wrong.");
        // Defender reports 65535 when definitions were never updated; that is Unknown, not an age.
        Ensure(EndpointTelemetryNormalizer.SignatureAgeDays(3) == 3 && EndpointTelemetryNormalizer.SignatureAgeDays(65535) is null &&
               EndpointTelemetryNormalizer.SignatureAgeDays(uint.MaxValue) is null && EndpointTelemetryNormalizer.SignatureAgeDays(-1) is null,
            "Signature age must be bounded.");
        Ensure(EndpointTelemetryNormalizer.Boolean(true) == true && EndpointTelemetryNormalizer.Boolean(1) is null,
            "Only real Boolean values may become Boolean observations.");

        Ensure(EndpointTelemetryNormalizer.AdministratorScope($"{DomainSid}-500", DomainSid) == AdministratorScopes.Local &&
               EndpointTelemetryNormalizer.AdministratorScope("S-1-5-21-2000-2000-2000-512", DomainSid) == AdministratorScopes.Domain &&
               EndpointTelemetryNormalizer.AdministratorScope($"{DomainSid}0-500", DomainSid) == AdministratorScopes.Domain &&
               EndpointTelemetryNormalizer.AdministratorScope("S-1-12-1-1000-2000-3000-4000", DomainSid) == AdministratorScopes.Entra &&
               EndpointTelemetryNormalizer.AdministratorScope("S-1-5-32-544", DomainSid) == AdministratorScopes.WellKnown &&
               EndpointTelemetryNormalizer.AdministratorScope($"{DomainSid}-500", null) is null,
            "Administrator scope must come from the SID and the machine's account domain only.");
        Ensure(EndpointTelemetryNormalizer.AdministratorAccountType(1) == "user" && EndpointTelemetryNormalizer.AdministratorAccountType(4) == "alias" &&
               EndpointTelemetryNormalizer.AdministratorAccountType(8) is null, "SID_NAME_USE mapping is wrong.");
        var administrators = EndpointTelemetryNormalizer.Administrators(
            Enumerable.Range(0, 70).Select(index => new RawAdministratorMember($"{DomainSid}-{2000 + index}", 1)).Reverse().ToArray(), 70, DomainSid);
        Ensure(administrators is { Availability: Collected, MemberCount: 70, Members.Count: 64 } &&
               administrators.Members![0].Sid == $"{DomainSid}-2000" && EndpointTelemetryContract.IsValid(administrators),
            "Administrators must keep the count and a sorted, bounded SID prefix.");
        Ensure(EndpointTelemetryNormalizer.Administrators([new("not-a-sid", 1)], 1, DomainSid).Availability == TelemetryAvailability.Unavailable,
            "An unusable member SID must make the member list Unknown, never shorter.");

        object?[] auOptions = [null, 2, 3, 4, 5, 7];
        Ensure(auOptions.Select(option => EndpointTelemetryNormalizer.AutomaticUpdatesPolicy(null, option))
                   .SequenceEqual(["notConfigured", "notifyDownload", "autoDownloadNotifyInstall", "autoDownloadScheduledInstall",
                       "localAdminChooses", "autoDownloadNotifyInstallNotifyRestart"]) &&
               EndpointTelemetryNormalizer.AutomaticUpdatesPolicy(1, 4) == "disabled" &&
               EndpointTelemetryNormalizer.AutomaticUpdatesPolicy(0, 6) is null &&
               EndpointTelemetryNormalizer.AutomaticUpdatesPolicy("1", null) is null,
            "Automatic update policy mapping is wrong.");
        Ensure(EndpointTelemetryNormalizer.ManagedUpdateServer(null) == false && EndpointTelemetryNormalizer.ManagedUpdateServer(1) == true &&
               EndpointTelemetryNormalizer.ManagedUpdateServer(2) is null, "Managed update server mapping is wrong.");
        Ensure(EndpointTelemetryNormalizer.UpdateResultDate(new DateTime(2026, 5, 1, 3, 0, 0), Now) == new DateTimeOffset(2026, 5, 1, 3, 0, 0, TimeSpan.Zero) &&
               EndpointTelemetryNormalizer.UpdateResultDate(new DateTime(1899, 12, 30), Now) is null &&
               EndpointTelemetryNormalizer.UpdateResultDate(Now.UtcDateTime.AddDays(2), Now) is null &&
               EndpointTelemetryNormalizer.UpdateResultDate(DBNull.Value, Now) is null,
            "Windows Update dates must be UTC, plausible and never invented.");
        Ensure(Enumerable.Range(1, 7).Select(EndpointTelemetryNormalizer.ServiceState).All(state => state is not null) &&
               EndpointTelemetryNormalizer.ServiceState(1) == "stopped" && EndpointTelemetryNormalizer.ServiceState(4) == "running" &&
               EndpointTelemetryNormalizer.ServiceState(8) is null && EndpointTelemetryNormalizer.ServiceStartType(2) == "auto" &&
               EndpointTelemetryNormalizer.ServiceStartType(4) == "disabled" && EndpointTelemetryNormalizer.ServiceStartType(5) is null,
            "Service state mapping is wrong.");

        Ensure(EndpointTelemetryNormalizer.Classify(new UnauthorizedAccessException()) == TelemetryAvailability.AccessDenied &&
               EndpointTelemetryNormalizer.Classify(new SecurityException()) == TelemetryAvailability.AccessDenied &&
               EndpointTelemetryNormalizer.Classify(new TargetInvocationException(new COMException("denied", unchecked((int)0x80041003)))) ==
               TelemetryAvailability.AccessDenied &&
               EndpointTelemetryNormalizer.Classify(new COMException("namespace", unchecked((int)0x8004100E))) == TelemetryAvailability.Unsupported &&
               EndpointTelemetryNormalizer.Classify(new COMException("class", unchecked((int)0x80040154))) == TelemetryAvailability.Unsupported &&
               EndpointTelemetryNormalizer.Classify(new COMException("busy", unchecked((int)0x80041006))) == TelemetryAvailability.Unavailable &&
               EndpointTelemetryNormalizer.Classify(new Win32Exception(5)) == TelemetryAvailability.AccessDenied &&
               EndpointTelemetryNormalizer.Classify(new DllNotFoundException()) == TelemetryAvailability.Unsupported &&
               EndpointTelemetryNormalizer.Classify(new IOException()) == TelemetryAvailability.Unavailable,
            "Failed reads must be classified, never treated as absent.");
    }

    // A3: installed applications are filtered, deduplicated, sorted and bounded deterministically.
    private static void VerifySoftwareBounds()
    {
        RawSoftwareEntry[] entries =
        [
            new("  Test-only Zeta  ", " 2.0 ", " Example Corp ", null, null, null, "x64"),
            new("test-only Alpha", "1.0", "Example Corp", 0, null, null, "x86"),
            new("test-only Alpha", "1.0", "Example Corp", 0, null, null, "x86"),
            new("test-only Alpha", "1.0", "Example Corp", 0, null, null, "x64"),
            new("test-only hidden component", "1.0", null, 1, null, null, "x64"),
            new("test-only patch", "1.0", null, null, "{parent}", null, "x64"),
            new("test-only hotfix", "1.0", null, null, null, "Hotfix", "x64"),
            new(null, "9.9", "No name", null, null, null, "x64"),
            new("   ", "9.9", "Blank name", null, null, null, "x64"),
            new(new string('n', EndpointTelemetryContract.MaxSoftwareNameLength + 1), null, null, null, null, null, "x64"),
            new("test-only long version", new string('9', 65), "Example\u0007Corp", null, null, null, "riscv")
        ];
        var software = EndpointTelemetryNormalizer.Software(entries, unreadableEntries: 2);
        Ensure(software.Items!.Select(item => $"{item.Name}|{item.Version}|{item.Publisher}|{item.Architecture}").SequenceEqual(
            [
                "test-only Alpha|1.0|Example Corp|x64", "test-only Alpha|1.0|Example Corp|x86",
                "test-only long version|||", "Test-only Zeta|2.0|Example Corp|x64"
            ]) && software is { TotalCount: 4, Truncated: false, SkippedCount: 3 } && EndpointTelemetryContract.IsValid(software),
            "Applications must be trimmed, deduplicated, filtered, sorted and bounded, with unusable names counted.");
        Ensure(JsonSerializer.Serialize(EndpointTelemetryNormalizer.Software(entries.Reverse(), unreadableEntries: 2)) ==
               JsonSerializer.Serialize(software), "Application order must not depend on registry enumeration order.");

        var many = Enumerable.Range(0, 3000).Select(index => new RawSoftwareEntry($"test-only app {index:D5}", "1.0.0", "Example Corp",
            null, null, null, "x64")).ToArray();
        var bounded = EndpointTelemetryNormalizer.Software(many);
        Ensure(bounded is { TotalCount: 3000, Truncated: true } && bounded.Items!.Count <= EndpointTelemetryContract.MaxSoftwareItems &&
               bounded.Items[0].Name == "test-only app 00000" && EndpointTelemetryContract.IsValid(bounded),
            "A large application list must be truncated deterministically with its full count.");
        var budget = EndpointTelemetryNormalizer.Software(many, byteBudget: 4096);
        Ensure(budget.Truncated && JsonSerializer.SerializeToUtf8Bytes(budget.Items, EndpointTelemetryContract.Json).Length <= 4096,
            "The application list must respect its byte budget.");
    }

    // C1–C4: collection is bounded per section, classifies failures and never accumulates threads.
    private static async Task VerifyBoundedCollectionAsync()
    {
        var endpointId = Guid.NewGuid();
        var time = new ManualTimeProvider(Now);
        var source = new FakeTelemetrySource(endpointId);
        var collector = new EndpointTelemetryCollector(source, time, TimeSpan.FromSeconds(5));
        var report = await collector.CollectAsync(endpointId, CancellationToken.None);
        Ensure(report == Benign(endpointId) with { CollectedUtc = Now } || JsonSerializer.Serialize(report, EndpointTelemetryContract.Json) ==
               JsonSerializer.Serialize(Benign(endpointId) with { CollectedUtc = Now }, EndpointTelemetryContract.Json),
            "The collector must assemble every section at the provider's UTC time.");
        Ensure(source.Calls == 8, "Each section must be read exactly once per collection.");

        // Failures are classified per section; the other sections are unaffected.
        source.Failures["bitLocker"] = new COMException("denied", unchecked((int)0x80041003));
        source.Failures["antivirus"] = new DllNotFoundException();
        source.Failures["software"] = new IOException();
        source.Invalid = true;
        report = await collector.CollectAsync(endpointId, CancellationToken.None);
        Ensure(report.BitLocker == new BitLockerTelemetry(TelemetryAvailability.AccessDenied) &&
               report.Antivirus == new AntivirusTelemetry(TelemetryAvailability.Unsupported) &&
               report.Software.Availability == TelemetryAvailability.Unavailable && report.Software.Items is null &&
               report.Defender == new DefenderTelemetry(TelemetryAvailability.Unavailable) &&
               report.Services.Availability == Collected && EndpointTelemetryContract.IsValid(report, Now),
            "Failed or contract-violating sections must be reported without values, leaving the others intact.");
        source.Failures.Clear();
        source.Invalid = false;

        // A hung source is reported Unavailable at the deadline and never read twice concurrently.
        using var release = new ManualResetEventSlim();
        source.Block = release;
        var quick = new EndpointTelemetryCollector(source, time, TimeSpan.FromMilliseconds(200));
        var stopwatch = Stopwatch.StartNew();
        report = await quick.CollectAsync(endpointId, CancellationToken.None);
        Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(5) && report.Software.Availability == TelemetryAvailability.Unavailable &&
               report.Services.Availability == Collected && quick.LingeringSections == 1,
            "A hung section must be bounded by the deadline without delaying the others.");
        var softwareReads = source.SoftwareCalls;
        report = await quick.CollectAsync(endpointId, CancellationToken.None);
        Ensure(source.SoftwareCalls == softwareReads && report.Software.Availability == TelemetryAvailability.Unavailable &&
               quick.LingeringSections == 1, "A section still running must not be started again.");
        source.Block = null;
        release.Set();
        await WaitUntilAsync(() => quick.LingeringSections == 0, "The released section did not finish.");
        report = await quick.CollectAsync(endpointId, CancellationToken.None);
        Ensure(source.SoftwareCalls == softwareReads + 1 && report.Software.Availability == Collected,
            "A section must be read again once its earlier read has returned.");

        // Cancellation ends the wait promptly.
        using var block = new ManualResetEventSlim();
        source.Block = block;
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var slow = new EndpointTelemetryCollector(source, time, TimeSpan.FromMinutes(1));
        var canceled = false;
        try
        {
            await slow.CollectAsync(endpointId, cancel.Token);
        }
        catch (OperationCanceledException)
        {
            canceled = true;
        }

        Ensure(canceled, "Collection must observe cancellation.");
        source.Block = null;
        block.Set();

        var unsupported = await new EndpointTelemetryCollector(new UnsupportedEndpointTelemetrySource(), time)
            .CollectAsync(endpointId, CancellationToken.None);
        Ensure(EndpointTelemetryContract.IsValid(unsupported, Now) && EndpointTelemetryWorker.Describe(unsupported).Split(", ")
                   .All(part => part.EndsWith("=unsupported", StringComparison.Ordinal)),
            "A host without the Windows sources must report every section as unsupported.");
    }

    // W1–W4: the worker is dormant without a link, retries failures, keeps the hourly cadence and restarts on a new endpoint.
    private static async Task VerifyWorkerScheduleAsync()
    {
        var link = new AgentLink();
        var source = new FakeTelemetrySource(Guid.NewGuid());
        var uploader = new FakeUploader();
        var collector = new EndpointTelemetryCollector(source, TimeProvider.System, TimeSpan.FromSeconds(5));
        var timings = new EndpointTelemetryTimings(TimeSpan.FromHours(1), TimeSpan.FromMilliseconds(100), TimeSpan.FromHours(6));
        using var worker = new EndpointTelemetryWorker(link, collector, uploader, TimeProvider.System,
            NullLogger<EndpointTelemetryWorker>.Instance, timings);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await Task.Delay(300);
            Ensure(uploader.Sent.IsEmpty && source.Calls == 0, "The worker must stay dormant until Core acknowledges an enrolled Agent.");

            uploader.Next = UploadResult.Failed;
            var first = Enrollment();
            link.Publish(first);
            await WaitUntilAsync(() => uploader.Sent.Count >= 2, "A failed delivery was not retried.");
            uploader.Next = UploadResult.Accepted;
            await WaitUntilAsync(() => uploader.Accepted == 1, "The retried delivery was not sent.");
            var sent = uploader.Sent.Count;
            await Task.Delay(500);
            Ensure(uploader.Sent.Count == sent, "An accepted delivery must wait for the hourly interval.");
            Ensure(uploader.Sent.All(item => item.EndpointId == first.EndpointId), "Reports must name the linked endpoint.");

            link.Publish(null);
            link.Publish(first);
            await Task.Delay(300);
            Ensure(uploader.Sent.Count == sent, "A heartbeat outage must not shorten the telemetry interval.");

            var second = Enrollment();
            link.Publish(second);
            await WaitUntilAsync(() => uploader.Sent.Any(item => item.EndpointId == second.EndpointId),
                "A newly linked endpoint did not report telemetry at once.");

            uploader.Next = UploadResult.Incompatible;
            var third = Enrollment();
            link.Publish(third);
            await WaitUntilAsync(() => uploader.Sent.Any(item => item.EndpointId == third.EndpointId), "The third endpoint was not reported.");
            sent = uploader.Sent.Count;
            await Task.Delay(400);
            Ensure(uploader.Sent.Count == sent, "An incompatible answer must not be retried quickly.");

            // An unexpected delivery failure is contained: the worker keeps running and retries after the retry delay.
            uploader.Next = UploadResult.Accepted;
            uploader.ThrowNext = true;
            var fourth = Enrollment();
            link.Publish(fourth);
            await WaitUntilAsync(() => uploader.Sent.Count(item => item.EndpointId == fourth.EndpointId) >= 2,
                "A delivery that failed unexpectedly was not retried.");
            Ensure(worker.ExecuteTask is { IsCompleted: false } && !uploader.ThrowNext,
                "An unexpected telemetry failure must never stop the worker or the Agent host.");
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    // W5: a wall clock stepped back neither stalls the worker nor stops it; the wait never exceeds the chosen delay.
    private static async Task VerifyWorkerClockStepAsync()
    {
        var link = new AgentLink();
        var source = new FakeTelemetrySource(Guid.NewGuid());
        var uploader = new FakeUploader();
        var clock = new SteppedClock();
        var collector = new EndpointTelemetryCollector(source, clock, TimeSpan.FromSeconds(5));
        var timings = new EndpointTelemetryTimings(TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(300),
            TimeSpan.FromMilliseconds(300));
        using var worker = new EndpointTelemetryWorker(link, collector, uploader, clock,
            NullLogger<EndpointTelemetryWorker>.Instance, timings);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            link.Publish(Enrollment());
            await WaitUntilAsync(() => uploader.Accepted >= 1, "The first report was not sent.");

            // One day back: an unclamped wait would last a day.
            clock.Offset -= TimeSpan.FromDays(1);
            var sent = uploader.Accepted;
            await WaitUntilAsync(() => uploader.Accepted >= sent + 2, "A wall clock stepped back stalled telemetry.");

            // Beyond the largest timer delay (about 49.7 days): an unclamped wait would fault the worker.
            clock.Offset -= TimeSpan.FromDays(66);
            sent = uploader.Accepted;
            await WaitUntilAsync(() => uploader.Accepted >= sent + 2, "A wall clock stepped far back stopped telemetry.");
            Ensure(worker.ExecuteTask is { IsCompleted: false }, "A clock step must never stop the worker or the Agent host.");
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    // W6: the uploader's request shape and status classification; a clock-skew rejection (422) is retried soon.
    private static async Task VerifyUploaderAsync()
    {
        var options = new AgentOptions(new Uri("http://127.0.0.1:5000"), Path.GetFullPath("telemetry-uploader"),
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(1), null, null);
        var enrollment = Enrollment();
        var report = Benign(enrollment.EndpointId);
        async Task<TelemetryUploadOutcome> Send(StubHttpHandler handler) =>
            await new HttpEndpointTelemetryUploader(new HttpClient(handler), options).SendAsync(report, enrollment,
                CancellationToken.None);

        var accepted = StubHttpHandler.Status(System.Net.HttpStatusCode.NoContent);
        Ensure(await Send(accepted) == new TelemetryUploadOutcome(UploadResult.Accepted, 204) &&
               accepted.LastMethod == HttpMethod.Post && accepted.LastPath == "/api/agent/security-telemetry" &&
               accepted.LastAuthorization == $"SentinelAgent {enrollment.EndpointId:D}.{enrollment.AgentCredential}" &&
               accepted.LastMediaType == "application/json" &&
               accepted.LastBody == JsonSerializer.Serialize(report, EndpointTelemetryContract.Json),
            "The telemetry request shape is wrong.");
        foreach (var status in new[] { 400, 404, 405, 413, 415 })
        {
            Ensure(await Send(StubHttpHandler.Status((System.Net.HttpStatusCode)status)) ==
                   new TelemetryUploadOutcome(UploadResult.Incompatible, status), $"HTTP {status} was not classified as incompatible.");
        }

        foreach (var status in new[] { 401, 403, 408, 422, 429, 500, 503 })
        {
            Ensure(await Send(StubHttpHandler.Status((System.Net.HttpStatusCode)status)) ==
                   new TelemetryUploadOutcome(UploadResult.Failed, status), $"HTTP {status} was not classified as a transient failure.");
        }

        Ensure(await Send(new StubHttpHandler((_, _) => throw new HttpRequestException("synthetic"))) ==
               new TelemetryUploadOutcome(UploadResult.Failed, null), "A transport failure was not classified as a transient failure.");
    }

    // E1–E2: the production Agent composition delivers telemetry to a real Core; a hung section never delays heartbeats.
    private static async Task VerifyDeliveryToCoreAsync(string testDirectory)
    {
        await using var core = await PostureMonitorTests.CoreFixture.StartAsync(Path.Combine(testDirectory, "telemetry-core"));
        var agentDirectory = Path.Combine(testDirectory, "telemetry-agent");
        var token = await core.IssueEnrollmentTokenAsync();
        var source = new FakeTelemetrySource(Guid.Empty);
        using var release = new ManualResetEventSlim();
        source.Block = release;
        using var httpClient = new HttpClient(new HttpClientHandler { UseProxy = false });
        var builder = AgentHost.CreateBuilder([]);
        builder.Configuration["Agent:CoreUrl"] = core.Url;
        builder.Configuration["Agent:DataDirectory"] = agentDirectory;
        builder.Configuration["Agent:HeartbeatInterval"] = "00:00:00.200";
        builder.Configuration["Agent:EnrollmentToken"] = token;
        builder.Services.RemoveAll<HttpClient>();
        builder.Services.AddSingleton(httpClient);
        builder.Services.RemoveAll<IEventLogAccess>();
        builder.Services.AddSingleton<IEventLogAccess>(new NoEventLogAccess());
        builder.Services.RemoveAll<IEndpointTelemetrySource>();
        builder.Services.AddSingleton<IEndpointTelemetrySource>(source);
        builder.Services.RemoveAll<EndpointTelemetryCollector>();
        builder.Services.AddSingleton(new EndpointTelemetryCollector(source, TimeProvider.System, TimeSpan.FromMilliseconds(500)));
        using var agent = builder.Build();
        await agent.StartAsync();
        try
        {
            var receipt = Path.Combine(agentDirectory, "endpoint-id");
            Guid endpointId = default;
            await WaitUntilAsync(() => File.Exists(receipt) && Guid.TryParse(File.ReadAllText(receipt), out endpointId),
                "The telemetry Agent did not enroll.");
            var store = core.Services.GetRequiredService<EndpointTelemetryStore>();
            StoredEndpointTelemetry? stored = null;
            await WaitUntilAsync(() => (stored = store.FindLatestAsync(endpointId).GetAwaiter().GetResult()) is not null,
                "The Agent did not deliver endpoint telemetry to Core.");
            Ensure(stored!.Report.EndpointId == endpointId && stored.Report.Software.Availability == TelemetryAvailability.Unavailable &&
                   stored.Report.Services.Availability == Collected && stored.Report.LocalAdministrators.MemberCount == 2,
                "Core did not store the delivered report, with the hung section Unknown and the others collected.");
            var devices = core.Services.GetRequiredService<DeviceReadStore>();
            var seen = (await devices.FindAsync(endpointId))!.Device.LastSeenUtc;
            await WaitUntilAsync(() => devices.FindAsync(endpointId).GetAwaiter().GetResult()!.Device.LastSeenUtc > seen,
                "A hung telemetry source delayed heartbeats.");
            Ensure(!Directory.EnumerateFileSystemEntries(agentDirectory, "*", SearchOption.AllDirectories)
                       .Any(path => Path.GetRelativePath(agentDirectory, path).Contains("telemetry", StringComparison.OrdinalIgnoreCase)),
                "Telemetry must not write any Agent state.");
        }
        finally
        {
            source.Block = null;
            release.Set();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await agent.StopAsync(timeout.Token).WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    // N1 (every Windows run): the real platform sources produce a valid report within the deadline.
    [SupportedOSPlatform("windows")]
    private static async Task VerifyPlatformCollectionAsync()
    {
        var stopwatch = Stopwatch.StartNew();
        var collector = new EndpointTelemetryCollector(new WindowsEndpointTelemetrySource(), TimeProvider.System);
        var report = await collector.CollectAsync(Guid.NewGuid(), CancellationToken.None);
        Ensure(EndpointTelemetryContract.IsValid(report, DateTimeOffset.UtcNow) && stopwatch.Elapsed < collector.Deadline + TimeSpan.FromSeconds(5),
            "Real Windows collection did not produce a valid report within its deadline.");
        Ensure(report.Services.Availability == Collected && report.Software.Availability == Collected &&
               report.PendingReboot.Availability == Collected && report.WindowsUpdate.PolicyAvailability == Collected,
            "SCM, the uninstall registry, restart markers and update policy must be readable on Windows.");
        Console.WriteLine($"Native endpoint telemetry ({stopwatch.ElapsedMilliseconds} ms): {EndpointTelemetryWorker.Describe(report)}");
    }

    /// <summary>
    /// N2 (elevated, Windows CI): compares every collected value with what Windows' own tools report, then delivers the
    /// real report through the production Agent composition to a real Core.
    /// </summary>
    public static async Task RunNativeAcceptanceAsync(string testDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new Exception("Native telemetry acceptance requires Windows.");
        }

        await RunWindowsAcceptanceAsync(testDirectory);
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunWindowsAcceptanceAsync(string testDirectory)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            Ensure(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
                "Native telemetry acceptance must run elevated.");
        }

        var report = await new EndpointTelemetryCollector(new WindowsEndpointTelemetrySource(), TimeProvider.System)
            .CollectAsync(Guid.NewGuid(), CancellationToken.None);
        Ensure(EndpointTelemetryContract.IsValid(report, DateTimeOffset.UtcNow), "The native report is invalid.");
        Console.WriteLine($"Native telemetry sources: {EndpointTelemetryWorker.Describe(report)}");

        // Services: Get-Service is the reference for state and start type.
        var reference = PowerShellJson("""
            $names = @('WinDefend','WdNisSvc','Sense','MpsSvc','BFE','EventLog','wscsvc','SecurityHealthService','wuauserv')
            ConvertTo-Json -Compress -InputObject @($names | ForEach-Object {
              $s = Get-Service -Name $_ -ErrorAction SilentlyContinue
              if ($null -eq $s) { [pscustomobject]@{ name = $_; state = 'notInstalled'; startType = $null } }
              else { [pscustomobject]@{ name = $_; state = [int]$s.Status; startType = [int]$s.StartType } }
            })
            """);
        Ensure(report.Services.Availability == Collected, "Elevated collection must read the Service Control Manager.");
        foreach (var expected in reference.EnumerateArray())
        {
            var name = expected.GetProperty("name").GetString()!;
            var actual = report.Services.Items!.Single(item => item.Name == name);
            var state = expected.GetProperty("state");
            var expectedState = state.ValueKind == JsonValueKind.String ? state.GetString()
                : EndpointTelemetryNormalizer.ServiceState(state.GetInt32());
            var startType = expected.GetProperty("startType");
            var expectedStart = startType.ValueKind == JsonValueKind.Number ? EndpointTelemetryNormalizer.ServiceStartType(startType.GetInt32()) : null;
            // A service can change state between the two reads; only a stable observation is compared exactly.
            Ensure(actual.State == expectedState || name is "WdNisSvc" or "Sense" or "wuauserv",
                $"Service {name}: collected {actual.State}, Windows reports {expectedState}.");
            Ensure(actual.StartType == expectedStart, $"Service {name}: collected start type {actual.StartType}, Windows reports {expectedStart}.");
        }

        // Administrators: the members' SIDs, compared with the SIDs Windows lists for S-1-5-32-544.
        var members = PowerShellJson("""
            $group = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $adsi = [ADSI]("WinNT://./" + $group + ",group")
            ConvertTo-Json -Compress -InputObject @($adsi.Invoke('Members') | ForEach-Object {
              (New-Object Security.Principal.SecurityIdentifier(([byte[]]$_.GetType().InvokeMember('objectSid','GetProperty',$null,$_,$null)), 0)).Value
            })
            """);
        var expectedSids = members.EnumerateArray().Select(item => item.GetString()!).Order(StringComparer.Ordinal).ToArray();
        Ensure(report.LocalAdministrators.Availability == Collected && report.LocalAdministrators.MemberCount == expectedSids.Length &&
               report.LocalAdministrators.Members!.Select(member => member.Sid).SequenceEqual(expectedSids.Take(64)),
            $"Administrators: collected {string.Join(",", report.LocalAdministrators.Members?.Select(m => m.Sid) ?? [])}, " +
            $"Windows lists {string.Join(",", expectedSids)}.");
        Ensure(report.LocalAdministrators.Members!.All(member => member.Scope is not null),
            "Elevated collection must resolve every member's scope.");

        // BitLocker: Win32_EncryptableVolume through CIM, or its absence.
        var bitLocker = PowerShellJson("""
            try {
              $v = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($env:SystemDrive)'" -ErrorAction Stop
              if ($null -eq $v) { [pscustomobject]@{ present = $false } | ConvertTo-Json -Compress }
              else { [pscustomobject]@{ present = $true; protection = [int]$v.ProtectionStatus; conversion = [int]$v.ConversionStatus } | ConvertTo-Json -Compress }
            } catch { [pscustomobject]@{ present = $false; error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }
            """);
        if (bitLocker.GetProperty("present").GetBoolean())
        {
            Ensure(report.BitLocker.Availability == Collected &&
                   report.BitLocker.ProtectionStatus == EndpointTelemetryNormalizer.BitLockerProtection(bitLocker.GetProperty("protection").GetInt32()) &&
                   report.BitLocker.ConversionStatus == EndpointTelemetryNormalizer.BitLockerConversion(bitLocker.GetProperty("conversion").GetInt32()),
                $"BitLocker: collected {report.BitLocker}, Windows reports {bitLocker.GetRawText()}.");
        }
        else
        {
            Ensure(report.BitLocker.Availability is TelemetryAvailability.Unsupported or TelemetryAvailability.Unavailable &&
                   report.BitLocker.ProtectionStatus is null, $"BitLocker is unavailable to Windows ({bitLocker.GetRawText()}) but was reported.");
        }

        // Defender: MSFT_MpComputerStatus through CIM, or its absence.
        var defender = PowerShellJson("""
            try {
              $s = Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpComputerStatus -ErrorAction Stop
              [pscustomobject]@{ present = $true; mode = [string]$s.AMRunningMode; av = $s.AntivirusEnabled; rtp = $s.RealTimeProtectionEnabled; tamper = $s.IsTamperProtected } | ConvertTo-Json -Compress
            } catch { [pscustomobject]@{ present = $false; error = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }
            """);
        if (defender.GetProperty("present").GetBoolean())
        {
            bool? Flag(string name) => defender.GetProperty(name).ValueKind switch
            {
                JsonValueKind.True => true, JsonValueKind.False => false, _ => null
            };
            Ensure(report.Defender.Availability == Collected &&
                   report.Defender.RunningMode == EndpointTelemetryNormalizer.DefenderRunningMode(defender.GetProperty("mode").GetString()) &&
                   report.Defender.AntivirusEnabled == Flag("av") && report.Defender.RealTimeProtectionEnabled == Flag("rtp") &&
                   report.Defender.TamperProtectionEnabled == Flag("tamper"),
                $"Defender: collected {report.Defender}, Windows reports {defender.GetRawText()}.");
        }
        else
        {
            Ensure(report.Defender.Availability != Collected, $"Defender is unavailable to Windows ({defender.GetRawText()}) but was reported.");
        }

        // Security Center exists on client editions only.
        var hasSecurityCenter = PowerShellJson("[bool](Get-Service -Name wscsvc -ErrorAction SilentlyContinue) | ConvertTo-Json -Compress")
            .ValueKind == JsonValueKind.True;
        Ensure(hasSecurityCenter ? report.Antivirus.Availability is Collected or TelemetryAvailability.Unavailable
                : report.Antivirus.Availability == TelemetryAvailability.Unsupported,
            $"Antivirus availability {report.Antivirus.Availability} does not match Security Center presence {hasSecurityCenter}.");

        // Restart markers: key and value presence.
        var reboot = PowerShellJson("""
            [pscustomobject]@{
              cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
              wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
              pfro = @((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').GetValueNames() | Where-Object { $_ -in 'PendingFileRenameOperations','PendingFileRenameOperations2' }).Count -gt 0
            } | ConvertTo-Json -Compress
            """);
        Ensure(report.PendingReboot.ComponentBasedServicing == reboot.GetProperty("cbs").GetBoolean() &&
               report.PendingReboot.WindowsUpdate == reboot.GetProperty("wu").GetBoolean() &&
               report.PendingReboot.PendingFileRenameOperations == reboot.GetProperty("pfro").GetBoolean(),
            $"Restart markers: collected {report.PendingReboot}, Windows reports {reboot.GetRawText()}.");

        // Applications: every collected name is a machine-wide uninstall display name, and none is missing.
        var names = PowerShellJson("""
            $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            ConvertTo-Json -Compress -InputObject @(Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object {
              $_.DisplayName -and ([string]$_.DisplayName).Trim() -and -not ($_.SystemComponent -is [int] -and $_.SystemComponent -eq 1) -and
              -not ([string]$_.ParentKeyName).Trim() -and
              ([string]$_.ReleaseType).Trim() -notin 'Update','Hotfix','Security Update','Service Pack' } |
              ForEach-Object { ([string]$_.DisplayName).Trim() } | Sort-Object -Unique)
            """);
        var registryNames = names.EnumerateArray().Select(item => item.GetString()!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var collectedNames = report.Software.Items!.Select(item => item.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Names the contract cannot carry (too long, control or format characters) are counted as skipped instead.
        Ensure(report.Software.Availability == Collected && report.Software.TotalCount > 0 && collectedNames.IsSubsetOf(registryNames) &&
               (report.Software.Truncated || registryNames.Except(collectedNames, StringComparer.OrdinalIgnoreCase).Count() <=
                   report.Software.SkippedCount),
            $"Applications: collected {collectedNames.Count} of {report.Software.TotalCount}; the registry lists {registryNames.Count}.");

        // Windows Update Agent results.
        var update = PowerShellJson("""
            try {
              $r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
              [pscustomobject]@{ present = $true
                search = if ($r.LastSearchSuccessDate -is [datetime]) { $r.LastSearchSuccessDate.ToString('o') } else { $null }
                install = if ($r.LastInstallationSuccessDate -is [datetime]) { $r.LastInstallationSuccessDate.ToString('o') } else { $null } } | ConvertTo-Json -Compress
            } catch { [pscustomobject]@{ present = $false } | ConvertTo-Json -Compress }
            """);
        if (update.GetProperty("present").GetBoolean())
        {
            DateTimeOffset? Date(string name) => update.GetProperty(name).GetString() is { } text
                ? EndpointTelemetryNormalizer.UpdateResultDate(DateTime.Parse(text, null, System.Globalization.DateTimeStyles.RoundtripKind), report.CollectedUtc)
                : null;
            Ensure(report.WindowsUpdate.ResultsAvailability == Collected &&
                   report.WindowsUpdate.LastSuccessfulSearchUtc == Date("search") &&
                   report.WindowsUpdate.LastSuccessfulInstallationUtc == Date("install"),
                $"Windows Update: collected {report.WindowsUpdate}, the Windows Update Agent reports {update.GetRawText()}.");
        }

        // End to end through the production composition and a real Core.
        await using var core = await PostureMonitorTests.CoreFixture.StartAsync(Path.Combine(testDirectory, "telemetry-core"));
        var agentDirectory = Path.Combine(testDirectory, "telemetry-agent");
        var builder = AgentHost.CreateBuilder([]);
        builder.Configuration["Agent:CoreUrl"] = core.Url;
        builder.Configuration["Agent:DataDirectory"] = agentDirectory;
        builder.Configuration["Agent:EnrollmentToken"] = await core.IssueEnrollmentTokenAsync();
        builder.Services.RemoveAll<IEventLogAccess>();
        builder.Services.AddSingleton<IEventLogAccess>(new NoEventLogAccess());
        using var agent = builder.Build();
        var stopwatch = Stopwatch.StartNew();
        await agent.StartAsync();
        try
        {
            var receipt = Path.Combine(agentDirectory, "endpoint-id");
            Guid endpointId = default;
            await WaitUntilAsync(() => File.Exists(receipt) && Guid.TryParse(File.ReadAllText(receipt), out endpointId),
                "The native Agent did not enroll.", TimeSpan.FromSeconds(30));
            var store = core.Services.GetRequiredService<EndpointTelemetryStore>();
            StoredEndpointTelemetry? stored = null;
            await WaitUntilAsync(() => (stored = store.FindLatestAsync(endpointId).GetAwaiter().GetResult()) is not null,
                "The native Agent did not deliver telemetry.", TimeSpan.FromSeconds(60));
            Ensure(stored!.Report.Services.Items!.Count == EndpointTelemetryContract.MonitoredServices.Count &&
                   stored.Report.LocalAdministrators.MemberCount == report.LocalAdministrators.MemberCount,
                "Core did not store the native report.");
            Console.WriteLine($"Native endpoint telemetry reached Core after {stopwatch.ElapsedMilliseconds} ms.");
        }
        finally
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await agent.StopAsync(timeout.Token);
        }
    }

    [SupportedOSPlatform("windows")]
    private static JsonElement PowerShellJson(string script)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new Exception("PowerShell did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        Ensure(process.WaitForExit(60_000) && process.ExitCode == 0,
            $"The reference PowerShell command failed: {error.GetAwaiter().GetResult()}");
        var text = output.GetAwaiter().GetResult().Trim();
        return JsonDocument.Parse(text.Length == 0 ? "[]" : text).RootElement.Clone();
    }

    internal static EndpointTelemetryReport Benign(Guid endpointId) => new(EndpointTelemetryContract.CurrentSchemaVersion, endpointId,
        Now.AddMinutes(-1),
        new BitLockerTelemetry(Collected, "on", "fullyEncrypted"),
        new AntivirusTelemetry(Collected, "good"),
        new DefenderTelemetry(Collected, "normal", true, true, true, 1),
        new LocalAdministratorsTelemetry(Collected, 2,
            [new($"{DomainSid}-1001", AdministratorScopes.Local, "user"), new($"{DomainSid}-500", AdministratorScopes.Local, "user")]),
        new WindowsUpdateTelemetry(Collected, Collected, "notConfigured", false, Now.AddHours(-1), Now.AddDays(-3)),
        new PendingRebootTelemetry(Collected, false, false, true),
        new SecurityServicesTelemetry(Collected, EndpointTelemetryContract.MonitoredServices
            .Select(name => new SecurityServiceObservation(name, ServiceRunStates.Running, ServiceStartTypes.Auto)).ToArray()),
        new InstalledSoftwareTelemetry(Collected, [new("test-only application", "1.0", "Example Corp", "x64")], 1));

    /// <summary>
    /// A report with every count, SID, vocabulary value and timestamp at its longest and every application character
    /// escaped. The application list is filled by the Agent's own budget; the size proof counts that budget in full.
    /// </summary>
    private static EndpointTelemetryReport WorstCase(Guid endpointId)
    {
        static string Longest(IEnumerable<string> values) => values.MaxBy(value => value.Length)!;
        var stamp = Now.AddTicks(1234567);
        var sid = "S-1-" + new string('9', 13) + string.Concat(Enumerable.Repeat("-4294967295", 15));
        var members = Enumerable.Range(0, EndpointTelemetryContract.MaxAdministratorMembers)
            .Select(index => new LocalAdministratorMember(sid[..^4] + (1000 + index), Longest(AdministratorScopes.All),
                Longest(AdministratorAccountTypes.All)))
            .ToArray();
        var escaped = new string('é', EndpointTelemetryContract.MaxSoftwareNameLength);
        var entries = Enumerable.Range(0, 5000).Select(index => new RawSoftwareEntry(
            escaped[..^5] + index.ToString("D5"), new string('é', EndpointTelemetryContract.MaxSoftwareVersionLength),
            new string('<', EndpointTelemetryContract.MaxSoftwarePublisherLength), null, null, null, "arm64"));
        var software = EndpointTelemetryNormalizer.Software(entries, unreadableEntries: 9999);
        return Benign(endpointId) with
        {
            CollectedUtc = stamp,
            BitLocker = new BitLockerTelemetry(Collected, Longest(BitLockerProtectionStates.All), Longest(BitLockerConversionStates.All)),
            Antivirus = new AntivirusTelemetry(Collected, Longest(SecurityCenterHealthStates.All)),
            Defender = new DefenderTelemetry(Collected, Longest(DefenderRunningModes.All), false, false, false,
                EndpointTelemetryContract.MaxSignatureAgeDays),
            LocalAdministrators = new LocalAdministratorsTelemetry(Collected, EndpointTelemetryContract.MaxAdministratorMemberCount, members),
            WindowsUpdate = new WindowsUpdateTelemetry(Collected, Collected, Longest(AutomaticUpdatesPolicies.All), false,
                stamp.AddMinutes(-1), stamp.AddMinutes(-2)),
            PendingReboot = new PendingRebootTelemetry(Collected, false, false, false),
            Services = new SecurityServicesTelemetry(Collected, EndpointTelemetryContract.MonitoredServices
                .Select(name => new SecurityServiceObservation(name, Longest(ServiceRunStates.All), Longest(ServiceStartTypes.All)))
                .ToArray()),
            Software = software with
            {
                TotalCount = EndpointTelemetryContract.MaxSoftwareTotal, SkippedCount = EndpointTelemetryContract.MaxSoftwareTotal
            }
        };
    }

    private static EnrollmentState Enrollment() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
        new string('a', 64), "http://127.0.0.1:5000", null);

    private static async Task WaitUntilAsync(Func<bool> condition, string message, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(20);
        }

        throw new Exception(message);
    }

    private static void Ensure(bool condition, string message)
    {
        _checks++;
        if (!condition)
        {
            throw new Exception(message);
        }
    }

    /// <summary>Returns the benign sections; can fail, return contract-violating values or block per section.</summary>
    private sealed class FakeTelemetrySource(Guid endpointId) : IEndpointTelemetrySource
    {
        private int _calls;
        private int _softwareCalls;
        private readonly EndpointTelemetryReport _report = Benign(endpointId == Guid.Empty ? Guid.NewGuid() : endpointId);

        public Dictionary<string, Exception> Failures { get; } = new(StringComparer.Ordinal);
        public bool Invalid { get; set; }
        public ManualResetEventSlim? Block { get; set; }
        public int Calls => Volatile.Read(ref _calls);
        public int SoftwareCalls => Volatile.Read(ref _softwareCalls);

        public BitLockerTelemetry ReadBitLocker() => Read("bitLocker", _report.BitLocker);
        public AntivirusTelemetry ReadAntivirus() => Read("antivirus", _report.Antivirus);

        public DefenderTelemetry ReadDefender() =>
            Read("defender", Invalid ? new DefenderTelemetry(TelemetryAvailability.AccessDenied, "normal") : _report.Defender);

        public LocalAdministratorsTelemetry ReadLocalAdministrators() => Read("localAdministrators", _report.LocalAdministrators);
        public WindowsUpdateTelemetry ReadWindowsUpdate(DateTimeOffset collectedUtc) => Read("windowsUpdate", _report.WindowsUpdate);
        public PendingRebootTelemetry ReadPendingReboot() => Read("pendingReboot", _report.PendingReboot);
        public SecurityServicesTelemetry ReadServices() => Read("services", _report.Services);

        public InstalledSoftwareTelemetry ReadSoftware()
        {
            Interlocked.Increment(ref _softwareCalls);
            Block?.Wait();
            return Read("software", _report.Software);
        }

        private T Read<T>(string section, T value)
        {
            Interlocked.Increment(ref _calls);
            return Failures.TryGetValue(section, out var failure) ? throw failure : value;
        }
    }

    /// <summary>The system clock with an adjustable wall-clock offset; timers stay monotonic, as on Windows.</summary>
    private sealed class SteppedClock : TimeProvider
    {
        private long _offsetTicks;

        public TimeSpan Offset
        {
            get => TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));
            set => Interlocked.Exchange(ref _offsetTicks, value.Ticks);
        }

        public override DateTimeOffset GetUtcNow() => System.GetUtcNow() + Offset;
    }

    private sealed class FakeUploader : IEndpointTelemetryUploader
    {
        private int _accepted;
        public System.Collections.Concurrent.ConcurrentQueue<EndpointTelemetryReport> Sent { get; } = new();
        public volatile UploadResult Next = UploadResult.Accepted;
        public volatile bool ThrowNext;
        public int Accepted => Volatile.Read(ref _accepted);

        public Task<TelemetryUploadOutcome> SendAsync(EndpointTelemetryReport report, EnrollmentState enrollment,
            CancellationToken cancellationToken)
        {
            Sent.Enqueue(report);
            if (ThrowNext)
            {
                ThrowNext = false;
                throw new InvalidOperationException("Synthetic unexpected uploader failure.");
            }

            var result = Next;
            if (result == UploadResult.Accepted) Interlocked.Increment(ref _accepted);
            return Task.FromResult(new TelemetryUploadOutcome(result, result == UploadResult.Accepted ? 204 : 503));
        }
    }
}
