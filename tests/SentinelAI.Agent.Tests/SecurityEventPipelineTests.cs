using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Agent;
using SentinelAI.Contracts.SecurityEvents;

/// <summary>
/// TASK-027 deterministic tier (D1-D23): the pipeline driven step by step with a synthetic event log,
/// a manual clock and scripted or in-memory Core uploaders; plus the read-only native tier N1 on Windows.
/// </summary>
internal static class SecurityEventPipelineTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 13, 8, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(5);
    // Shared across the normalizer, continuity and availability checks for the log privacy check (D19).
    private static readonly CapturingEventLoggerProvider PrivacyLogs = new();
    private static int assertions;

    public static async Task RunAsync(string root)
    {
        Directory.CreateDirectory(root);
        VerifyOptions(root);
        VerifyCatalogConformance();
        await VerifyNormalizerAsync(root);
        VerifyServiceImagePath();
        VerifyValidator();
        VerifySizeBounds();
        await VerifyCheckpointStoreAsync(Path.Combine(root, "d7"));
        await VerifyDormancyAsync(Path.Combine(root, "d8"));
        await VerifyFirstStartAsync(Path.Combine(root, "d9"));
        await VerifySteadyDeliveryAsync(Path.Combine(root, "d10"));
        await VerifyCapsAsync(Path.Combine(root, "d11"));
        await VerifyBackpressureAsync(Path.Combine(root, "d12"));
        await VerifyIncompatibleAsync(Path.Combine(root, "d13"));
        await VerifyContinuityAsync(Path.Combine(root, "d14"));
        await VerifyAvailabilityAsync(Path.Combine(root, "d15"));
        await VerifyStatusCadenceAsync(Path.Combine(root, "d16"));
        await VerifyScanCapsAsync(Path.Combine(root, "d17"));
        await VerifyCorruptCheckpointAsync(Path.Combine(root, "d18"));
        VerifyLogPrivacy();
        await VerifyUploaderAsync(root);
        await VerifyAgentLinkAsync();
        await VerifyInvariantAsync(Path.Combine(root, "d22"));
        VerifyForbiddenApis();
        if (OperatingSystem.IsWindows()) VerifyNativeConformance();
        Console.WriteLine($"Security event pipeline tests passed ({assertions} assertions).");
    }

    // D1: the one option, its bounds and the derived timing table.
    private static void VerifyOptions(string root)
    {
        AgentOptions Read(string? interval) => AgentOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Agent:DataDirectory"] = Path.GetFullPath(root), ["Agent:EventPollInterval"] = interval
            }).Build());

        Check(Read(null).EventPollInterval == TimeSpan.FromSeconds(5), "The default event poll interval is not 5 seconds.");
        Check(Read("00:00:00.100").EventPollInterval == TimeSpan.FromMilliseconds(100), "The minimum poll interval was rejected.");
        Check(Read("00:05:00").EventPollInterval == TimeSpan.FromMinutes(5), "The maximum poll interval was rejected.");
        foreach (var invalid in new[] { "00:00:00.099", "00:05:00.001", "0", "-00:00:01", "abc" })
            Reject<InvalidOperationException>(() => Read(invalid), $"The event poll interval {invalid} was accepted.");
        Check(Read(null).SecurityEventsUrl.AbsoluteUri == "http://127.0.0.1:5000/api/agent/security-events",
            "The security event route is wrong.");

        var production = SecurityEventTimings.From(Read(null));
        Check(production == new SecurityEventTimings(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(60),
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5)),
            "Production event timings differ from the documented table.");
        var fast = SecurityEventTimings.From(Read("00:00:00.100"));
        Check(fast == new SecurityEventTimings(TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100),
                TimeSpan.FromMilliseconds(400), TimeSpan.FromMilliseconds(1200), TimeSpan.FromSeconds(18),
                TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(72), TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(6)),
            "Test event timings differ from the documented table.");
    }

    // D2: catalog conformance, golden server queries, field allowlist and documentation sync.
    private static void VerifyCatalogConformance()
    {
        var catalog = SecurityEventCatalog.Production;
        var definitions = catalog.Channels.SelectMany(channel => channel.Definitions).ToArray();
        Check(definitions.Select(definition =>
                    new SecurityEventSelection(definition.Channel, definition.Provider, definition.EventId, definition.Kind))
                .SequenceEqual(SecurityEventContract.Catalog),
            "Agent catalog definitions differ from the shared contract catalog.");
        Check(definitions.Length == 16 && definitions.Select(definition => definition.Kind).Distinct().Count() == 12 &&
              catalog.ChannelNames.SequenceEqual(SecurityEventChannels.All),
            "The catalog does not have 16 selections, 12 kinds and 4 channels in order.");

        var expected = new Dictionary<int, (string Predicate, string Fields)>
        {
            [4624] = ("LogonType:0", "TargetUserSid:0,IpAddress:0,ElevatedToken:2"),
            [4625] = ("", "LogonType:0,TargetUserSid:0,IpAddress:0,Status:0,SubStatus:0"),
            [4698] = ("", "TaskName:0,SubjectUserSid:0"),
            [1102] = ("", ""),
            [7045] = ("", "ServiceName:0,ImagePath:0,ServiceType:0,StartType:0,AccountName:0"),
            [7040] = ("param4:0", "param3:0"),
            [104] = ("", "Channel:0"),
            [4104] = ("MessageNumber:1", "ScriptBlockId:1,MessageTotal:1"),
            [1116] = ("", "Detection ID:0,Threat ID:0,Threat Name:0,Severity ID:0,Category ID:0"),
            [1117] = ("", "Detection ID:0,Threat ID:0,Threat Name:0,Severity ID:0,Category ID:0,Action ID:0"),
            [1118] = ("", "Detection ID:0,Threat ID:0,Threat Name:0,Severity ID:0,Category ID:0,Action ID:0,Error Code:0"),
            [1119] = ("", "Detection ID:0,Threat ID:0,Threat Name:0,Severity ID:0,Category ID:0,Action ID:0,Error Code:0"),
            [5001] = ("", ""),
            [5010] = ("", ""),
            [5012] = ("", ""),
            [5007] = ("", "Old Value:0,New Value:0")
        };
        static string Describe(EventFieldSet? set) =>
            string.Join(",", set?.Fields.Select(field => $"{field.Name}:{field.SinceVersion}") ?? []);
        foreach (var definition in definitions)
        {
            Check(Describe(definition.Predicate) == expected[definition.EventId].Predicate &&
                  Describe(definition.Fields) == expected[definition.EventId].Fields,
                $"Catalog fields for {definition.EventId} differ from the specification.");
            foreach (var field in (definition.Predicate?.Fields ?? []).Concat(definition.Fields.Fields))
            {
                var path = field.Name == "Channel" && definition.EventId == 104
                    ? "Event/UserData/LogFileCleared/Channel"
                    : $"Event/EventData/Data[@Name='{field.Name}']";
                Check(field.Path == path, $"Field {field.Name} of {definition.EventId} is not read by name.");
                Check(!SecurityEventFixtures.ExcludedFields.Contains(field.Name, StringComparer.OrdinalIgnoreCase),
                    $"Field {field.Name} is excluded from collection.");
            }

            Check(definition.Level is null || definition.EventId == 4104 && definition.Level == 3,
                "Only 4104 is filtered by level.");
        }

        var groups = new Dictionary<string, string>
        {
            [SecurityEventChannels.Security] =
                "(Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625 or EventID=4698)) or " +
                "(Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=1102)",
            [SecurityEventChannels.System] =
                "(Provider[@Name='Service Control Manager'] and (EventID=7040 or EventID=7045)) or " +
                "(Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104)",
            [SecurityEventChannels.PowerShell] = "(Provider[@Name='Microsoft-Windows-PowerShell'] and EventID=4104 and Level=3)",
            [SecurityEventChannels.Defender] =
                "(Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=1116 or EventID=1117 or EventID=1118 or " +
                "EventID=1119 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012))"
        };
        foreach (var (channel, group) in groups)
        {
            Check(catalog.BuildXPath(channel, 1234, 5678, null) ==
                  $"*[System[{group} or EventRecordID=1234 or EventRecordID=5678]]",
                $"The {channel} query with an anchor differs from the golden string.");
            Check(catalog.BuildXPath(channel, null, 5678, null) == $"*[System[{group} or EventRecordID=5678]]",
                $"The {channel} query without an anchor differs from the golden string.");
            Check(catalog.BuildXPath(channel, 1234, 5678, 1234) ==
                  $"*[System[(({group}) or EventRecordID=1234 or EventRecordID=5678) and EventRecordID>=1234]]",
                $"The {channel} fallback query differs from the golden string.");
        }

        Reject<ArgumentException>(() => catalog.BuildXPath("Application", null, 1, null), "A non-catalog query was built.");
        var providerRule = new Regex("^[A-Za-z0-9 ._-]+$");
        Check(definitions.All(definition => providerRule.IsMatch(definition.Provider)),
            "A catalog provider name contains characters outside the query-safe set.");
        Reject<ArgumentException>(() => SecurityEventCatalog.Create(
        [
            new("Test-Only/Operational",
            [
                new("Test-Only/Operational", "Test'Only", 1, "test", null, null, new EventFieldSet([]))
            ])
        ]), "A provider name with a quote was accepted.");
        Reject<ArgumentException>(() => SecurityEventCatalog.Create(
        [
            new("Test'Only",
            [
                new("Test'Only", "Test-Only", 1, "test", null, null, new EventFieldSet([]))
            ])
        ]), "A channel name with a quote was accepted.");

        // Documentation sync: the published allowlist table must list every selection and exclusion.
        var documentation = Path.Combine(RepositoryRoot(), "docs", "SECURITY-EVENTS.md");
        if (File.Exists(documentation))
        {
            var lines = File.ReadAllLines(documentation);
            foreach (var selection in SecurityEventContract.Catalog)
            {
                var prefix = $"| {selection.Channel} | {selection.Provider} | {selection.EventId} | {selection.Kind} |";
                Check(lines.Any(line => line.StartsWith(prefix, StringComparison.Ordinal)),
                    $"docs/SECURITY-EVENTS.md does not document {selection.EventId} on {selection.Channel}.");
            }

            var text = string.Join("\n", lines);
            foreach (var excluded in SecurityEventFixtures.ExcludedFields)
                Check(text.Contains(excluded, StringComparison.Ordinal), $"docs/SECURITY-EVENTS.md does not list {excluded}.");
        }
        else
        {
            Console.WriteLine("Security event documentation sync skipped: docs/SECURITY-EVENTS.md is not present yet.");
        }
    }

    // D3: the normalizer per kind with typed and string inputs, plus edge variants.
    private static async Task VerifyNormalizerAsync(string root)
    {
        var expected = new Dictionary<int, Func<SecurityEventObservation, bool>>
        {
            [4624] = o => o.Logon == new LogonEvent(10, SecurityEventFixtures.UserSid, SecurityEventFixtures.RemoteIp, null, null, true),
            [4625] = o => o.Logon == new LogonEvent(3, null, "2001:db8::10", 3221225581, 0xC000006A, null),
            [4698] = o => o.ScheduledTask == new ScheduledTaskEvent(@"\test-only-task", SecurityEventFixtures.SubjectSid),
            [1102] = o => o.LogCleared == new LogClearedEvent(SecurityEventChannels.Security),
            [7045] = o => o.ServiceInstall == new ServiceInstallEvent("test-only-service", "svc.exe",
                ServiceImageLocations.ProgramFiles, ServiceTypes.UserModeService, ServiceStartTypes.Demand,
                ServiceAccountKinds.LocalSystem),
            [7040] = o => o.ServiceStartType == new ServiceStartTypeEvent("WinDefend", ServiceStartTypes.Disabled),
            [104] = o => o.LogCleared == new LogClearedEvent("Application"),
            [4104] = o => o.ScriptBlock == new ScriptBlockEvent(SecurityEventFixtures.ScriptBlockId, 2),
            [1116] = o => o.Malware == new MalwareEvent(SecurityEventFixtures.DetectionId, 2147735505,
                "Test-Only:Win32/Fixture", 5, 8, null, null),
            [1117] = o => o.Malware == new MalwareEvent(SecurityEventFixtures.DetectionId, 2147735505,
                "Test-Only:Win32/Fixture", 5, 8, 2, null),
            [1118] = o => o.Malware == new MalwareEvent(SecurityEventFixtures.DetectionId, 2147735505,
                "Test-Only:Win32/Fixture", 5, 8, 2, 0x80508023),
            [1119] = o => o.Malware == new MalwareEvent(SecurityEventFixtures.DetectionId, 2147735505,
                "Test-Only:Win32/Fixture", 5, 8, 2, 0x80508023),
            [5001] = NoPayload,
            [5010] = NoPayload,
            [5012] = NoPayload,
            [5007] = o => o.DefenderSetting == new DefenderSettingEvent(DefenderSettingAreas.ExclusionPath, DefenderSettingChanges.Added)
        };
        foreach (var fixture in SecurityEventFixtures.Positive)
        {
            var result = Normalize(fixture);
            var observation = result.Observation;
            Check(result.Outcome == NormalizationOutcome.Selected && observation is not null && result.FieldsDiscarded == 0,
                $"Fixture {fixture.EventId} was not normalized cleanly.");
            Check(observation!.Channel == fixture.Channel && observation.Provider == fixture.Provider &&
                  observation.EventId == fixture.EventId && observation.EventVersion == fixture.Version &&
                  observation.Level == fixture.Level && observation.RecordId == 7 &&
                  observation.TimeCreatedUtc == SyntheticEventLog.TimeOf(0, 7) && expected[fixture.EventId](observation),
                $"Fixture {fixture.EventId} produced an unexpected observation.");
            Check(result.Size == SecurityEventContract.MeasureBytes(observation), "The measured observation size is wrong.");
            Check(!JsonSerializer.Serialize(observation, SecurityEventContract.Json).Contains(SecurityEventFixtures.Marker) &&
                  !JsonSerializer.Serialize(observation).Contains(SecurityEventFixtures.Marker) &&
                  !observation.ToString().Contains(SecurityEventFixtures.Marker),
                $"Fixture {fixture.EventId} leaked an excluded value.");
        }

        // Absent, canonicalized and discarded values.
        var logonFailed = SecurityEventFixtures.For(4625);
        Check(Normalize(logonFailed, new() { ["IpAddress"] = "-" }) is { FieldsDiscarded: 0 } dash &&
              dash.Observation!.Logon!.IpAddress is null, "An absent IP address was not null.");
        Check(Normalize(logonFailed, new() { ["IpAddress"] = "::ffff:192.0.2.10" }).Observation!.Logon!.IpAddress == "192.0.2.10",
            "An IPv4-mapped address was not reduced to IPv4.");
        Check(Normalize(logonFailed, new() { ["IpAddress"] = "fe80::1%12" }).Observation!.Logon!.IpAddress == "fe80::1",
            "An IPv6 scope ID was kept.");
        Check(Normalize(logonFailed, new() { ["IpAddress"] = "not-an-address" }) is { FieldsDiscarded: 1 } badIp &&
              badIp.Observation!.Logon!.IpAddress is null, "An invalid IP address was not discarded and counted.");
        Check(Normalize(logonFailed).Observation!.Logon!.TargetUserSid is null && Normalize(logonFailed).FieldsDiscarded == 0,
            "The anonymous SID was not treated as absent.");
        Check(Normalize(logonFailed, new() { ["TargetUserSid"] = "S-1-5-21-test-only" }) is { FieldsDiscarded: 1 } badSid &&
              badSid.Observation!.Logon!.TargetUserSid is null, "An invalid SID was not discarded and counted.");
        Check(Normalize(logonFailed, new() { ["Status"] = "0xC000006D" }).Observation!.Logon!.Status == 3221225581 &&
              Normalize(logonFailed, new() { ["Status"] = "3221225581" }).Observation!.Logon!.Status == 3221225581,
            "NTSTATUS strings were not parsed.");
        var logon = SecurityEventFixtures.For(4624);
        Check(Normalize(logon, new() { ["ElevatedToken"] = "%%1843" }).Observation!.Logon!.ElevatedToken == false &&
              Normalize(logon, new() { ["ElevatedToken"] = "x" }) is { FieldsDiscarded: 1 } elevated &&
              elevated.Observation!.Logon!.ElevatedToken is null, "Elevated token values were not mapped.");
        Check(Normalize(logon, new() { ["LogonType"] = 3 }).Outcome == NormalizationOutcome.NotSelected &&
              Normalize(logon, new() { ["LogonType"] = "2" }).Observation!.Logon!.LogonType == 2 &&
              Normalize(logon, new() { ["LogonType"] = 11 }).Observation!.Logon!.LogonType == 11,
            "The 4624 logon type predicate is wrong.");
        Check(Normalize(logon, new() { ["TargetOutboundUserName"] = SecurityEventFixtures.Marker }, version: 3) is
              { Outcome: NormalizationOutcome.Selected } later && later.Observation!.EventVersion == 3 &&
              later.Observation.Logon == new LogonEvent(10, SecurityEventFixtures.UserSid, SecurityEventFixtures.RemoteIp,
                  null, null, true), "A later event version with an extra field was not parsed by name.");
        var scriptBlock = SecurityEventFixtures.For(4104);
        Check(Normalize(scriptBlock, new() { ["MessageNumber"] = 2 }).Outcome == NormalizationOutcome.NotSelected,
            "A continuation script block part was selected.");
        var startType = SecurityEventFixtures.For(7040);
        Check(Normalize(startType, new() { ["param4"] = "BITS" }).Outcome == NormalizationOutcome.NotSelected,
            "A start-type change of a non-protection service was selected.");
        var service = SecurityEventFixtures.For(7045);
        Check(Normalize(service, new() { ["StartType"] = "Start bei Bedarf" }) is { FieldsDiscarded: 1 } localized &&
              localized.Observation!.ServiceInstall!.StartType is null &&
              Normalize(service, new() { ["StartType"] = "3" }).Observation!.ServiceInstall!.StartType == ServiceStartTypes.Demand &&
              Normalize(service, new() { ["StartType"] = 2 }).Observation!.ServiceInstall!.StartType == ServiceStartTypes.Auto,
            "Service start types were not mapped.");
        Check(SecurityEventCatalog.Production.Find(SecurityEventChannels.Security, "Test-Only-Provider", 4624, 0) is null &&
              SecurityEventCatalog.Production.Find(SecurityEventChannels.Security, "microsoft-windows-security-auditing", 4624, 0)
                  is not null &&
              SecurityEventCatalog.Production.Find(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104, 4)
                  is null, "Catalog lookup does not follow the server filter.");

        var definition = Definition(service);
        var renderFailed = SecurityEventNormalizer.Normalize(definition, Header(service, 9), null, null);
        Check(renderFailed is { Outcome: NormalizationOutcome.Selected, FieldsDiscarded: 5 } &&
              renderFailed.Observation!.ServiceInstall == new ServiceInstallEvent(null, null, null, null, null, null),
            "A field render failure suppressed the occurrence or kept values.");
        var task = SecurityEventFixtures.For(4698);
        Check(Normalize(task, new() { ["TaskName"] = EventFieldValue.Oversize }) is { FieldsDiscarded: 1 } oversized &&
              oversized.Observation!.ScheduledTask!.TaskName is null, "An oversized value was not discarded and counted.");
        Check(Normalize(task, new() { ["TaskName"] = "test-only\u202Etask" }) is { FieldsDiscarded: 1 } bidi &&
              bidi.Observation!.ScheduledTask!.TaskName is null, "A format character survived in text.");
        var predicateFailed = SecurityEventNormalizer.PassesPredicate(Definition(logon), null, out var predicateDiscarded);
        Check(!predicateFailed && predicateDiscarded == 1, "A predicate render failure was selected or not counted.");

        // 5007 classification: area by registry prefix, change by which value is present.
        (string? Area, string? Change) Setting(object? oldValue, object? newValue)
        {
            var setting = DefenderSettingClassifier.Classify(oldValue, newValue);
            return (setting.Area, setting.Change);
        }

        const string Prefix = @"HKLM\SOFTWARE\Microsoft\Windows Defender\";
        Check(Setting("", Prefix + @"Exclusions\Paths\C:\test-only = 0x0") == (DefenderSettingAreas.ExclusionPath, "added") &&
              Setting(Prefix + @"Exclusions\Processes\test-only.exe = 0x0", "") == (DefenderSettingAreas.ExclusionProcess, "removed") &&
              Setting(Prefix + @"Exclusions\Extensions\x = 0x0", Prefix + @"Exclusions\Extensions\y = 0x0") ==
              (DefenderSettingAreas.ExclusionExtension, "modified") &&
              Setting(null, Prefix + @"Exclusions\IpAddresses\192.0.2.1 = 0x0") == (DefenderSettingAreas.ExclusionIpAddress, "added") &&
              Setting(Prefix + @"Real-Time Protection\DisableRealtimeMonitoring = 0x0",
                  Prefix + @"Real-Time Protection\DisableRealtimeMonitoring = 0x1") == (DefenderSettingAreas.RealTimeProtection, "modified") &&
              Setting(null, @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features\TamperProtection = 0x4") ==
              (DefenderSettingAreas.TamperProtection, "added") &&
              Setting(null, Prefix + @"Scan\AvgCPULoadFactor = 0x32") == (DefenderSettingAreas.Other, "added") &&
              Setting(null, @"HKLM\SOFTWARE\test-only = 0x1") == (DefenderSettingAreas.Other, "added") &&
              Setting("-", "") == (null, null),
            "Defender setting changes were not classified.");

        // Through the pipeline: every fixture plus a render failure and a record without a time.
        var rig = await Rig.CoveredAsync(Path.Combine(root, "d3"), logs: PrivacyLogs);
        foreach (var fixture in SecurityEventFixtures.Positive) SecurityEventFixtures.Append(rig.Log, fixture);
        var failedRender = SecurityEventFixtures.Append(rig.Log, service, new() { ["ImagePath"] = SyntheticEventLog.RenderFailure });
        var untimed = rig.Log.Append(service.Channel, service.Provider, service.EventId, service.Fields, service.Level,
            withoutTime: true);
        await rig.AdvanceAsync(Poll);
        var delivered = rig.Uploader.AcceptedBatches[^1];
        Check(delivered.Events.Count == 17 &&
              delivered.Events.Single(o => o.RecordId == failedRender && o.Channel == SecurityEventChannels.System)
                  .ServiceInstall == new ServiceInstallEvent(null, null, null, null, null, null),
            "The pipeline did not deliver every fixture and the render-failed occurrence.");
        Check(delivered.Gaps.SingleOrDefault() == new SecurityEventGap(SecurityEventChannels.System,
                  SecurityEventGapReasons.Dropped, untimed, untimed, rig.Time.GetUtcNow()) &&
              rig.Source(SecurityEventChannels.System).DroppedUnparsed == 1 &&
              rig.Source(SecurityEventChannels.System).FieldsDiscarded == 5,
            "A record without a creation time was not reported as a dropped gap.");
        Check(!JsonSerializer.Serialize(delivered, SecurityEventContract.Json).Contains(SecurityEventFixtures.Marker),
            "A delivered batch contained an excluded value.");
        Check(!rig.Log.RequestedFieldNames.Intersect(SecurityEventFixtures.ExcludedFields, StringComparer.OrdinalIgnoreCase).Any(),
            "An excluded field was requested from the event log.");

        static bool NoPayload(SecurityEventObservation o) =>
            o is { Logon: null, ScheduledTask: null, LogCleared: null, ServiceInstall: null, ServiceStartType: null,
                ScriptBlock: null, Malware: null, DefenderSetting: null };
    }

    // D4: image path reduction to a leaf name and location class; account kinds.
    private static void VerifyServiceImagePath()
    {
        var cases = new (string Input, string? Name, string? Location, bool Discarded)[]
        {
            ("\"C:\\Program Files\\Test Only\\svc.exe\" --password=x", "svc.exe", ServiceImageLocations.ProgramFiles, false),
            (@"C:\Windows\system32\svchost.exe -k netsvcs", "svchost.exe", ServiceImageLocations.Windows, false),
            (@"System32\drivers\t.sys", "t.sys", ServiceImageLocations.Windows, false),
            (@"\SystemRoot\System32\drivers\x.sys", "x.sys", ServiceImageLocations.Windows, false),
            (@"\??\C:\Windows\x.sys", "x.sys", ServiceImageLocations.Windows, false),
            (@"%SystemRoot%\Temp\a.exe", "a.exe", ServiceImageLocations.Temp, false),
            (@"%windir%\system32\a.exe", "a.exe", ServiceImageLocations.Windows, false),
            (@"C:\Windows\Temp\a.exe", "a.exe", ServiceImageLocations.Temp, false),
            (@"C:\Users\test-only\AppData\Local\Temp\a.exe", "a.exe", ServiceImageLocations.Temp, false),
            (@"C:\Users\test-only\a.exe", "a.exe", ServiceImageLocations.UserProfile, false),
            (@"C:\ProgramData\a.exe", "a.exe", ServiceImageLocations.ProgramData, false),
            (@"C:\Program Files (x86)\Test Only\a.exe /service", "a.exe", ServiceImageLocations.ProgramFiles, false),
            (@"\\server\share\a.exe", "a.exe", ServiceImageLocations.Network, false),
            (@"\\?\UNC\server\share\a.exe", "a.exe", ServiceImageLocations.Network, false),
            (@"D:\tools\a.exe", "a.exe", ServiceImageLocations.Other, false),
            (@"C:/Windows/a.exe", "a.exe", ServiceImageLocations.Windows, false),
            (@"C:\Windows\..\Users\test-only\a.exe", "a.exe", ServiceImageLocations.Other, false),
            ("cmd /c whoami", "cmd", null, false),
            ("%COMSPEC% /c x", null, null, true),
            (@"C:\Program Files\Test Only\svc --flag", null, null, true),
            ("\"C:\\Program Files\\svc.exe --password=x", null, null, true),
            ("\"C:\\Windows\\\" --password=x", null, ServiceImageLocations.Windows, true),
            ("-", null, null, false)
        };
        foreach (var (input, name, location, discarded) in cases)
        {
            var image = ServiceImagePath.Derive(input);
            Check(image == new ServiceImage(name, location, discarded), $"Image path '{input}' was not derived as expected.");
            Check((image.FileName ?? string.Empty).IndexOfAny(['\\', '/', ' ', '=']) < 0,
                $"Image path '{input}' kept directories or arguments.");
        }

        Check(ServiceImagePath.Derive(EventFieldValue.Oversize) == new ServiceImage(null, null, true) &&
              ServiceImagePath.Derive(null) == new ServiceImage(null, null, false),
            "Oversized or absent image paths were not handled.");

        var accounts = new (string? Input, string? Kind)[]
        {
            ("LocalSystem", ServiceAccountKinds.LocalSystem), (@".\LocalSystem", ServiceAccountKinds.LocalSystem),
            (@"NT AUTHORITY\SYSTEM", ServiceAccountKinds.LocalSystem), (@"nt authority\localservice", ServiceAccountKinds.LocalService),
            (@"NT AUTHORITY\LOCAL SERVICE", ServiceAccountKinds.LocalService),
            (@"NT AUTHORITY\NetworkService", ServiceAccountKinds.NetworkService),
            (@"NT AUTHORITY\NETWORK SERVICE", ServiceAccountKinds.NetworkService),
            (@"NT SERVICE\TestOnly", ServiceAccountKinds.VirtualAccount), (@" TEST-ONLY\user ", ServiceAccountKinds.OtherAccount),
            ("", null), (null, null)
        };
        foreach (var (input, kind) in accounts)
        {
            var discarded = 0;
            Check(SecurityEventNormalizer.AccountKind(input, ref discarded) == kind && discarded == 0,
                $"Account '{input}' was not classified.");
        }
    }

    // D5: the shared validator, including strict JSON.
    private static void VerifyValidator()
    {
        var endpoint = Guid.NewGuid();
        var valid = SampleBatch(endpoint);
        Check(SecurityEventContract.IsValidEnvelope(valid), "A valid batch envelope was rejected.");
        var observation = valid.Events[0];
        var status = valid.Sources[0];
        Check(SecurityEventContract.IsValidEnvelope(valid with { Events = Enumerable.Repeat(observation, 256).ToArray() }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { Events = Enumerable.Repeat(observation, 257).ToArray() }),
            "The event cap is not 256.");
        var gap = valid.Gaps[0];
        Check(SecurityEventContract.IsValidEnvelope(valid with { Gaps = Enumerable.Repeat(gap, 32).ToArray() }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { Gaps = Enumerable.Repeat(gap, 33).ToArray() }),
            "The gap cap is not 32.");
        SecurityEventSourceStatus[] eight = Enumerable.Range(0, 8).Select(index => status with { Channel = $"Test-Only-{index}" }).ToArray();
        Check(SecurityEventContract.IsValidEnvelope(valid with { Sources = eight }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { Sources = [.. eight, status] }),
            "The source cap is not 8.");
        Check(!SecurityEventContract.IsValidEnvelope(valid with { Sources = [status, status] }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { Events = [observation, null!] }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { SentUtc = Start.ToOffset(TimeSpan.FromHours(2)) }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { Format = "sentinelai-security-events-v2" }) &&
              !SecurityEventContract.IsValidEnvelope(valid with { EndpointId = Guid.Empty }) &&
              SecurityEventContract.IsValidEnvelope(valid with { SentUtc = Start.AddYears(5) }),
            "Envelope validation does not match the contract.");

        Check(SecurityEventContract.Classify(observation) == SecurityEventItemValidity.Valid, "A valid observation was rejected.");
        var invalid = new (string Name, SecurityEventObservation Observation)[]
        {
            ("payload mismatch", observation with { Logon = null, ScheduledTask = new ScheduledTaskEvent(null, null) }),
            ("two payloads", observation with { ScheduledTask = new ScheduledTaskEvent(null, null) }),
            ("elevated failure", observation with { Kind = SecurityEventKinds.LogonFailed, EventId = 4625,
                Logon = observation.Logon! with { ElevatedToken = true } }),
            ("success status", observation with { Logon = observation.Logon! with { Status = 1 } }),
            ("bell", observation with { Kind = SecurityEventKinds.ScheduledTaskCreated, EventId = 4698, Logon = null,
                ScheduledTask = new ScheduledTaskEvent("test-only\u0007", null) }),
            ("bidi", observation with { Kind = SecurityEventKinds.ScheduledTaskCreated, EventId = 4698, Logon = null,
                ScheduledTask = new ScheduledTaskEvent("test-only\u202E", null) }),
            ("surrogate", observation with { Kind = SecurityEventKinds.ScheduledTaskCreated, EventId = 4698, Logon = null,
                ScheduledTask = new ScheduledTaskEvent("test-only\uD800", null) }),
            ("unicode digit SID", observation with { Logon = observation.Logon! with { TargetUserSid = "S-1-\u0665-21" } }),
            ("non-canonical IP", observation with { Logon = observation.Logon! with { IpAddress = "192.000.002.010" } }),
            ("offset time", observation with { TimeCreatedUtc = Start.ToOffset(TimeSpan.FromHours(1)) }),
            ("record zero", observation with { RecordId = 0 }),
            ("version", observation with { EventVersion = 256 })
        };
        foreach (var (name, item) in invalid)
            Check(SecurityEventContract.Classify(item) == SecurityEventItemValidity.Invalid, $"The {name} observation was not invalid.");
        var malware = new SecurityEventObservation(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 1116, 0, 3, 1,
            Start, SecurityEventKinds.MalwareDetected, Malware: new MalwareEvent(null, 1, "test-only", 1, 1, null, null));
        Check(SecurityEventContract.Classify(malware) == SecurityEventItemValidity.Valid &&
              SecurityEventContract.Classify(malware with { Malware = malware.Malware! with { ErrorCode = 1 } }) ==
              SecurityEventItemValidity.Invalid, "ErrorCode on a detection was accepted.");
        var script = new SecurityEventObservation(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104, 1, 3, 1,
            Start, SecurityEventKinds.ScriptBlockFlagged, ScriptBlock: new ScriptBlockEvent(null, 1));
        Check(SecurityEventContract.Classify(script) == SecurityEventItemValidity.Valid &&
              SecurityEventContract.Classify(script with { Level = 4 }) == SecurityEventItemValidity.Invalid,
            "A script block below warning level was accepted.");
        Check(SecurityEventContract.Classify(observation with { TimeCreatedUtc = Start.AddDays(2) }) == SecurityEventItemValidity.Valid &&
              SecurityEventContract.Classify(observation with { TimeCreatedUtc = new DateTimeOffset(1971, 1, 1, 0, 0, 0, TimeSpan.Zero) }) ==
              SecurityEventItemValidity.Valid, "Far-future or far-past event times were rejected.");
        var huge = new SecurityEventObservation(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4698, 0, 0, 1,
            Start, SecurityEventKinds.ScheduledTaskCreated,
            ScheduledTask: new ScheduledTaskEvent(new string('\u00e9', 256), null));
        Check(SecurityEventContract.MeasureBytes(huge) < SecurityEventContract.MaxObservationBytes,
            "A maximal task name exceeded the observation bound.");
        Check(SecurityEventContract.Classify(observation with { Channel = "Microsoft-Windows-Sysmon/Operational" }) ==
              SecurityEventItemValidity.Unknown &&
              SecurityEventContract.Classify(status with { State = "paused" }) == SecurityEventItemValidity.Unknown &&
              SecurityEventContract.Classify(gap with { Reason = SecurityEventGapReasons.Rejected }) == SecurityEventItemValidity.Unknown,
            "Unknown items were not classified as unknown.");
        Check(SecurityEventContract.Classify(gap with { Reason = SecurityEventGapReasons.Overwritten, LastRecordId = null }) ==
              SecurityEventItemValidity.Invalid &&
              SecurityEventContract.Classify(gap with { Reason = SecurityEventGapReasons.LogReset, LastRecordId = 9 }) ==
              SecurityEventItemValidity.Invalid &&
              SecurityEventContract.Classify(gap with { Cause = "test-only" }) == SecurityEventItemValidity.Invalid &&
              SecurityEventContract.Classify(gap with { Reason = SecurityEventGapReasons.Dropped, LastRecordId = 1, Cause = null,
                  FirstRecordId = 1 }) == SecurityEventItemValidity.Valid &&
              SecurityEventContract.Classify(gap with { FirstRecordId = 0 }) == SecurityEventItemValidity.Invalid,
            "Gap shape rules were not applied.");
        Check(SecurityEventContract.Classify(status with { Scanned = -1 }) == SecurityEventItemValidity.Invalid,
            "A negative status counter was accepted.");

        // Strict JSON: duplicate keys, nulls, missing required members and string numbers are rejected.
        var json = JsonSerializer.Serialize(valid, SecurityEventContract.Json);
        Check(JsonSerializer.Deserialize<SecurityEventBatch>(json, SecurityEventContract.Json) is { } roundTrip &&
              JsonSerializer.Serialize(roundTrip, SecurityEventContract.Json) == json, "A batch did not round-trip.");
        Check(JsonSerializer.Deserialize<SecurityEventBatch>(json.Replace("\"format\":", "\"unknownMember\":{\"a\":1},\"format\":"),
            SecurityEventContract.Json) is not null, "An unknown member was not skipped.");
        foreach (var (name, mutated) in new[]
                 {
                     ("duplicate key", json.Replace("\"format\":", "\"agentVersion\":\"1\",\"format\":")),
                     ("null member", json.Replace($"\"format\":\"{SecurityEventContract.Format}\"", "\"format\":null")),
                     ("missing member", Regex.Replace(json, "\"agentVersion\":\"[^\"]*\",", "")),
                     ("string number", json.Replace("\"scanned\":0", "\"scanned\":\"0\""))
                 })
        {
            Check(mutated != json, $"The {name} mutation did not apply.");
            try
            {
                JsonSerializer.Deserialize<SecurityEventBatch>(mutated, SecurityEventContract.Json);
                throw new Exception($"Strict JSON accepted a {name}.");
            }
            catch (JsonException)
            {
                assertions++;
            }
        }
    }

    // D6: worst-case observation and request sizes stay inside the bounds.
    private static void VerifySizeBounds()
    {
        var text = new string('\u00e9', 256);
        var sid = "S-1-" + new string('9', 13) + string.Concat(Enumerable.Repeat("-" + new string('9', 10), 15));
        const string ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        Check(SecurityEventContract.IsValidSid(sid) && SecurityEventContract.IsCanonicalIp(ip), "The maximal SID or IP is invalid.");
        var channel = SecurityEventChannels.Defender;
        SecurityEventObservation Envelope(string ch, string provider, int id, string kind) =>
            new(ch, provider, id, 255, 255, long.MaxValue, DateTimeOffset.MaxValue.ToUniversalTime(), kind);
        var maximal = new[]
        {
            Envelope(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4624, SecurityEventKinds.LogonSucceeded)
                with { Logon = new LogonEvent(11, sid, ip, null, null, false) },
            Envelope(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4625, SecurityEventKinds.LogonFailed)
                with { Logon = new LogonEvent(15, sid, ip, 0xFFFFFFFF, 0xFFFFFFFF, null) },
            Envelope(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4698, SecurityEventKinds.ScheduledTaskCreated)
                with { ScheduledTask = new ScheduledTaskEvent(text, sid) },
            Envelope(SecurityEventChannels.System, SecurityEventProviders.Eventlog, 104, SecurityEventKinds.LogCleared)
                with { LogCleared = new LogClearedEvent(text) },
            Envelope(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7045, SecurityEventKinds.ServiceInstalled)
                with { ServiceInstall = new ServiceInstallEvent(text, new string('\u00e9', 128), ServiceImageLocations.ProgramFiles,
                    ServiceTypes.FileSystemDriver, ServiceStartTypes.Disabled, ServiceAccountKinds.NetworkService) },
            Envelope(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7040,
                    SecurityEventKinds.ProtectionServiceStartTypeChanged)
                with { ServiceStartType = new ServiceStartTypeEvent("SecurityHealthService", ServiceStartTypes.Disabled) },
            (Envelope(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104, SecurityEventKinds.ScriptBlockFlagged)
                with { ScriptBlock = new ScriptBlockEvent(Guid.NewGuid(), 10000) }) with { Level = 3 },
            Envelope(channel, SecurityEventProviders.Defender, 1116, SecurityEventKinds.MalwareDetected)
                with { Malware = new MalwareEvent(Guid.NewGuid(), long.MaxValue, text, 255, 255, null, null) },
            Envelope(channel, SecurityEventProviders.Defender, 1117, SecurityEventKinds.MalwareActionTaken)
                with { Malware = new MalwareEvent(Guid.NewGuid(), long.MaxValue, text, 255, 255, 255, null) },
            Envelope(channel, SecurityEventProviders.Defender, 1119, SecurityEventKinds.MalwareActionFailed)
                with { Malware = new MalwareEvent(Guid.NewGuid(), long.MaxValue, text, 255, 255, 255, 0xFFFFFFFF) },
            Envelope(channel, SecurityEventProviders.Defender, 5012, SecurityEventKinds.ProtectionDisabled),
            Envelope(channel, SecurityEventProviders.Defender, 5007, SecurityEventKinds.DefenderSettingChanged)
                with { DefenderSetting = new DefenderSettingEvent(DefenderSettingAreas.ExclusionIpAddress, DefenderSettingChanges.Modified) }
        };
        var sizes = new List<string>();
        foreach (var observation in maximal)
        {
            Check(SecurityEventContract.Classify(observation) == SecurityEventItemValidity.Valid,
                $"The maximal {observation.Kind} observation is not valid.");
            sizes.Add($"{observation.Kind}={SecurityEventContract.MeasureBytes(observation)}");
        }

        var largest = maximal.MaxBy(SecurityEventContract.MeasureBytes)!;
        var largestBytes = SecurityEventContract.MeasureBytes(largest);
        Check(largestBytes < SecurityEventContract.MaxObservationBytes, "A maximal observation exceeds 4 KiB.");
        var events = new List<SecurityEventObservation>();
        var eventBytes = 0;
        while (events.Count < SecurityEventContract.MaxEventsPerBatch &&
               eventBytes + largestBytes <= SecurityEventContract.MaxBatchEventBytes)
        {
            events.Add(largest);
            eventBytes += largestBytes;
        }

        var gap = new SecurityEventGap(SecurityEventChannels.Defender, SecurityEventGapReasons.CoverageStarted, long.MaxValue, null,
            DateTimeOffset.MaxValue.ToUniversalTime(), SecurityEventCoverageCauses.CheckpointInvalid);
        var status = new SecurityEventSourceStatus(SecurityEventChannels.Defender, SecurityEventSourceStates.AccessDenied,
            int.MinValue, long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue, DateTimeOffset.MaxValue.ToUniversalTime(),
            long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue,
            long.MaxValue, long.MaxValue);
        var batch = new SecurityEventBatch(Guid.NewGuid(), SecurityEventContract.Format, new string('9', 64),
            DateTimeOffset.MaxValue.ToUniversalTime(), DateTimeOffset.MaxValue.ToUniversalTime(),
            Enumerable.Range(0, 8).Select(index => status with { Channel = channel + index }).ToArray(),
            Enumerable.Repeat(gap, SecurityEventContract.MaxGapsPerBatch).ToArray(), events);
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(batch, SecurityEventContract.Json).Length;
        Check(SecurityEventContract.IsValidEnvelope(batch) && requestBytes < SecurityEventContract.MaxRequestBytes,
            "A worst-case request exceeds 256 KiB.");
        Console.WriteLine($"Security event size bounds: {string.Join(", ", sizes)}; worst-case request {requestBytes} bytes.");
    }

    // D7: checkpoint persistence and every invalid shape.
    private static async Task VerifyCheckpointStoreAsync(string directory)
    {
        Directory.CreateDirectory(directory);
        var store = new EventCheckpointStore(Options(directory));
        var endpoint = Guid.NewGuid();
        Check((await store.LoadAsync(endpoint)) is { Cause: SecurityEventCoverageCauses.NoCheckpoint, Checkpoints.Count: 0 },
            "A missing checkpoint did not start coverage.");
        var ticks = SyntheticEventLog.TimeOf(0, 9).UtcTicks;
        await store.SaveAsync(endpoint,
        [
            (SecurityEventChannels.Defender, new EventCheckpoint(0, null)),
            (SecurityEventChannels.System, new EventCheckpoint(123456, ticks))
        ]);
        var loaded = await store.LoadAsync(endpoint);
        Check(loaded.Cause == SecurityEventCoverageCauses.NoCheckpoint && loaded.Checkpoints.Count == 2 &&
              loaded.Checkpoints[SecurityEventChannels.System] == new EventCheckpoint(123456, ticks) &&
              loaded.Checkpoints[SecurityEventChannels.Defender] == new EventCheckpoint(0, null),
            "Checkpoints did not round-trip.");
        var text = await File.ReadAllTextAsync(store.StatePath);
        Check(Regex.IsMatch(text, "^[\\x20-\\x7e]*$") && text.Length <= EventCheckpointStore.MaxBytes &&
              text.IndexOf(SecurityEventChannels.System, StringComparison.Ordinal) <
              text.IndexOf(SecurityEventChannels.Defender, StringComparison.Ordinal),
            "The checkpoint file is not printable ASCII in catalog order.");
        Check(!Directory.EnumerateFiles(directory, "*.tmp").Any() && store.Writes == 1, "A checkpoint save left a temporary file.");
        if (!OperatingSystem.IsWindows())
            Check(File.GetUnixFileMode(store.StatePath) == (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                "The checkpoint file is not private.");
        Check((await store.LoadAsync(Guid.NewGuid())) is { Cause: SecurityEventCoverageCauses.EndpointChanged, Checkpoints.Count: 0 },
            "Another endpoint's checkpoint was replayed.");

        async Task Invalid(string name, byte[] content)
        {
            await File.WriteAllBytesAsync(store.StatePath, content);
            Check((await store.LoadAsync(endpoint)) is { Cause: SecurityEventCoverageCauses.CheckpointInvalid, Checkpoints.Count: 0 },
                $"A checkpoint with {name} was accepted.");
        }

        string Document(string channels, string format = EventCheckpointStore.Format, string extra = "") =>
            $"{{\"format\":\"{format}\",\"endpointId\":\"{endpoint:D}\",\"channels\":[{channels}]{extra}}}";
        const string Entry = "{\"channel\":\"System\",\"recordId\":5,\"anchorUtcTicks\":639000000001234567}";
        await Invalid("4097 bytes", Encoding.ASCII.GetBytes(Document(Entry).PadRight(4097)));
        await Invalid("a wrong format", Encoding.ASCII.GetBytes(Document(Entry, "sentinelai-event-checkpoints-v2")));
        await Invalid("an extra property", Encoding.ASCII.GetBytes(Document(Entry, extra: ",\"x\":1")));
        await Invalid("an unknown channel", Encoding.ASCII.GetBytes(Document(Entry.Replace("System", "Application"))));
        await Invalid("a duplicate channel", Encoding.ASCII.GetBytes(Document(Entry + "," + Entry)));
        await Invalid("a duplicate property", Encoding.ASCII.GetBytes(Document(Entry.Replace("{\"channel\"", "{\"recordId\":1,\"channel\""))));
        await Invalid("a negative record", Encoding.ASCII.GetBytes(Document(Entry.Replace("\"recordId\":5", "\"recordId\":-1"))));
        await Invalid("record zero with ticks", Encoding.ASCII.GetBytes(Document(Entry.Replace("\"recordId\":5", "\"recordId\":0"))));
        await Invalid("pre-epoch ticks", Encoding.ASCII.GetBytes(Document(Entry.Replace("639000000001234567", "1"))));
        await Invalid("a fractional record", Encoding.ASCII.GetBytes(Document(Entry.Replace("\"recordId\":5", "\"recordId\":5.5"))));
        await Invalid("bad UTF-8", [.. Encoding.ASCII.GetBytes(Document(Entry))[..^2], 0xC3, 0x28]);
        await Invalid("depth 5", Encoding.ASCII.GetBytes(Document("{\"channel\":\"System\",\"recordId\":5,\"anchorUtcTicks\":[[1]]}")));
        await Invalid("an empty file", []);
        await File.WriteAllBytesAsync(store.StatePath, Encoding.ASCII.GetBytes(Document(Entry)));
        Check((await store.LoadAsync(endpoint)) is { Cause: SecurityEventCoverageCauses.NoCheckpoint } entryLoad &&
              entryLoad.Checkpoints[SecurityEventChannels.System] == new EventCheckpoint(5, 639000000001234567),
            "A hand-written valid checkpoint was rejected.");

        // Orphaned temporary files are swept, bounded, and nothing else is touched.
        var others = new[] { ".event-checkpoints.x.tmpx", "event-checkpoints.tmp", ".enrollment-state.x.tmp" };
        foreach (var name in others) await File.WriteAllTextAsync(Path.Combine(directory, name), "x");
        for (var index = 0; index < 20; index++)
            await File.WriteAllTextAsync(Path.Combine(directory, $".event-checkpoints.{index:D2}.tmp"), "x");
        await store.LoadAsync(endpoint);
        Check(Directory.EnumerateFiles(directory, ".event-checkpoints.*.tmp").Count(path => path.EndsWith(".tmp")) == 4 &&
              others.All(name => File.Exists(Path.Combine(directory, name))),
            "The temporary file sweep was unbounded or touched other files.");

        // A linked checkpoint is never read or written through.
        var target = Path.Combine(directory, "link-target");
        await File.WriteAllBytesAsync(target, Encoding.ASCII.GetBytes(Document(Entry)));
        File.Delete(store.StatePath);
        try
        {
            File.CreateSymbolicLink(store.StatePath, target);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine("Checkpoint link check skipped: symbolic links are unavailable.");
            return;
        }

        Check((await store.LoadAsync(endpoint)).Cause == SecurityEventCoverageCauses.CheckpointInvalid,
            "A linked checkpoint was read.");
        Reject<InvalidOperationException>(() => store.SaveAsync(endpoint, []).GetAwaiter().GetResult(),
            "A checkpoint was written through a link.");
        Check(await File.ReadAllTextAsync(target) == Document(Entry), "The link target was modified.");
    }

    // D8: nothing happens before the Agent is linked.
    private static async Task VerifyDormancyAsync(string directory)
    {
        var rig = Rig.Create(directory, linked: false);
        Seed(rig.Log, 10);
        Check(!await rig.Pipeline.InitializeAsync(CancellationToken.None), "The pipeline initialized while unlinked.");
        for (var step = 0; step < 20; step++) await rig.AdvanceAsync(Poll);
        Check(rig.Log.DescribeCalls == 0 && rig.Log.OpenCalls == 0 && rig.Uploader.Attempts.Count == 0 &&
              !File.Exists(rig.CheckpointPath), "The unlinked pipeline read events or wrote state.");
        Check(!rig.Pipeline.Snapshot.Active, "The unlinked pipeline reported itself active.");
    }

    // D9: first start covers each channel at its tail; history is never delivered.
    private static async Task VerifyFirstStartAsync(string directory)
    {
        var rig = Rig.Create(directory);
        Seed(rig.Log, 100);
        var tails = SecurityEventChannels.All.ToDictionary(channel => channel, channel => rig.Log.Extent(channel).Newest!.Value);
        rig.Uploader.Enqueue(ScriptedUploader.Failed);
        await rig.StepAsync();
        var first = rig.Uploader.Attempts.Single();
        Check(first.Events.Count == 0 && first.Gaps.Count == 4 && first.Gaps.All(gap =>
                  gap.Reason == SecurityEventGapReasons.CoverageStarted && gap.Cause == SecurityEventCoverageCauses.NoCheckpoint &&
                  gap.LastRecordId is null && gap.FirstRecordId == tails[gap.Channel] + 1),
            "First start did not report coverage at each channel's tail.");
        Check(rig.Log.ReadNewestCalls == 4 && rig.Log.OpenCalls == 0 && !File.Exists(rig.CheckpointPath),
            "First start read history or wrote positions before acknowledgement.");

        // A crash before the acknowledgement re-tails at the then-current tail.
        rig.Uploader = new ScriptedUploader();
        rig.Restart();
        foreach (var channel in SecurityEventChannels.All) rig.Log.AppendNoise(channel, 1);
        await rig.StepAsync();
        var resent = rig.Uploader.Attempts.Single();
        Check(resent.Gaps.Count == 4 && resent.Gaps.All(gap => gap.FirstRecordId == tails[gap.Channel] + 2) &&
              rig.Log.ReadNewestCalls == 8 && rig.Store.Writes == 1,
            "A restart before acknowledgement did not re-tail and persist positions once.");
        var saved = await rig.Store.LoadAsync(rig.Enrollment.EndpointId);
        Check(saved.Checkpoints.Count == 4 && SecurityEventChannels.All.All(channel =>
                  saved.Checkpoints[channel] == new EventCheckpoint(tails[channel] + 1,
                      SyntheticEventLog.TimeOf(0, tails[channel] + 1).UtcTicks)),
            "The acknowledged coverage positions or anchors are wrong.");
        for (var step = 0; step < 5; step++) await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.All(batch => batch.Events.Count == 0), "History before coverage was delivered.");
    }

    // D10: steady delivery and the cost of an idle poll.
    private static async Task VerifySteadyDeliveryAsync(string directory)
    {
        var rig = await Rig.CoveredAsync(directory);
        var system = SecurityEventFixtures.For(7045);
        SecurityEventFixtures.Append(rig.Log, system);
        rig.Log.AppendNoise(SecurityEventChannels.System, 2);
        SecurityEventFixtures.Append(rig.Log, system);
        rig.Log.AppendNoise(SecurityEventChannels.System, 1);
        SecurityEventFixtures.Append(rig.Log, system);
        rig.Log.AppendNoise(SecurityEventChannels.System, 2);
        var attempts = rig.Uploader.Attempts.Count;
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == attempts + 1 && rig.Uploader.Attempts[^1].Events.Count == 3,
            "Three selected records were not delivered in one batch.");
        Check(rig.Source(SecurityEventChannels.System).CheckpointRecordId == rig.Log.Extent(SecurityEventChannels.System).Newest,
            "The position did not advance to the newest record seen.");
        var (describe, open, writes) = (rig.Log.DescribeCalls, rig.Log.OpenCalls, rig.Store.Writes);
        await rig.AdvanceAsync(Poll);
        Check(rig.Log.OpenCalls == open && rig.Log.DescribeCalls == describe + 4 && rig.Store.Writes == writes &&
              rig.Uploader.Attempts.Count == attempts + 1, "An idle poll opened a channel, wrote state or sent data.");
    }

    // D11: count and byte caps, with no loss or duplicate across batches.
    private static async Task VerifyCapsAsync(string directory)
    {
        var rig = await Rig.CoveredAsync(Path.Combine(directory, "count"));
        var expected = new HashSet<long>();
        for (var index = 0; index < 600; index++) expected.Add(SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045)));
        var before = rig.Uploader.AcceptedBatches.Count;
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Events.Count == 256, "The first batch was not capped at 256 events.");
        await rig.StepAsync();
        Check(rig.Pipeline.Snapshot.PreparedEvents == 256, "A full batch did not trigger an immediate re-poll.");
        for (var step = 0; step < 10; step++) await rig.AdvanceAsync(TimeSpan.FromSeconds(1));
        var batches = rig.Uploader.AcceptedBatches.Skip(before).Where(batch => batch.Events.Count > 0).ToArray();
        Check(batches.Select(batch => batch.Events.Count).SequenceEqual([256, 256, 88]), "Batches were not 256/256/88.");
        var ids = batches.SelectMany(batch => batch.Events).Select(observation => observation.RecordId).ToArray();
        Check(ids.Length == 600 && ids.ToHashSet().SetEquals(expected), "Batching lost or duplicated records.");

        var bytesRig = await Rig.CoveredAsync(Path.Combine(directory, "bytes"));
        var name = new string('\u00e9', 256);
        for (var index = 0; index < 150; index++)
            SecurityEventFixtures.Append(bytesRig.Log, SecurityEventFixtures.For(1116), new() { ["Threat Name"] = name });
        for (var step = 0; step < 10; step++) await bytesRig.AdvanceAsync(TimeSpan.FromSeconds(2));
        var sized = bytesRig.Uploader.AcceptedBatches.Where(batch => batch.Events.Count > 0).ToArray();
        var size = SecurityEventContract.MeasureBytes(sized[0].Events[0]);
        Check(sized.Length == 2 && sized[0].Events.Count == SecurityEventContract.MaxBatchEventBytes / size &&
              sized[0].Events.Sum(SecurityEventContract.MeasureBytes) <= SecurityEventContract.MaxBatchEventBytes &&
              sized.Sum(batch => batch.Events.Count) == 150, "Large observations did not stop at the byte budget.");
    }

    // D12: nothing is read while a batch is pending; the retry schedule; link loss and return.
    private static async Task VerifyBackpressureAsync(string directory)
    {
        var rig = await Rig.CoveredAsync(directory);
        SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045));
        rig.Uploader.Enqueue(Enumerable.Repeat(ScriptedUploader.Failed, 6).ToArray());
        var attemptsBefore = rig.Uploader.Attempts.Count;
        await rig.AdvanceAsync(Poll);
        var firstAttempt = rig.Time.GetUtcNow();
        var (describe, open) = (rig.Log.DescribeCalls, rig.Log.OpenCalls);
        for (var second = 0; second < 200; second++)
        {
            await rig.AdvanceAsync(TimeSpan.FromSeconds(1));
            if (rig.Uploader.Attempts.Count - attemptsBefore < 7)
                Check(rig.Log.DescribeCalls == describe && rig.Log.OpenCalls == open, "The pipeline read events while a batch was pending.");
        }

        var offsets = rig.Uploader.Attempts.Skip(attemptsBefore).Take(7)
            .Select(batch => (batch.SentUtc - firstAttempt).TotalSeconds).ToArray();
        Check(offsets.SequenceEqual([0d, 5, 15, 35, 75, 135, 195]) &&
              rig.Uploader.Attempts.Skip(attemptsBefore).Take(7).All(batch => batch.Events.Count == 1),
            $"Retry attempts were at {string.Join(",", offsets)} seconds.");
        Check(rig.Source(SecurityEventChannels.System).Delivered == 1, "The batch was not delivered after the failures.");

        SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045));
        rig.Uploader.Enqueue(ScriptedUploader.Failed, ScriptedUploader.Failed);
        await rig.AdvanceAsync(Poll);
        await rig.AdvanceAsync(TimeSpan.FromSeconds(5));
        var attempts = rig.Uploader.Attempts.Count;
        rig.Link.Publish(null);
        for (var step = 0; step < 120; step++) await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == attempts, "The pipeline sent while unlinked.");
        rig.Link.Publish(rig.Enrollment);
        rig.Uploader.Enqueue(ScriptedUploader.Failed);
        await rig.StepAsync();
        var relinked = rig.Time.GetUtcNow();
        Check(rig.Uploader.Attempts.Count == attempts + 1, "The returned link did not trigger an immediate attempt.");
        await rig.AdvanceAsync(TimeSpan.FromSeconds(4));
        Check(rig.Uploader.Attempts.Count == attempts + 1, "The backoff was not reset by the returned link.");
        await rig.AdvanceAsync(TimeSpan.FromSeconds(1));
        Check(rig.Uploader.Attempts.Count == attempts + 2 && rig.Uploader.Attempts[^1].SentUtc - relinked == TimeSpan.FromSeconds(5),
            "The first retry after the link returned was not at the base delay.");
    }

    // D13: incompatibility holds the batch for the long retry.
    private static async Task VerifyIncompatibleAsync(string directory)
    {
        foreach (var status in new[] { 404, 400, 413, 415 })
        {
            var logs = new CapturingEventLoggerProvider();
            var rig = await Rig.CoveredAsync(Path.Combine(directory, status.ToString()), logs: logs);
            var position = rig.Source(SecurityEventChannels.System).CheckpointRecordId;
            SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045));
            rig.Uploader.Enqueue(ScriptedUploader.Incompatible(status), ScriptedUploader.Incompatible(status));
            var attempts = rig.Uploader.Attempts.Count;
            await rig.AdvanceAsync(Poll);
            for (var minute = 1; minute < 15; minute++) await rig.AdvanceAsync(TimeSpan.FromMinutes(1));
            await rig.AdvanceAsync(TimeSpan.FromSeconds(59));
            Check(rig.Uploader.Attempts.Count == attempts + 1 && rig.Pipeline.Snapshot.PreparedEvents == 1 &&
                  rig.Source(SecurityEventChannels.System).CheckpointRecordId == position,
                $"HTTP {status} did not hold the batch without moving positions.");
            await rig.AdvanceAsync(TimeSpan.FromSeconds(1));
            await rig.AdvanceAsync(TimeSpan.FromMinutes(15));
            Check(rig.Uploader.Attempts.Count == attempts + 3 && rig.Source(SecurityEventChannels.System).Delivered == 1,
                $"HTTP {status} retries were not exactly 15 minutes apart or the batch was not delivered afterwards.");
            Check(logs.Count(LogLevel.Warning, "does not accept") == 1, $"HTTP {status} was not warned once per transition.");
        }
    }

    // D14: overwrite, reset, clear, markers, seek fallbacks, races and crash consistency.
    private static async Task VerifyContinuityAsync(string directory)
    {
        var service = SecurityEventFixtures.For(7045);
        const string System = SecurityEventChannels.System;

        // (a) Overwrite after position 50: exactly [51, 80], then resume at the oldest record.
        var rig = await Rig.CoveredAsync(Path.Combine(directory, "a"), logs: PrivacyLogs);
        AppendMany(rig.Log, service, 50);
        await rig.AdvanceAsync(Poll);
        AppendMany(rig.Log, service, 50);
        rig.Log.Trim(System, 80);
        await rig.AdvanceAsync(Poll);
        var overwritten = rig.Uploader.AcceptedBatches[^1];
        Check(overwritten.Gaps.SingleOrDefault() is { Reason: SecurityEventGapReasons.Overwritten, FirstRecordId: 51, LastRecordId: 80 } &&
              overwritten.Events.Select(o => o.RecordId).SequenceEqual(Range(81, 100)) &&
              rig.Source(System) is { SkippedRecords: 30, Gaps: 2, CheckpointRecordId: 100 },
            "An overwrite was not reported exactly.");

        // (b) A shrunk log is a reset; the new generation is delivered from record 1.
        rig.Log.Clear(System, restartIds: true);
        AppendMany(rig.Log, service, 10);
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is
                  { Reason: SecurityEventGapReasons.LogReset, FirstRecordId: 101, LastRecordId: null },
            "A shrunk log was not reported as a reset.");
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Events.Select(o => (o.RecordId, o.TimeCreatedUtc))
                  .SequenceEqual(Range(1, 10).Select(id => (id, SyntheticEventLog.TimeOf(1, id)))),
            "The new generation was not delivered from record 1.");

        // (c) An emptied log is a reset.
        rig.Log.Clear(System, restartIds: true);
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is { Reason: SecurityEventGapReasons.LogReset, FirstRecordId: 11 } &&
              rig.Source(System).CheckpointRecordId == 0, "An emptied log was not reported as a reset.");

        // A generation start with its first records already overwritten reports them.
        AppendMany(rig.Log, service, 30);
        rig.Log.Trim(System, 12);
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is
                  { Reason: SecurityEventGapReasons.Overwritten, FirstRecordId: 1, LastRecordId: 12 } &&
              rig.Uploader.AcceptedBatches[^1].Events.Count == 18, "Records overwritten before a generation was read were not reported.");

        // (d) Cleared while stopped and regrown past the position: the anchor time differs.
        rig = await Rig.CoveredAsync(Path.Combine(directory, "d"), logs: PrivacyLogs);
        AppendMany(rig.Log, service, 20);
        await rig.AdvanceAsync(Poll);
        await rig.Pipeline.FlushAsync(CancellationToken.None);
        rig.Log.Clear(System, restartIds: true);
        var cleared = SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(104));
        AppendMany(rig.Log, service, 29);
        rig.Restart();
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is { Reason: SecurityEventGapReasons.LogReset, FirstRecordId: 21 },
            "A clear regrown past the position was not detected by the anchor time.");
        await rig.AdvanceAsync(Poll);
        var regrown = rig.Uploader.AcceptedBatches[^1].Events;
        Check(cleared == 1 && regrown.Count == 30 && regrown[0] is { RecordId: 1, Kind: SecurityEventKinds.LogCleared } &&
              regrown[0].LogCleared == new LogClearedEvent("Application"), "The regrown generation was not fully delivered.");

        // (e) A below-oldest marker contradicted by the oldest record is a reset.
        var markerDirectory = Path.Combine(directory, "e");
        var markerRig = Rig.Create(markerDirectory);
        await markerRig.Store.SaveAsync(markerRig.Enrollment.EndpointId,
            SecurityEventChannels.All.Select(channel => (channel, new EventCheckpoint(channel == System ? 50 : 0, null))).ToArray());
        AppendMany(markerRig.Log, service, 60);
        await markerRig.StepAsync();
        Check(markerRig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is { Reason: SecurityEventGapReasons.LogReset, FirstRecordId: 51 },
            "A contradicted below-oldest marker was not reported as a reset.");

        // (f) and (g): a seek that misses the anchor, and a failing bookmark seek, both fall back exactly.
        foreach (var mode in new[] { "f", "g" })
        {
            rig = await Rig.CoveredAsync(Path.Combine(directory, mode), logs: PrivacyLogs);
            AppendMany(rig.Log, service, 10);
            await rig.AdvanceAsync(Poll);
            AppendMany(rig.Log, service, 5);
            if (mode == "f") rig.Log.DropAnchorOnce(System);
            else rig.Log.FailBookmarkSeek(System, true);
            await rig.AdvanceAsync(Poll);
            Check(rig.Uploader.AcceptedBatches[^1].Events.Select(o => o.RecordId).SequenceEqual(Range(11, 15)) &&
                  rig.Uploader.AcceptedBatches[^1].Gaps.Count == 0 && rig.Source(System).SeekFallbacks == 1,
                $"Seek fallback mode {mode} did not deliver exactly the new records.");
        }

        // (h) The anchor is overwritten between Describe and Open.
        rig = await Rig.CoveredAsync(Path.Combine(directory, "h"), logs: PrivacyLogs);
        AppendMany(rig.Log, service, 50);
        await rig.AdvanceAsync(Poll);
        AppendMany(rig.Log, service, 50);
        rig.Log.BeforeOpen = channel =>
        {
            rig.Log.BeforeOpen = null;
            rig.Log.Trim(channel, 70);
        };
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.AcceptedBatches[^1].Gaps.SingleOrDefault() is
                  { Reason: SecurityEventGapReasons.Overwritten, FirstRecordId: 51, LastRecordId: 70 } &&
              rig.Uploader.AcceptedBatches[^1].Events.Select(o => o.RecordId).SequenceEqual(Range(71, 100)) &&
              rig.Source(System).SeekFallbacks == 1, "A Describe-to-Open race was not resolved into an exact gap.");

        // (i) Crash consistency: a gap whose acknowledgement was lost is re-detected with the same key.
        var sink = new FakeCoreSink();
        rig = await Rig.CoveredAsync(Path.Combine(directory, "i"), sink, PrivacyLogs);
        AppendMany(rig.Log, service, 50);
        await rig.AdvanceAsync(Poll);
        AppendMany(rig.Log, service, 50);
        rig.Log.Trim(System, 80);
        sink.LoseNextAcknowledgements = 1;
        await rig.AdvanceAsync(Poll);
        rig.Restart();
        rig.Log.Trim(System, 90);
        await rig.AdvanceAsync(Poll);
        var key = (System, SecurityEventGapReasons.Overwritten, 51L);
        Check(sink.Gaps.Count(entry => entry.Key.Reason == SecurityEventGapReasons.Overwritten) == 1 &&
              sink.Gaps[key].LastRecordId == 90 && sink.Duplicates == 10 &&
              Range(51, 100).Count(id => sink.Rows.Keys.Any(row => row.Channel == System && row.RecordId == id)) == 20,
            "A re-detected gap was not merged into one row after a lost acknowledgement.");
    }

    // D15: per-channel degradation never stops other channels or escapes the step.
    private static async Task VerifyAvailabilityAsync(string directory)
    {
        const int AccessDenied = unchecked((int)0x80070005);
        const int NotFound = unchecked((int)0x80073A9F);
        var rig = Rig.Create(directory, logs: PrivacyLogs);
        Seed(rig.Log, 5);
        rig.Log.SetUnavailable(SecurityEventChannels.Security, SecurityEventSourceStates.AccessDenied, AccessDenied);
        rig.Log.SetUnavailable(SecurityEventChannels.Defender, SecurityEventSourceStates.NotFound, NotFound);
        await rig.StepAsync();
        await rig.AdvanceAsync(TimeSpan.FromSeconds(2));
        var sources = rig.Pipeline.Snapshot.Sources.ToDictionary(source => source.Channel);
        Check(sources[SecurityEventChannels.Security] is { State: SecurityEventSourceStates.AccessDenied, LastErrorCode: AccessDenied, CheckpointRecordId: null } &&
              sources[SecurityEventChannels.Defender] is { State: SecurityEventSourceStates.NotFound, LastErrorCode: NotFound } &&
              sources[SecurityEventChannels.System] is { State: SecurityEventSourceStates.Collecting, CheckpointRecordId: not null },
            "Unavailable channels were not reported with their HResults.");
        Check(rig.Uploader.AcceptedBatches.Last().Sources.Any(source => source.State == SecurityEventSourceStates.AccessDenied),
            "Channel states were not delivered to Core.");

        SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(4104));
        rig.Log.ThrowOnOpen(SecurityEventChannels.PowerShell, new InvalidOperationException(SecurityEventFixtures.Marker));
        SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045));
        var securityDescribes = rig.Log.DescribeCallsFor(SecurityEventChannels.Security);
        var powerShellDescribes = rig.Log.DescribeCallsFor(SecurityEventChannels.PowerShell);
        await rig.AdvanceAsync(TimeSpan.FromSeconds(3));
        Check(rig.Source(SecurityEventChannels.PowerShell) is { State: SecurityEventSourceStates.Error } powerShell &&
              powerShell.LastErrorCode == new InvalidOperationException().HResult &&
              rig.Source(SecurityEventChannels.System).Delivered == 1, "A failing channel stopped another channel.");
        rig.Log.ThrowOnOpen(SecurityEventChannels.PowerShell, new OperationCanceledException(SecurityEventFixtures.Marker));
        for (var poll = 1; poll <= 24; poll++) await rig.AdvanceAsync(Poll);
        Check(rig.Log.DescribeCallsFor(SecurityEventChannels.Security) - securityDescribes == 2 &&
              rig.Log.DescribeCallsFor(SecurityEventChannels.PowerShell) - powerShellDescribes == 3,
            "Unavailable channels were not retried exactly every 12 polls.");
        Check(rig.Source(SecurityEventChannels.PowerShell).LastErrorCode == new OperationCanceledException().HResult,
            "A non-stopping cancellation was not reported as a channel error.");

        rig.Log.ThrowOnOpen(SecurityEventChannels.PowerShell, null);
        var preGrant = SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(4625));
        rig.Log.SetUnavailable(SecurityEventChannels.Security, null);
        for (var poll = 0; poll < 13; poll++) await rig.AdvanceAsync(Poll);
        var coverage = rig.Uploader.AcceptedBatches.SelectMany(batch => batch.Gaps)
            .SingleOrDefault(gap => gap.Channel == SecurityEventChannels.Security);
        Check(rig.Source(SecurityEventChannels.Security).State == SecurityEventSourceStates.Collecting &&
              coverage is { Reason: SecurityEventGapReasons.CoverageStarted, Cause: SecurityEventCoverageCauses.NoCheckpoint } &&
              coverage.FirstRecordId == preGrant + 1 &&
              rig.Source(SecurityEventChannels.PowerShell) is { State: SecurityEventSourceStates.Collecting, Delivered: 1 },
            "A granted channel did not start coverage at its tail or a recovered channel did not deliver.");
        var postGrant = SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(4625));
        await rig.AdvanceAsync(Poll);
        var delivered = rig.Uploader.AcceptedBatches.SelectMany(batch => batch.Events)
            .Where(o => o.Channel == SecurityEventChannels.Security).Select(o => o.RecordId).ToArray();
        Check(delivered.SequenceEqual([postGrant]), "Records written before a grant were delivered.");
    }

    // D16: status-only reports on change, counter changes at most every 5 minutes, liveness hourly.
    private static async Task VerifyStatusCadenceAsync(string directory)
    {
        var rig = Rig.Create(directory);
        Seed(rig.Log, 5);
        await rig.Store.SaveAsync(rig.Enrollment.EndpointId, SecurityEventChannels.All
            .Select(channel => (channel, new EventCheckpoint(5, SyntheticEventLog.TimeOf(0, 5).UtcTicks))).ToArray());
        var start = rig.Time.GetUtcNow();
        await rig.StepAsync();
        Check(rig.Uploader.Attempts.Count == 1 && rig.Uploader.Attempts[0] is { Events.Count: 0, Gaps.Count: 0, Sources.Count: 4 },
            "The first status was not reported immediately.");
        while (rig.Time.GetUtcNow() - start < TimeSpan.FromMinutes(60)) await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == 2 && rig.Uploader.Attempts[1].SentUtc - start == TimeSpan.FromMinutes(60),
            "An unchanged status was not reported exactly hourly.");

        await rig.AdvanceAsync(TimeSpan.FromMinutes(1));
        rig.Log.AppendNoise(SecurityEventChannels.System, 1);
        while (rig.Time.GetUtcNow() - start < TimeSpan.FromMinutes(65) - Poll) await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == 2, "A counter change was reported before 5 minutes.");
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == 3 && rig.Uploader.Attempts[2].SentUtc - start == TimeSpan.FromMinutes(65),
            "A counter change was not reported at 5 minutes.");

        await rig.AdvanceAsync(TimeSpan.FromSeconds(30));
        rig.Log.SetUnavailable(SecurityEventChannels.Defender, SecurityEventSourceStates.NotFound, 2);
        await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Count == 4 && rig.Uploader.Attempts[3].Sources
                  .Single(source => source.Channel == SecurityEventChannels.Defender).State == SecurityEventSourceStates.NotFound,
            "A state change was not reported at the next delivery slot.");

        SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(7045));
        rig.Uploader.Enqueue(ScriptedUploader.Failed, ScriptedUploader.Failed, ScriptedUploader.Failed);
        var pending = rig.Uploader.Attempts.Count;
        for (var step = 0; step < 30; step++) await rig.AdvanceAsync(Poll);
        Check(rig.Uploader.Attempts.Skip(pending).Take(4).All(batch => batch.Events.Count == 1) &&
              rig.Source(SecurityEventChannels.System).Delivered == 1, "A status-only report was sent while a batch was prepared.");
    }

    // D17: scan caps bound each poll, channels rotate, and scan-only progress persists lazily.
    private static async Task VerifyScanCapsAsync(string directory)
    {
        var rig = await Rig.CoveredAsync(directory);
        var logon = SecurityEventFixtures.For(4624);
        for (var index = 0; index < 5000; index++) SecurityEventFixtures.Append(rig.Log, logon, new() { ["LogonType"] = 3 });
        var selected = SecurityEventFixtures.Append(rig.Log, logon);
        var defender = SecurityEventFixtures.Append(rig.Log, SecurityEventFixtures.For(1116));
        var writes = rig.Store.Writes;
        var batches = rig.Uploader.AcceptedBatches.Count;
        await rig.AdvanceAsync(Poll);
        var deliveredAt = 0;
        for (var poll = 1; poll <= 5; poll++)
        {
            var before = rig.Pipeline.Snapshot.Sources.ToDictionary(source => source.Channel, source => source.Scanned);
            var polls = rig.Pipeline.Snapshot.Polls;
            if (poll > 1) await rig.AdvanceAsync(TimeSpan.FromSeconds(1));
            var after = rig.Pipeline.Snapshot.Sources.ToDictionary(source => source.Channel, source => source.Scanned);
            if (poll > 1) Check(rig.Pipeline.Snapshot.Polls == polls + 1, "A backlog did not re-poll after one second.");
            Check(after[SecurityEventChannels.Security] - (poll == 1 ? 0 : before[SecurityEventChannels.Security]) <= 1024 &&
                  after.Sum(entry => entry.Value) - (poll == 1 ? 0 : before.Sum(entry => entry.Value)) <= 2048,
                "A poll exceeded the scan caps.");
            if (deliveredAt == 0 && rig.Uploader.AcceptedBatches.SelectMany(batch => batch.Events)
                    .Any(o => o.Channel == SecurityEventChannels.Security && o.RecordId == selected))
                deliveredAt = poll;
            if (poll is > 1 and < 5) Check(rig.Store.Writes == writes + 1, "Scan-only progress was written more than once per 5 minutes.");
        }

        var first = rig.Uploader.AcceptedBatches.Skip(batches).First(batch => batch.Events.Count > 0);
        Check(first.Events.Any(o => o.Channel == SecurityEventChannels.Defender && o.RecordId == defender),
            "Another channel's event waited behind a scan backlog.");
        Check(deliveredAt == 5, $"The selected record behind 5,000 rejected records was delivered at poll {deliveredAt}.");
        Check(rig.Source(SecurityEventChannels.Security).CheckpointRecordId == selected, "Scan-only progress was not applied.");
    }

    // D18: corrupt and foreign checkpoints restart coverage visibly and are rewritten valid.
    private static async Task VerifyCorruptCheckpointAsync(string directory)
    {
        var logs = new CapturingEventLoggerProvider();
        var rig = Rig.Create(Path.Combine(directory, "corrupt"), logs: logs);
        Seed(rig.Log, 5);
        Directory.CreateDirectory(rig.Directory);
        await File.WriteAllTextAsync(rig.CheckpointPath, "{\"format\":garbage");
        await rig.StepAsync();
        Check(logs.Count(LogLevel.Warning, "invalid") >= 1 &&
              rig.Uploader.Attempts[0].Gaps.Count(gap => gap.Cause == SecurityEventCoverageCauses.CheckpointInvalid) == 4,
            "A corrupt checkpoint did not restart coverage with a warning.");
        var rewritten = await rig.Store.LoadAsync(rig.Enrollment.EndpointId);
        Check(rewritten is { Cause: SecurityEventCoverageCauses.NoCheckpoint, Checkpoints.Count: 4 },
            "The checkpoint was not rewritten valid after acknowledgement.");

        var foreign = Rig.Create(Path.Combine(directory, "foreign"));
        Seed(foreign.Log, 5);
        await new EventCheckpointStore(foreign.Options).SaveAsync(Guid.NewGuid(),
            [(SecurityEventChannels.System, new EventCheckpoint(1, SyntheticEventLog.TimeOf(0, 1).UtcTicks))]);
        await foreign.StepAsync();
        Check(foreign.Uploader.Attempts[0].Gaps.Count(gap => gap.Cause == SecurityEventCoverageCauses.EndpointChanged) == 4,
            "A foreign endpoint's checkpoint was not reported as endpointChanged.");
    }

    // D19: no marker, field value or exception message reaches the logs; types and HResults do.
    private static void VerifyLogPrivacy()
    {
        var text = PrivacyLogs.Text;
        Check(text.Length > 0 && !text.Contains(SecurityEventFixtures.Marker, StringComparison.Ordinal) &&
              !text.Contains(SecurityEventFixtures.UserSid, StringComparison.Ordinal) &&
              !text.Contains("test-only-service", StringComparison.Ordinal) &&
              !text.Contains(SecurityEventFixtures.RemoteIp, StringComparison.Ordinal),
            "Security event logs contained an event value or exception message.");
        Check(text.Contains(nameof(InvalidOperationException), StringComparison.Ordinal) &&
              text.Contains("0x80131509", StringComparison.Ordinal) &&
              text.Contains(nameof(OperationCanceledException), StringComparison.Ordinal),
            "Security event logs did not identify failures by type and HResult.");
    }

    // D20: HTTP status classification, bounded result parsing and request shape.
    private static async Task VerifyUploaderAsync(string root)
    {
        var options = Options(root);
        var enrollment = Enrollment(Guid.NewGuid());
        var batch = SampleBatch(enrollment.EndpointId);
        async Task<UploadOutcome> Send(StubHttpHandler handler, CancellationToken token = default) =>
            await new HttpSecurityEventUploader(new HttpClient(handler), options).SendAsync(batch, enrollment, token);

        var ok = StubHttpHandler.Status(HttpStatusCode.OK, "{\"accepted\":1,\"duplicates\":2,\"ignored\":3,\"rejected\":4}");
        Check(await Send(ok) == new UploadOutcome(UploadResult.Accepted, 200, new SecurityEventBatchResult(1, 2, 3, 4)),
            "A 200 response was not accepted with counts.");
        Check(ok.LastMethod == HttpMethod.Post && ok.LastPath == "/api/agent/security-events" &&
              ok.LastAuthorization == $"SentinelAgent {enrollment.EndpointId:D}.{enrollment.AgentCredential}" &&
              ok.LastMediaType == "application/json" &&
              JsonSerializer.Deserialize<SecurityEventBatch>(ok.LastBody!, SecurityEventContract.Json) is { } sent &&
              JsonSerializer.Serialize(sent, SecurityEventContract.Json) == JsonSerializer.Serialize(batch, SecurityEventContract.Json),
            "The security event request shape is wrong.");
        Check(await Send(StubHttpHandler.Status(HttpStatusCode.OK, "not json")) == new UploadOutcome(UploadResult.Accepted, 200, null) &&
              await Send(StubHttpHandler.Status(HttpStatusCode.OK,
                  "{\"accepted\":1,\"duplicates\":0,\"ignored\":0,\"rejected\":0," + new string(' ', 5000) + "}")) ==
              new UploadOutcome(UploadResult.Accepted, 200, null) &&
              await Send(StubHttpHandler.Status(HttpStatusCode.NoContent)) == new UploadOutcome(UploadResult.Accepted, 204, null),
            "A committed response with an unusable body was not accepted.");
        foreach (var status in new[] { 400, 404, 405, 413, 415 })
            Check(await Send(StubHttpHandler.Status((HttpStatusCode)status)) == new UploadOutcome(UploadResult.Incompatible, status, null),
                $"HTTP {status} was not classified as incompatible.");
        foreach (var status in new[] { 401, 403, 408, 429, 500, 503 })
            Check(await Send(StubHttpHandler.Status((HttpStatusCode)status)) == new UploadOutcome(UploadResult.Failed, status, null),
                $"HTTP {status} was not classified as a transient failure.");
        foreach (var failure in new Exception[]
                 {
                     new HttpRequestException(SecurityEventFixtures.Marker), new TaskCanceledException("timeout"),
                     new IOException(SecurityEventFixtures.Marker)
                 })
            Check(await Send(new StubHttpHandler((_, _) => Task.FromException<HttpResponseMessage>(failure))) ==
                  new UploadOutcome(UploadResult.Failed, null, null), $"{failure.GetType().Name} was not a transient failure.");
        using var stopping = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        try
        {
            await Send(new StubHttpHandler(async (_, token) =>
            {
                await Task.Delay(Timeout.Infinite, token);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }), stopping.Token);
            throw new Exception("Stopping did not cancel the upload.");
        }
        catch (OperationCanceledException)
        {
            assertions++;
        }
    }

    // D21: the link signals only when it appears, disappears or changes endpoint.
    private static async Task VerifyAgentLinkAsync()
    {
        var link = new AgentLink();
        var enrollment = Enrollment(Guid.NewGuid());
        var initial = link.Changed;
        link.Publish(null);
        Check(!initial.IsCompleted && link.Current is null, "Publishing no link signalled a change.");
        var waiter = Task.Run(async () => await initial);
        link.Publish(enrollment);
        await waiter.WaitAsync(TimeSpan.FromSeconds(5));
        Check(link.Current == enrollment, "A waiter captured before publishing did not wake.");
        var same = link.Changed;
        link.Publish(enrollment with { AgentCredential = new string('b', 64) });
        Check(!same.IsCompleted && link.Current!.AgentCredential == new string('b', 64),
            "Republishing the same endpoint signalled a change.");
        link.Publish(null);
        Check(same.IsCompleted && link.Current is null, "Losing the link did not signal once.");
        var relink = link.Changed;
        link.Publish(enrollment);
        var other = link.Changed;
        link.Publish(Enrollment(Guid.NewGuid()));
        Check(relink.IsCompleted && other.IsCompleted, "A new or different endpoint did not signal.");
        for (var index = 0; index < 100; index++) link.Publish(index % 3 == 0 ? null : enrollment);
        assertions++;
    }

    // D22: random interleavings never lose or duplicate a selected record without a gap covering it.
    private static async Task VerifyInvariantAsync(string directory)
    {
        foreach (var seed in new[] { 27, 1027, 2027 }) await RunInvariantAsync(Path.Combine(directory, seed.ToString()), seed, 1500);
    }

    private static async Task RunInvariantAsync(string directory, int seed, int operations)
    {
        var random = new Random(seed);
        var sink = new FakeCoreSink();
        var rig = Rig.Create(directory, sink);
        var all = new List<Generated>();
        var clearedAt = SecurityEventChannels.All.ToDictionary(channel => channel, _ => new List<DateTimeOffset>());
        var pendingClear = new Dictionary<string, (DateTimeOffset At, long FirstId, bool Restart)>();
        byte[]? savedCheckpoint = null;

        void Append(string channel, SecurityEventFixtures.Fixture? fixture, Dictionary<string, object?>? overrides, bool selected)
        {
            var created = rig.Time.GetUtcNow();
            long id;
            if (fixture is null)
            {
                rig.Log.AppendNoise(channel, 1);
                id = rig.Log.Extent(channel).Newest!.Value;
            }
            else
            {
                id = SecurityEventFixtures.Append(rig.Log, fixture, overrides);
            }

            all.Add(new Generated(channel, rig.Log.Generation(channel), id, created, selected ? fixture : null));
        }

        SecurityEventFixtures.Fixture RandomFixture() =>
            SecurityEventFixtures.Positive[random.Next(SecurityEventFixtures.Positive.Count)];

        foreach (var fixture in SecurityEventFixtures.Positive) Append(fixture.Channel, fixture, null, true);
        for (var operation = 0; operation < operations; operation++)
        {
            rig.Time.Advance(TimeSpan.FromMilliseconds(1));
            foreach (var (channel, clear) in pendingClear.ToArray())
            {
                // A clear is observed once Core holds a reset or coverage start detected after it, or the
                // position moved into the new generation.
                if (sink.ReceivedGaps.Any(gap => gap.Channel == channel && gap.DetectedUtc > clear.At &&
                                                 gap.Reason is SecurityEventGapReasons.LogReset or SecurityEventGapReasons.CoverageStarted) ||
                    !clear.Restart && rig.Source(channel).CheckpointRecordId >= clear.FirstId)
                    pendingClear.Remove(channel);
            }

            var channelPick = SecurityEventChannels.All[random.Next(4)];
            var roll = random.Next(100);
            if (roll < 25)
            {
                var fixture = RandomFixture();
                Append(fixture.Channel, fixture, null, true);
            }
            else if (roll < 33)
            {
                Append(channelPick, null, null, false);
            }
            else if (roll < 38)
            {
                var (fixture, overrides) = random.Next(3) switch
                {
                    0 => (SecurityEventFixtures.For(4624), new Dictionary<string, object?> { ["LogonType"] = 3 }),
                    1 => (SecurityEventFixtures.For(4104), new Dictionary<string, object?> { ["MessageNumber"] = 2 }),
                    _ => (SecurityEventFixtures.For(7040), new Dictionary<string, object?> { ["param4"] = "BITS" })
                };
                Append(fixture.Channel, fixture, overrides, false);
            }
            else if (roll < 41)
            {
                // Overwrite never empties a log; a cleared channel is not overwritten until the clear is observed.
                var (oldest, newest) = rig.Log.Extent(channelPick);
                if (!pendingClear.ContainsKey(channelPick) && oldest is { } low && newest is { } high && high > low)
                    rig.Log.Trim(channelPick, low + random.NextInt64(high - low));
            }
            else if (roll < 43)
            {
                // Clear only a channel read through its newest record, so the reset is detectable by the anchor.
                var snapshot = rig.Pipeline.Snapshot;
                if (!pendingClear.ContainsKey(channelPick) && snapshot.PreparedEvents + snapshot.PreparedGaps == 0 &&
                    rig.Source(channelPick).CheckpointRecordId is > 0 and var position &&
                    position == rig.Log.Extent(channelPick).Newest)
                {
                    var restart = random.Next(2) == 0;
                    var firstId = rig.Log.Extent(channelPick).Newest!.Value + 1;
                    rig.Log.Clear(channelPick, restart);
                    clearedAt[channelPick].Add(rig.Time.GetUtcNow());
                    pendingClear[channelPick] = (rig.Time.GetUtcNow(), restart ? 1 : firstId, restart);
                }
            }
            else if (roll < 46)
            {
                sink.FailNext += random.Next(1, 4);
            }
            else if (roll < 47)
            {
                sink.IncompatibleNext = 1;
            }
            else if (roll < 49)
            {
                sink.LoseNextAcknowledgements = 1;
            }
            else if (roll < 51)
            {
                await rig.Pipeline.FlushAsync(CancellationToken.None);
                rig.Restart();
            }
            else if (roll < 53)
            {
                if (random.Next(2) == 0 && savedCheckpoint is not null) await File.WriteAllBytesAsync(rig.CheckpointPath, savedCheckpoint);
                else File.Delete(rig.CheckpointPath);
                rig.Restart();
            }
            else if (roll < 55)
            {
                if (File.Exists(rig.CheckpointPath)) savedCheckpoint = await File.ReadAllBytesAsync(rig.CheckpointPath);
            }
            else
            {
                rig.Time.Advance(TimeSpan.FromMilliseconds(random.Next(0, 20_000)));
                await rig.StepAsync();
            }
        }

        // Quiesce: Core healthy, everything read and acknowledged.
        sink.FailNext = sink.IncompatibleNext = sink.LoseNextAcknowledgements = 0;
        var quiet = 0;
        for (var step = 0; step < 500 && quiet < 3; step++)
        {
            await rig.AdvanceAsync(TimeSpan.FromMinutes(1));
            var snapshot = rig.Pipeline.Snapshot;
            quiet = snapshot.PreparedEvents + snapshot.PreparedGaps == 0 && SecurityEventChannels.All.All(channel =>
                rig.Source(channel).CheckpointRecordId == (rig.Log.Extent(channel).Newest ?? 0)) ? quiet + 1 : 0;
        }

        Check(quiet == 3, $"Seed {seed} did not quiesce.");
        var byKey = all.ToDictionary(record => (record.Channel, SyntheticEventLog.TimeOf(record.Generation, record.Id).UtcTicks));
        foreach (var ((channel, recordId, ticks), row) in sink.Rows)
        {
            Check(byKey.TryGetValue((channel, ticks), out var generated) && generated.Id == recordId && generated.Fixture is not null,
                $"Seed {seed}: Core holds a row that was never generated as a selected record.");
            var expected = SecurityEventNormalizer.Normalize(Definition(generated!.Fixture!), Header(generated.Fixture!, recordId)
                with { TimeCreatedUtc = SyntheticEventLog.TimeOf(generated.Generation, recordId) },
                Render(Definition(generated.Fixture!).Predicate, generated.Fixture!.Fields),
                Render(Definition(generated.Fixture!).Fields, generated.Fixture!.Fields)).Observation;
            Check(expected == row, $"Seed {seed}: a stored row differs from its generated record.");
        }

        var uncovered = 0;
        foreach (var record in all.Where(record => record.Fixture is not null))
        {
            var ticks = SyntheticEventLog.TimeOf(record.Generation, record.Id).UtcTicks;
            if (sink.Rows.ContainsKey((record.Channel, record.Id, ticks))) continue;
            var covered = sink.ReceivedGaps.Any(gap => gap.Channel == record.Channel && gap.DetectedUtc > record.Created && gap.Reason switch
            {
                SecurityEventGapReasons.Overwritten or SecurityEventGapReasons.Dropped =>
                    gap.FirstRecordId <= record.Id && record.Id <= gap.LastRecordId &&
                    all.Where(other => other.Channel == record.Channel && other.Id == record.Id && other.Created < gap.DetectedUtc)
                        .MaxBy(other => other.Created) == record,
                SecurityEventGapReasons.LogReset =>
                    gap.FirstRecordId <= record.Id && clearedAt[record.Channel].Count > record.Generation &&
                    clearedAt[record.Channel][record.Generation] < gap.DetectedUtc,
                SecurityEventGapReasons.CoverageStarted =>
                    record.Generation < GenerationAt(clearedAt[record.Channel], gap.DetectedUtc) || record.Id < gap.FirstRecordId,
                _ => false
            });
            if (!covered) uncovered++;
        }

        Check(uncovered == 0, $"Seed {seed}: {uncovered} selected records were neither delivered nor covered by a gap.");
        Check(sink.Rejected == 0 && sink.Rows.Count > 100, $"Seed {seed}: Core rejected items or too few rows were delivered.");
        Console.WriteLine($"Security event invariant seed {seed}: {sink.Rows.Count} rows, {sink.Gaps.Count} gap rows, " +
                          $"{sink.Duplicates} duplicates absorbed, {sink.Attempts} attempts.");

        static int GenerationAt(List<DateTimeOffset> clears, DateTimeOffset at) => clears.Count(clear => clear < at);
    }

    // D23: the event code never calls rendering or log-changing APIs.
    private static void VerifyForbiddenApis()
    {
        var agent = Path.Combine(RepositoryRoot(), "agent");
        var files = new[] { "EventLogAccess.cs", "WindowsEventLogAccess.cs", "EventCheckpointStore.cs", "AgentLink.cs" }
            .Select(name => Path.Combine(agent, name))
            .Concat(Directory.EnumerateFiles(agent, "SecurityEvent*.cs")).ToArray();
        Check(files.Length >= 8, "The forbidden API scan found too few files.");
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            foreach (var forbidden in new[] { "ToXml(", "FormatDescription(", ".Properties", "DisplayName", "ClearLog(", "SaveChanges(", "EventLogWatcher" })
                Check(!text.Contains(forbidden, StringComparison.Ordinal), $"{Path.GetFileName(file)} uses {forbidden}.");
        }
    }

    // N1: read-only native conformance; no event content is read.
    [SupportedOSPlatform("windows")]
    private static void VerifyNativeConformance()
    {
        var catalog = SecurityEventCatalog.Production;
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "UnicodeString", "AnsiString", "Int8", "Int16", "Int32", "Int64", "UInt8", "UInt16", "UInt32", "UInt64",
            "HexInt32", "HexInt64", "SID", "GUID"
        };
        var report = new List<string>();
        foreach (var provider in catalog.Channels.SelectMany(channel => channel.Definitions).Select(d => d.Provider).Distinct())
        {
            List<EventMetadata> events;
            try
            {
                using var metadata = new ProviderMetadata(provider);
                events = metadata.Events.ToList();
            }
            catch (Exception) when (provider == SecurityEventProviders.Defender)
            {
                Console.WriteLine("Native manifest conformance notice: the Defender provider is not installed.");
                continue;
            }

            foreach (var definition in catalog.Channels.SelectMany(channel => channel.Definitions).Where(d => d.Provider == provider))
            {
                var versions = events.Where(metadata => metadata.Id == definition.EventId).ToList();
                Check(versions.Count > 0, $"The {provider} manifest has no event {definition.EventId}.");
                foreach (var field in (definition.Predicate?.Fields ?? []).Concat(definition.Fields.Fields))
                {
                    if (!field.Path.StartsWith("Event/EventData/", StringComparison.Ordinal)) continue;
                    foreach (var version in versions.Where(metadata => metadata.Version >= field.SinceVersion))
                    {
                        var template = string.IsNullOrEmpty(version.Template) ? "<template/>" : version.Template;
                        var data = XDocument.Parse(template).Descendants()
                            .Where(element => element.Name.LocalName == "data")
                            .FirstOrDefault(element => (string?)element.Attribute("name") == field.Name);
                        var inType = ((string?)data?.Attribute("inType"))?.Split(':')[^1];
                        Check(data is not null && inType is not null && allowed.Contains(inType),
                            $"Event {definition.EventId} v{version.Version} lacks a readable {field.Name}.");
                    }
                }

                report.Add($"{definition.EventId} v[{string.Join(",", versions.Select(v => v.Version).Order())}] ok");
            }
        }

        Console.WriteLine($"Native manifest conformance: {string.Join("; ", report)}");
        foreach (var channel in catalog.ChannelNames)
        {
            foreach (var xpath in new[] { catalog.BuildXPath(channel, 1, 2, null), catalog.BuildXPath(channel, 1, 2, 1) })
            {
                try
                {
                    using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName, xpath));
                    assertions++;
                }
                catch (UnauthorizedAccessException) when (channel == SecurityEventChannels.Security)
                {
                    Console.WriteLine("Native query parse notice: Security is accessDenied for this account.");
                }
                catch (EventLogNotFoundException) when (channel == SecurityEventChannels.Defender)
                {
                    Console.WriteLine("Native query parse notice: Defender is notFound.");
                }
            }
        }

        using var access = new WindowsEventLogAccess(catalog);
        var states = new List<string>();
        foreach (var channel in catalog.ChannelNames)
        {
            try
            {
                var extent = access.Describe(channel);
                states.Add($"{channel}=collecting(newest {extent.NewestRecordId?.ToString() ?? "none"})");
            }
            catch (EventChannelUnavailableException exception) when (channel != SecurityEventChannels.System)
            {
                states.Add($"{channel}={exception.State}");
            }
        }

        Console.WriteLine($"Native event channel metadata: {string.Join(", ", states)}");
        var missingCatalog = SecurityEventCatalog.Create(
        [
            new("SentinelAI-Nonexistent/Operational",
            [
                new("SentinelAI-Nonexistent/Operational", "SentinelAI-Test-Only", 1, "test", null, null, new EventFieldSet([]))
            ])
        ]);
        using (var missing = new WindowsEventLogAccess(missingCatalog))
        {
            try
            {
                missing.Describe("SentinelAI-Nonexistent/Operational");
                throw new Exception("A nonexistent channel was described.");
            }
            catch (EventChannelUnavailableException exception)
            {
                Check(exception.State == SecurityEventSourceStates.NotFound, "A nonexistent channel was not reported as notFound.");
            }
        }

        Reject<ArgumentException>(() => access.Describe("Application"), "The adapter described a non-catalog channel.");
        Check(WindowsEventLogAccess.ToPortable(new SecurityIdentifier("S-1-5-18")) is "S-1-5-18" &&
              WindowsEventLogAccess.ToPortable(7) is 7L && WindowsEventLogAccess.ToPortable((uint)7) is 7L &&
              WindowsEventLogAccess.ToPortable(ulong.MaxValue) is null &&
              ReferenceEquals(WindowsEventLogAccess.ToPortable(new string('x', 1025)), EventFieldValue.Oversize) &&
              WindowsEventLogAccess.ToPortable(DateTime.UtcNow) is null && WindowsEventLogAccess.ToPortable(true) is null,
            "Native values were not converted to portable values.");
    }

    private static NormalizationResult Normalize(SecurityEventFixtures.Fixture fixture,
        Dictionary<string, object?>? overrides = null, int? version = null)
    {
        var fields = new Dictionary<string, object?>(fixture.Fields);
        foreach (var (name, value) in overrides ?? []) fields[name] = value;
        var definition = Definition(fixture);
        return SecurityEventNormalizer.Normalize(definition, Header(fixture, 7) with { Version = version ?? fixture.Version },
            Render(definition.Predicate, fields), Render(definition.Fields, fields));
    }

    private static SecurityEventDefinition Definition(SecurityEventFixtures.Fixture fixture) =>
        SecurityEventCatalog.Production.Find(fixture.Channel, fixture.Provider, fixture.EventId, fixture.Level)!;

    private static EventRecordHeader Header(SecurityEventFixtures.Fixture fixture, long recordId) =>
        new(recordId, fixture.Provider, fixture.EventId, fixture.Version, fixture.Level, SyntheticEventLog.TimeOf(0, recordId));

    private static IReadOnlyList<object?>? Render(EventFieldSet? set, IReadOnlyDictionary<string, object?> fields) =>
        set?.Fields.Select(field => fields.GetValueOrDefault(field.Name) is int number ? (long)number : fields.GetValueOrDefault(field.Name))
            .ToArray();

    private static void Seed(SyntheticEventLog log, int perChannel)
    {
        var fixtures = new Dictionary<string, int>
        {
            [SecurityEventChannels.Security] = 4625, [SecurityEventChannels.System] = 7045,
            [SecurityEventChannels.PowerShell] = 4104, [SecurityEventChannels.Defender] = 1116
        };
        foreach (var (channel, eventId) in fixtures)
        {
            for (var index = 0; index < perChannel; index++)
            {
                if (index % 2 == 0) SecurityEventFixtures.Append(log, SecurityEventFixtures.For(eventId));
                else log.AppendNoise(channel, 1);
            }
        }
    }

    private static void AppendMany(SyntheticEventLog log, SecurityEventFixtures.Fixture fixture, int count)
    {
        for (var index = 0; index < count; index++) SecurityEventFixtures.Append(log, fixture);
    }

    private static IEnumerable<long> Range(long first, long last)
    {
        for (var id = first; id <= last; id++) yield return id;
    }

    private static SecurityEventBatch SampleBatch(Guid endpoint) => new(endpoint, SecurityEventContract.Format, "1.0.0.0", Start, Start,
        [
            new SecurityEventSourceStatus(SecurityEventChannels.System, SecurityEventSourceStates.Collecting, null, 1, 10, 10,
                20 * 1024 * 1024, Start, 0, 1, 1, 0, 0, 0, 0, 0, 0)
        ],
        [
            new SecurityEventGap(SecurityEventChannels.System, SecurityEventGapReasons.CoverageStarted, 1, null, Start,
                SecurityEventCoverageCauses.NoCheckpoint)
        ],
        [
            new SecurityEventObservation(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4624, 2, 0, 9,
                Start, SecurityEventKinds.LogonSucceeded,
                Logon: new LogonEvent(10, SecurityEventFixtures.UserSid, SecurityEventFixtures.RemoteIp, null, null, true))
        ]);

    private static AgentOptions Options(string directory) =>
        new(new Uri("http://127.0.0.1:5000"), Path.GetFullPath(directory), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5),
            TimeSpan.FromMinutes(1), null, null);

    private static EnrollmentState Enrollment(Guid endpointId) =>
        new(Guid.NewGuid(), endpointId, Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), "http://127.0.0.1:5000/", null);

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SentinelAI.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new Exception("The repository root was not found.");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        assertions++;
    }

    private static void Reject<TException>(Action action, string message) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            assertions++;
            return;
        }

        throw new Exception(message);
    }

    private sealed record Generated(string Channel, int Generation, long Id, DateTimeOffset Created,
        SecurityEventFixtures.Fixture? Fixture);

    /// <summary>A pipeline over a synthetic log, a manual clock and a scripted or in-memory Core.</summary>
    private sealed class Rig
    {
        private readonly ILoggerProvider? _logs;

        private Rig(string directory, ISecurityEventUploader uploader, ILoggerProvider? logs)
        {
            Directory = Path.GetFullPath(directory);
            Options = SecurityEventPipelineTests.Options(directory);
            Enrollment = SecurityEventPipelineTests.Enrollment(Guid.NewGuid());
            UploaderInstance = uploader;
            _logs = logs;
            Restart();
        }

        public string Directory { get; }
        public AgentOptions Options { get; }
        public EnrollmentState Enrollment { get; }
        public SyntheticEventLog Log { get; } = new();
        public ManualTimeProvider Time { get; } = new(Start);
        public AgentLink Link { get; } = new();
        public ISecurityEventUploader UploaderInstance { get; private set; }
        public EventCheckpointStore Store { get; private set; } = null!;
        public SecurityEventPipeline Pipeline { get; private set; } = null!;
        public string CheckpointPath => Path.Combine(Directory, "event-checkpoints");

        public ScriptedUploader Uploader
        {
            get => (ScriptedUploader)UploaderInstance;
            set => UploaderInstance = value;
        }

        public static Rig Create(string directory, ISecurityEventUploader? uploader = null, bool linked = true,
            ILoggerProvider? logs = null)
        {
            var rig = new Rig(directory, uploader ?? new ScriptedUploader(), logs);
            if (linked) rig.Link.Publish(rig.Enrollment);
            return rig;
        }

        /// <summary>A linked rig whose channels are covered at their (empty) tails and whose status settled.</summary>
        public static async Task<Rig> CoveredAsync(string directory, ISecurityEventUploader? uploader = null,
            ILoggerProvider? logs = null)
        {
            var rig = Create(directory, uploader, logs: logs);
            await rig.StepAsync();
            await rig.AdvanceAsync(TimeSpan.FromSeconds(2));
            return rig;
        }

        /// <summary>A new pipeline over the same data directory, log, clock and link (a process restart).</summary>
        public void Restart()
        {
            Store = new EventCheckpointStore(Options);
            var logger = _logs is CapturingEventLoggerProvider capturing
                ? capturing.LoggerFor<SecurityEventPipeline>()
                : NullLogger<SecurityEventPipeline>.Instance;
            Pipeline = new SecurityEventPipeline(Options, Log, Store, Link, UploaderInstance, Time, logger);
        }

        public Task StepAsync() => Pipeline.StepAsync(CancellationToken.None);

        public async Task AdvanceAsync(TimeSpan by)
        {
            Time.Advance(by);
            await StepAsync();
        }

        public SecurityEventSourceStatus Source(string channel) =>
            Pipeline.Snapshot.Sources.Single(source => source.Channel == channel);
    }
}
