using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;
using SentinelAI.Agent;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core.Persistence;

/// <summary>
/// TASK-027 Tier N2: elevated, opt-in acceptance of native security event collection. The production
/// adapter reads the real System channel, driven by never-started marker services; the adapter mechanics
/// run against a test-only classic log under a test catalog. Audit policy, channel access and real logs are
/// never changed, and only marker and test-log records are inspected. Every artifact is removed in finally.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SecurityEventNativeAcceptance
{
    private const string EventLogKey = @"SYSTEM\CurrentControlSet\Services\EventLog";
    private const int TestEventId = 1000;
    private const int OtherEventId = 1001;
    private const string PollInterval = "00:00:05";
    private static readonly TimeSpan FirstCollect = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan Latency = TimeSpan.FromSeconds(30);
    private static readonly Regex TestLogName = new("^SAIT[0-9a-f]{4}$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));

    public static async Task RunAsync(string testDirectory)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            Ensure(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
                "Native event acceptance must run elevated.");
        }

        PrintChannelAccess();
        var cleanupFailures = new List<string>();
        await DeleteStaleTestLogsAsync(cleanupFailures);
        Ensure(cleanupFailures.Count == 0, "A test-only event log from an earlier run could not be deleted.");
        var services = new List<string>();
        try
        {
            await RunScenarioAsync(testDirectory, services, cleanupFailures);
        }
        finally
        {
            foreach (var service in services)
            {
                try
                {
                    // Never started, so the delete is immediate; 1060 means it is already gone, 1072 that it is going.
                    var exitCode = await ScAsync("delete", service);
                    if (exitCode is not (0 or 1060 or 1072)) cleanupFailures.Add($"marker service (sc.exe exit code {exitCode})");
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add($"marker service ({exception.GetType().Name})");
                }
            }
        }

        Ensure(cleanupFailures.Count == 0, $"Native event acceptance cleanup failed: {string.Join(", ", cleanupFailures)}.");
        Console.WriteLine("Native event acceptance passed.");
    }

    private static async Task RunScenarioAsync(string testDirectory, List<string> services, List<string> cleanupFailures)
    {
        var markers = new List<string>();
        string Marker()
        {
            markers.Add($"test-only-secret-{Guid.NewGuid():N}");
            return markers[^1];
        }

        string Service()
        {
            services.Add("SentinelAIEventProbe" + Guid.NewGuid().ToString("N")[..8]);
            return services[^1];
        }

        var coreDirectory = Path.Combine(testDirectory, "core");
        var agentDirectory = Path.Combine(testDirectory, "agent");
        var logs = new CapturingEventLoggerProvider();
        using var link = new CoreLinkHandler();
        using var httpClient = new HttpClient(link, disposeHandler: false);

        // Step 2: marker A is logged before the Agent starts, so a tail start must never deliver it.
        var serviceA = Service();
        await CreateMarkerAsync(serviceA, Marker());
        await DeleteMarkerAsync(serviceA);
        await WaitForAsync(() => MarkerRecordId(serviceA) is not null,
            "The marker service installed before the start was not logged.", Latency);

        var core = await PostureMonitorTests.CoreFixture.StartAsync(coreDirectory);
        Guid endpointId;
        string states;
        try
        {
            var events = core.Services.GetRequiredService<SecurityEventStore>();
            IHost BuildAgent(IEventLogAccess source, string? enrollmentToken = null) => SecurityEventTestHost.BuildEventAgent(
                agentDirectory, core.Url, httpClient, source, enrollmentToken, logs, PollInterval);

            string serviceB;
            long recordB;
            using (var source = new WindowsEventLogAccess(SecurityEventCatalog.Production))
            using (var agent = BuildAgent(source, await core.IssueEnrollmentTokenAsync()))
            {
                await agent.StartAsync();
                try
                {
                    endpointId = await WaitForEndpointAsync(agentDirectory);
                    await WaitForAsync(async () => (await events.ListSourcesAsync(endpointId)).Any(view => view is
                        { Channel: SecurityEventChannels.System, State: SecurityEventSourceStates.Collecting, CheckpointRecordId: not null }),
                        "System was not collecting from an acknowledged position.", FirstCollect);

                    serviceB = Service();
                    var stopwatch = Stopwatch.StartNew();
                    await CreateMarkerAsync(serviceB, Marker());
                    await DeleteMarkerAsync(serviceB);
                    await WaitForAsync(async () => (await ServiceRowsAsync(events, endpointId, serviceB)).Count > 0,
                        "The marker service installation was not reflected in Core.", Latency);
                    var latency = stopwatch.ElapsedMilliseconds;
                    var rows = await ServiceRowsAsync(events, endpointId, serviceB);
                    // SCM inserts the type and start type as display text in the system language.
                    var english = CultureInfo.InstalledUICulture.TwoLetterISOLanguageName == "en";
                    Ensure(rows.Count == 1 && rows[0].ServiceInstall is
                           {
                               ImageFileName: "cmd.exe", ImageLocation: ServiceImageLocations.Windows,
                               AccountKind: ServiceAccountKinds.LocalSystem
                           } install &&
                           (install.ServiceType == ServiceTypes.UserModeService || !english && install.ServiceType is null) &&
                           install.StartType is ServiceStartTypes.Demand or null,
                        "The marker service installation was not normalized as expected.");
                    recordB = rows[0].RecordId;
                    Ensure((await ServiceRowsAsync(events, endpointId, serviceA)).Count == 0,
                        "A service installed before coverage started was delivered.");
                    Console.WriteLine($"Native event acceptance: service installation reflected in Core after {latency} ms");

                    await VerifyTestLogAsync(events, endpointId, Marker(), cleanupFailures);
                }
                finally
                {
                    await StopAsync(agent);
                }
            }

            // Step 4: a graceful restart resumes from the persisted positions; B is neither sent nor stored again.
            var serviceC = Service();
            await CreateMarkerAsync(serviceC, Marker());
            await DeleteMarkerAsync(serviceC);
            using (var source = new WindowsEventLogAccess(SecurityEventCatalog.Production))
            using (var agent = BuildAgent(source))
            {
                await agent.StartAsync();
                try
                {
                    await WaitForAsync(async () => (await ServiceRowsAsync(events, endpointId, serviceC)).Count == 1,
                        "A service installed while the Agent was stopped was not delivered after the restart.", FirstCollect);
                    Ensure((await ServiceRowsAsync(events, endpointId, serviceB)).Count == 1,
                        "The restart stored the earlier service installation again.");
                }
                finally
                {
                    await StopAsync(agent);
                }
            }

            Ensure(link.AcceptedSends(SecurityEventChannels.System, recordB) == 1,
                "The restarted Agent sent the earlier service installation again.");
            var view = await core.EventSourcesAsync(endpointId);
            states = string.Join(", ", new[]
            {
                ("Security", SecurityEventChannels.Security), ("System", SecurityEventChannels.System),
                ("PowerShell", SecurityEventChannels.PowerShell), ("Defender", SecurityEventChannels.Defender)
            }.Select(channel => $"{channel.Item1}={view.Sources.FirstOrDefault(source => source.Channel == channel.Item2)?.State ?? "none"}"));
        }
        finally
        {
            await core.DisposeAsync();
        }

        // Step 5: no marker reached Core's files, the Agent's files or the Agent's logs.
        SqliteConnection.ClearAllPools();
        foreach (var path in Directory.EnumerateFiles(coreDirectory, "*", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(agentDirectory, "*", SearchOption.AllDirectories)))
        {
            var bytes = File.ReadAllBytes(path);
            Ensure(markers.All(marker => bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(marker)) < 0 &&
                                         bytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes(marker)) < 0),
                $"A marker was persisted in {Path.GetFileName(path)}.");
        }

        Ensure(logs.Entries.Count > 0 && markers.All(marker => !logs.Text.Contains(marker, StringComparison.Ordinal)),
            "A marker reached the Agent logs.");
        Console.WriteLine($"Native event channel states: {states}");
    }

    // Step 3: adapter mechanics on a test-only classic log, read through a test catalog by its own adapter.
    // The production catalog is untouched, so the Agent never reads these records and Core never sees them.
    private static async Task VerifyTestLogAsync(SecurityEventStore events, Guid endpointId, string marker,
        List<string> cleanupFailures)
    {
        var suffix = Guid.NewGuid().ToString("N")[..4];
        var log = "SAIT" + suffix;
        var source = "SAITSrc" + suffix;
        var message = $"test-only native event acceptance {marker}";
        Ensure(!EventLog.Exists(log) && !EventLog.SourceExists(source), "The test-only event log already exists.");
        var catalog = SecurityEventCatalog.Create(
            [new(log, [new(log, source, TestEventId, "test", null, null, new EventFieldSet([]))])]);
        try
        {
            EventLog.CreateEventSource(source, log);
            await WaitForAsync(() => EventLogSession.GlobalSession.GetLogNames().Contains(log, StringComparer.OrdinalIgnoreCase),
                "The event log service did not register the test-only log.", Latency);
            // Best effort: until the service has loaded the source, a write could be routed to the Application log.
            var listed = Stopwatch.StartNew();
            while (!EventLogSession.GlobalSession.GetProviderNames().Contains(source, StringComparer.OrdinalIgnoreCase) &&
                   listed.Elapsed < TimeSpan.FromSeconds(10))
                await Task.Delay(250);
            using var access = new WindowsEventLogAccess(catalog);
            using var system = new WindowsEventLogAccess(SecurityEventCatalog.Production);

            // a) A new source may be refused until the service has loaded it; each attempt registers afresh.
            await WaitForAsync(() => TryWrite(log, source, message), "The test-only source could not be written.", Latency);
            await WaitForAsync(() => TryDescribe(access, log)?.NewestRecordId is not null,
                "The first test-only record did not reach the test log.", Latency);
            // Record numbers follow the plan's 1..8; r is 0 in a new log.
            var r = TryDescribe(access, log)!.NewestRecordId!.Value - 1;
            using var writer = new EventLog(log) { Source = source };
            foreach (var id in new[] { OtherEventId, OtherEventId, TestEventId, TestEventId, OtherEventId, OtherEventId, OtherEventId })
                writer.WriteEntry(message, EventLogEntryType.Information, id);
            await WaitForAsync(() => TryDescribe(access, log) is { } extent && extent.OldestRecordId == r + 1 && extent.NewestRecordId == r + 8,
                "The test-only log did not hold the eight written records.", Latency);

            // b) Without an anchor the query selects the catalog records plus the newest member.
            var plain = ReadAll(access, log, null, r + 8, out _);
            Ensure(plain.Select(header => header.RecordId).SequenceEqual(new long?[] { r + 4, r + 5, r + 8 }) &&
                   plain[0].EventId == TestEventId && plain[1].EventId == TestEventId,
                "The catalog query did not select exactly the catalog records and the newest member.");

            // c) The seek design gate: the bookmark positions on a non-catalog anchor selected by record number.
            var seek = ReadAll(access, log, r + 3, r + 8, out var usedFallback);
            Ensure(!usedFallback && seek.Select(header => header.RecordId).SequenceEqual(new long?[] { r + 3, r + 4, r + 5, r + 8 }),
                "The bookmark seek did not position on a non-catalog anchor without the fallback.");
            Ensure(seek[1].TimeCreatedUtc is { } time && time.UtcTicks == plain[0].TimeCreatedUtc?.UtcTicks,
                "A record's creation time changed between reads.");

            // d) The unfiltered reverse read returns the newest record with the same time.
            Ensure(access.ReadNewest(log) is { } newest && newest.RecordId == r + 8 &&
                   newest.TimeCreatedUtc?.UtcTicks == plain[2].TimeCreatedUtc?.UtcTicks,
                "The newest record was not read back with its time.");
            Console.WriteLine("Native event adapter: the bookmark seek positioned on a non-catalog anchor without the fallback.");

            // e) A long catalog run is read contiguously after its anchor.
            for (var index = 0; index < 300; index++) writer.WriteEntry(message, EventLogEntryType.Information, TestEventId);
            await WaitForAsync(() => TryDescribe(access, log)?.NewestRecordId == r + 308,
                "The test-only log did not hold the 300 catalog records.", Latency);
            var headersOnly = MeasureRead(access, log, r + 8, r + 308, source, null);
            var rendered = MeasureRead(access, log, r + 8, r + 308, source, new EventFieldSet(
                [new EventField("RecordId", "Event/System/EventRecordID", 0), new EventField("Provider", "Event/System/Provider/@Name", 0)]));
            Console.WriteLine($"Native event adapter read: {headersOnly:F1} us per record (headers), {rendered:F1} us per record (with field render)");

            // f) Overwrite. The size must be a multiple of 64 KiB; the service may apply a larger .evtx minimum.
            var p = r + 308;
            using (var settings = new EventLog(log))
            {
                settings.MaximumKilobytes = 64;
                settings.ModifyOverflowPolicy(OverflowAction.OverwriteAsNeeded, 0);
            }

            var filler = (marker + " ").PadRight(512, 'x');
            var writes = 0;
            while (writes < 50_000 && !(TryDescribe(access, log)?.OldestRecordId > p + 1))
            {
                for (var index = 0; index < 50; index++) writer.WriteEntry(filler, EventLogEntryType.Information, TestEventId);
                writes += 50;
            }

            await WaitForAsync(() => TryDescribe(access, log)?.OldestRecordId > p + 1,
                $"The test-only log was not overwritten after {writes} writes.", Latency);
            var overwritten = await SettleAsync(access, log);
            var firstLeft = ReadAll(access, log, null, overwritten.NewestRecordId!.Value, out _, limit: 1);
            Ensure(firstLeft.Count == 1 && firstLeft[0].RecordId >= overwritten.OldestRecordId,
                "A read after the overwrite returned a record older than the oldest one.");
            using (var configuration = new EventLogConfiguration(log))
            {
                Console.WriteLine($"Native event overwrite: oldest record {overwritten.OldestRecordId} after {writes} writes " +
                                  $"(64 KiB requested; effective maximum {configuration.MaximumSizeInBytes} bytes, {configuration.LogMode})");
            }

            // g) A clear of the test log only, then one write: the pipeline's reset predicate must see it.
            var anchor = access.ReadNewest(log) ?? throw new Exception("The test-only log is empty before the clear.");
            var anchorId = anchor.RecordId!.Value;
            var systemNewest = system.Describe(SecurityEventChannels.System).NewestRecordId ?? 0;
            var clearWatch = Stopwatch.StartNew();
            writer.Clear();
            writer.WriteEntry(message, EventLogEntryType.Information, TestEventId);
            await WaitForAsync(() => TryDescribe(access, log)?.NewestRecordId is { } id && id != anchorId,
                "The write after the clear did not reach the test log.", Latency);
            var reset = DetectReset(access, log, anchorId, anchor.TimeCreatedUtc);
            Ensure(reset is not null, "The clear of the test-only log is not detectable as a reset.");
            Console.WriteLine($"Native event reset detection: {reset}");

            // h) The clear produced System 104, which the running Agent delivers.
            await WaitForAsync(async () => await ClearRowAsync(events, endpointId, log, systemNewest) is not null,
                "The test-only log clear (System 104) was not reflected in Core.", Latency);
            var cleared = (await ClearRowAsync(events, endpointId, log, systemNewest))!.LogCleared?.ClearedChannel;
            Console.WriteLine($"Native event log clear: System 104 reflected in Core after {clearWatch.ElapsedMilliseconds} ms; " +
                              $"ClearedChannel={cleared ?? "null (notice: the UserData selector did not resolve)"}");
            Ensure((await events.ListRecentAsync(endpointId, 1000)).All(row => row.Observation.Channel != log),
                "A test-only log record reached Core.");
        }
        finally
        {
            await DeleteTestLogAsync(log, source, cleanupFailures);
        }
    }

    // Step 1: read-only channel configuration; no event is read.
    private static void PrintChannelAccess()
    {
        foreach (var channel in SecurityEventCatalog.Production.ChannelNames)
        {
            try
            {
                using var configuration = new EventLogConfiguration(channel);
                var sddl = configuration.SecurityDescriptor;
                Console.WriteLine($"Native event channel access: {channel}: SU/LS read ACE={GrantsServiceRead(sddl)}, " +
                                  $"maximum {configuration.MaximumSizeInBytes} bytes, SDDL {sddl}");
            }
            catch (EventLogNotFoundException)
            {
                Console.WriteLine($"Native event channel access: {channel}: notFound");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Native event channel access: {channel}: accessDenied");
            }
        }

        Console.WriteLine("Native event channel access expectation: Security has no SU/LS read ACE (a LocalService Agent reports accessDenied).");
    }

    private static bool GrantsServiceRead(string sddl)
    {
        const int ChannelRead = 0x1;
        const int GenericAll = 0x10000000;
        const int GenericRead = unchecked((int)0x80000000);
        return !string.IsNullOrEmpty(sddl) && new RawSecurityDescriptor(sddl).DiscretionaryAcl?.OfType<CommonAce>().Any(ace =>
            ace.AceQualifier == AceQualifier.AccessAllowed &&
            (ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.ServiceSid) ||
             ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.LocalServiceSid)) &&
            (ace.AccessMask & (ChannelRead | GenericAll | GenericRead)) != 0) == true;
    }

    private static string? DetectReset(IEventLogAccess access, string log, long anchorId, DateTimeOffset? anchorTime)
    {
        var extent = access.Describe(log);
        if (extent.NewestRecordId is not { } newest || newest < anchorId)
            return $"newest record {extent.NewestRecordId?.ToString() ?? "none"} is below the anchor {anchorId}";
        if (extent.OldestRecordId is not { } oldest || oldest > anchorId) return null;
        using var cursor = access.Open(log, anchorId, newest);
        if (!cursor.TryNext(out var header) || header.RecordId != anchorId) return $"anchor {anchorId} is missing";
        return header.TimeCreatedUtc?.UtcTicks != anchorTime?.UtcTicks ? $"anchor {anchorId} has a different time" : null;
    }

    private static List<EventRecordHeader> ReadAll(IEventLogAccess access, string log, long? after, long through,
        out bool usedFallback, int limit = 1024)
    {
        using var cursor = access.Open(log, after, through);
        var headers = new List<EventRecordHeader>();
        while (headers.Count < limit && cursor.TryNext(out var header)) headers.Add(header);
        usedFallback = cursor.UsedFallback;
        return headers;
    }

    // Microseconds per record over 256 records after the anchor, which the cursor returns first.
    private static double MeasureRead(IEventLogAccess access, string log, long anchor, long through, string source,
        EventFieldSet? fields)
    {
        using var cursor = access.Open(log, anchor, through);
        Ensure(!cursor.UsedFallback && cursor.TryNext(out var first) && first.RecordId == anchor,
            "A long read did not start at its anchor.");
        var stopwatch = Stopwatch.StartNew();
        for (var expected = anchor + 1; expected <= anchor + 256; expected++)
        {
            Ensure(cursor.TryNext(out var header) && header.RecordId == expected && header.EventId == TestEventId,
                "Catalog records were not read contiguously in ascending order.");
            if (fields is not null)
            {
                var values = cursor.ReadFields(fields);
                Ensure(values[0] is long id && id == expected && values[1] is string provider && provider == source,
                    "Rendered fields did not match the record.");
            }
        }

        return stopwatch.Elapsed.TotalMicroseconds / 256;
    }

    private static bool TryWrite(string log, string source, string message)
    {
        try
        {
            using var probe = new EventLog(log) { Source = source };
            probe.WriteEntry(message, EventLogEntryType.Information, OtherEventId);
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
            return false;
        }
    }

    private static ChannelExtent? TryDescribe(IEventLogAccess access, string log)
    {
        try
        {
            return access.Describe(log);
        }
        catch (Exception exception) when (exception is EventChannelUnavailableException or EventLogException)
        {
            return null;
        }
    }

    // Classic writes reach the log asynchronously: settled means the newest record held still for a second.
    private static async Task<ChannelExtent> SettleAsync(IEventLogAccess access, string log)
    {
        var deadline = Stopwatch.StartNew();
        var stable = Stopwatch.StartNew();
        var last = TryDescribe(access, log);
        while (deadline.Elapsed < Latency)
        {
            await Task.Delay(250);
            var current = TryDescribe(access, log);
            if (current is null || current.NewestRecordId != last?.NewestRecordId)
            {
                last = current;
                stable.Restart();
            }
            else if (stable.Elapsed >= TimeSpan.FromSeconds(1))
            {
                return current;
            }
        }

        throw new Exception("The test-only log did not settle.");
    }

    private static async Task<List<SecurityEventObservation>> ServiceRowsAsync(SecurityEventStore events, Guid endpointId,
        string service) => (await events.ListRecentAsync(endpointId, 1000)).Select(row => row.Observation)
        .Where(observation => observation.Channel == SecurityEventChannels.System &&
                              observation.Kind == SecurityEventKinds.ServiceInstalled &&
                              observation.ServiceInstall?.ServiceName == service)
        .ToList();

    // The 104 written after the clear: it names the test log, or nothing if the UserData selector did not resolve.
    private static async Task<SecurityEventObservation?> ClearRowAsync(SecurityEventStore events, Guid endpointId,
        string log, long systemNewest) => (await events.ListRecentAsync(endpointId, 1000)).Select(row => row.Observation)
        .FirstOrDefault(observation => observation is
                                       {
                                           Channel: SecurityEventChannels.System, EventId: 104,
                                           Kind: SecurityEventKinds.LogCleared
                                       } &&
                                       observation.RecordId > systemNewest &&
                                       (observation.LogCleared?.ClearedChannel is null ||
                                        string.Equals(observation.LogCleared.ClearedChannel, log, StringComparison.OrdinalIgnoreCase)));

    // Reads only the marker's own 7045 record, and only its record number.
    private static long? MarkerRecordId(string service)
    {
        var query = new EventLogQuery(SecurityEventChannels.System, PathType.LogName,
            $"*[System[Provider[@Name='{SecurityEventProviders.ServiceControlManager}'] and (EventID=7045)] and " +
            $"EventData[Data[@Name='ServiceName']='{service}']]")
        {
            ReverseDirection = true
        };
        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent(TimeSpan.FromSeconds(10));
        return record?.RecordId;
    }

    private static async Task CreateMarkerAsync(string service, string marker)
    {
        var exitCode = await ScAsync("create", service, "binPath=",
            $"{Path.Combine(Environment.SystemDirectory, "cmd.exe")} /c exit 0 --{marker}", "start=", "demand");
        Ensure(exitCode == 0, $"sc.exe could not create a marker service (exit code {exitCode}).");
    }

    private static async Task DeleteMarkerAsync(string service)
    {
        var exitCode = await ScAsync("delete", service);
        Ensure(exitCode == 0, $"sc.exe could not delete a marker service (exit code {exitCode}).");
    }

    private static async Task<int> ScAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new Exception("sc.exe did not start.");
        // Drained and discarded: the exit code is the result, and nothing service-specific is printed.
        var output = Task.WhenAll(process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill();
            throw new Exception("sc.exe did not finish within 30 seconds.");
        }

        await output;
        return process.ExitCode;
    }

    private static async Task DeleteStaleTestLogsAsync(List<string> failures)
    {
        string[] names;
        using (var root = Registry.LocalMachine.OpenSubKey(EventLogKey))
        {
            names = root?.GetSubKeyNames() ?? [];
        }

        foreach (var name in names.Where(key => TestLogName.IsMatch(key))) await DeleteTestLogAsync(name, null, failures);
        try
        {
            // Files of deleted logs that the service still held when an earlier run cleaned up.
            foreach (var file in Directory.EnumerateFiles(Path.Combine(Environment.SystemDirectory, "winevt", "Logs"), "SAIT*.evtx"))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                if (TestLogName.IsMatch(name) && !EventLog.Exists(name)) File.Delete(file);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine("Native event cleanup notice: a stale test-only log file is still in use.");
        }
    }

    // EventLog.Delete clears the log (System 104) and removes its registry tree with its sources. The registry
    // names no file for a log created this way, so the .evtx file is removed here once the service releases it.
    private static async Task DeleteTestLogAsync(string log, string? source, List<string> failures)
    {
        var file = Path.Combine(Environment.SystemDirectory, "winevt", "Logs", log + ".evtx");
        try
        {
            using var configuration = new EventLogConfiguration(log);
            file = Environment.ExpandEnvironmentVariables(configuration.LogFilePath);
        }
        catch (Exception)
        {
            // The default location applies when the service does not know the log.
        }

        try
        {
            if (EventLog.Exists(log)) EventLog.Delete(log);
        }
        catch (Exception)
        {
            // A log the service cannot clear keeps its registration; remove it directly.
            using var root = Registry.LocalMachine.OpenSubKey(EventLogKey, writable: true);
            root?.DeleteSubKeyTree(log, throwOnMissingSubKey: false);
        }

        try
        {
            if (source is not null && EventLog.SourceExists(source)) EventLog.DeleteEventSource(source);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            failures.Add("test-only event source");
        }

        if (EventLog.Exists(log))
        {
            failures.Add("test-only event log");
            return;
        }

        if (!string.Equals(Path.GetFileName(file), log + ".evtx", StringComparison.OrdinalIgnoreCase)) return;
        var deadline = Stopwatch.StartNew();
        while (File.Exists(file))
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (deadline.Elapsed >= TimeSpan.FromSeconds(10))
                {
                    Console.WriteLine("Native event cleanup notice: the event log service still holds the test-only log file; the next run deletes it.");
                    return;
                }

                await Task.Delay(250);
            }
        }
    }

    private static async Task<Guid> WaitForEndpointAsync(string agentDirectory)
    {
        var path = Path.Combine(agentDirectory, "endpoint-id");
        var endpointId = Guid.Empty;
        await WaitForAsync(() =>
        {
            try
            {
                return File.Exists(path) && Guid.TryParse(File.ReadAllText(path), out endpointId);
            }
            catch (IOException)
            {
                return false;
            }
        }, "The Agent did not enroll.", FirstCollect);
        return endpointId;
    }

    private static async Task StopAsync(IHost host)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await host.StopAsync(timeout.Token).WaitAsync(TimeSpan.FromSeconds(15));
    }

    // Core and the native log are polled every 250 ms within bounded deadlines.
    private static async Task WaitForAsync(Func<Task<bool>> condition, string message, TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (!await condition())
        {
            if (deadline.Elapsed >= timeout) throw new Exception(message);
            await Task.Delay(250);
        }
    }

    private static Task WaitForAsync(Func<bool> condition, string message, TimeSpan timeout) =>
        WaitForAsync(() => Task.FromResult(condition()), message, timeout);

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
