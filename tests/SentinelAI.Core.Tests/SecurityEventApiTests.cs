using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class SecurityEventApiTests
{
    private const string IngestPath = "/api/agent/security-events";
    private const string AgentVersion = "0.1.0-test";
    private static readonly DateTimeOffset EventEpoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset CountersSince = DateTimeOffset.UtcNow.AddHours(-3);
    private static readonly string Marker = $"test-only-secret-{Guid.NewGuid():N}";
    // Synthetic identities only: fictitious SIDs, documentation IP ranges and test-only names.
    private static readonly string[] SyntheticValues = ["S-1-5-21-1000-1000-1000-", "192.0.2.", "2001:db8:", "test-only-"];

    private static readonly string[] SourceProperties =
    [
        "channel", "state", "lastErrorCode", "oldestRecordId", "newestRecordId", "checkpointRecordId",
        "logMaximumBytes", "lastReadUtc", "scanned", "observed", "delivered", "droppedUnparsed", "droppedOversize",
        "fieldsDiscarded", "gaps", "skippedRecords", "seekFallbacks", "reportedUtc", "agentSentUtc",
        "countersSinceUtc", "agentVersion", "coveredSinceUtc", "storedObservations"
    ];

    private static readonly string[] GapProperties =
        ["channel", "reason", "cause", "firstRecordId", "lastRecordId", "detectedUtc", "receivedUtc", "coverageRestart"];

    private sealed record Agent(Guid EndpointId, string Credential)
    {
        public string Authorization => $"{EndpointId:D}.{Credential}";
        public override string ToString() => nameof(Agent);
    }

    public static async Task VerifyAsync(string username, string password)
    {
        // Private synthetic installations keep these scenarios within their own per-IP rate windows.
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-security-event-tests-{Guid.NewGuid():N}");
        var retentionDirectory = directory + "-retention";
        var logs = new CapturingLoggerProvider();
        try
        {
            await VerifyIngestAsync(directory, username, password, logs);
            await VerifyConcurrencyAsync(directory, username, password, logs);
            await VerifyRateLimitAsync(directory, logs);
            await VerifyRetentionAsync(retentionDirectory, logs);
            Check(logs.Entries.Count > 0 && logs.Entries.All(entry => !ContainsSynthetic(entry.Message)),
                "Core logged security event content, an identity or a request body.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            if (Directory.Exists(retentionDirectory)) Directory.Delete(retentionDirectory, recursive: true);
        }

        Console.WriteLine("Security event API tests passed (ingest, per-item validation, deduplication, gaps, " +
                          "status guard, retention, strictness, rate limit, status route, concurrency).");
    }

    private static async Task VerifyIngestAsync(string directory, string username, string password,
        CapturingLoggerProvider logs)
    {
        await using var app = Build(directory, logs);
        using var client = await StartAsync(app);
        var store = app.Services.GetRequiredService<SecurityEventStore>();
        var a = await EnrollAsync(app);
        var b = await EnrollAsync(app);
        var c = await EnrollAsync(app);

        // C1: every catalog selection, all four statuses and a coverage gap in one batch.
        var all = SecurityEventContract.Catalog.Select((selection, index) => Observation(selection, 10 + index)).ToArray();
        var coverage = Gap(SecurityEventChannels.System, SecurityEventGapReasons.CoverageStarted, 9, null,
            SecurityEventCoverageCauses.NoCheckpoint);
        var statuses = SecurityEventChannels.All.Select(channel => Status(channel)).ToArray();
        var before = DateTimeOffset.UtcNow;
        var first = await RecordAsync(client, a, Batch(a, all, [coverage], statuses));
        var after = DateTimeOffset.UtcNow;
        Check(first == new SecurityEventBatchResult(all.Length, 0, 0, 0), "A valid security event batch was not fully accepted.");
        var stored = await store.ListRecentAsync(a.EndpointId, 100);
        Check(stored.Count == all.Length && stored.All(row => row.ReceivedUtc >= before && row.ReceivedUtc <= after) &&
              all.All(sent => stored.Count(row => row.Observation == sent &&
                  row.Observation.TimeCreatedUtc.UtcTicks == sent.TimeCreatedUtc.UtcTicks &&
                  row.Observation.TimeCreatedUtc.Offset == TimeSpan.Zero) == 1),
            "Stored observations did not round-trip every typed field and exact event time.");
        var columns = await QueryAsync(app, """
            SELECT Channel, Provider, EventId, EventVersion, RecordId, TimeCreatedUtcTicks, Kind, Format
            FROM SecurityEventObservations WHERE EndpointId = $e;
            """, a.EndpointId);
        Check(columns.Count == all.Length && all.All(o => columns.Count(row => row.SequenceEqual([
                o.Channel, o.Provider, Invariant(o.EventId), Invariant(o.EventVersion), Invariant(o.RecordId),
                Invariant(o.TimeCreatedUtc.UtcTicks), o.Kind, SecurityEventContract.Format])) == 1),
            "Security event envelope columns or the wire format were not stored.");
        var view = await store.GetSourcesViewAsync(a.EndpointId);
        Check(view.EndpointId == a.EndpointId && view.Sources.Count == 4 && view.Sources.All(source =>
                  source.State == SecurityEventSourceStates.Collecting && source.CheckpointRecordId == 100 &&
                  source.CoveredSinceUtc is not null && source.AgentVersion == AgentVersion &&
                  source.CountersSinceUtc == CountersSince &&
                  source.StoredObservations == all.Count(o => o.Channel == source.Channel)),
            "Per-channel statuses were not stored with coverage and stored-observation counts.");
        Check(view.RecentGaps.Count == 1 && view.RecentGaps[0] is
              {
                  Channel: SecurityEventChannels.System, Reason: SecurityEventGapReasons.CoverageStarted,
                  Cause: SecurityEventCoverageCauses.NoCheckpoint, FirstRecordId: 9, LastRecordId: null,
                  CoverageRestart: false
              }, "A first coverage start was not stored as a non-restart gap.");

        // C2: replay is absorbed; a record number reused after a clear is a new event.
        var replay = await RecordAsync(client, a, Batch(a, all, [coverage], statuses));
        Check(replay == new SecurityEventBatchResult(0, all.Length, 0, 0) &&
              await store.CountAsync(a.EndpointId) == all.Length &&
              (await store.ListGapsAsync(a.EndpointId, 500)).Count == 1,
            "A replayed batch duplicated observations or gaps.");
        var service = all.Single(o => o.EventId == 7045);
        var reused = service with { TimeCreatedUtc = service.TimeCreatedUtc.AddDays(1) };
        Check(await RecordAsync(client, a, Batch(a, [reused])) == new SecurityEventBatchResult(1, 0, 0, 0) &&
              await store.CountAsync(a.EndpointId) == all.Length + 1,
            "A record number reused with a different event time was treated as a duplicate.");

        // C3: unknown tuples, statuses and gap reasons are ignored; unknown members are never stored.
        var unknown = await RecordAsync(client, a, Batch(a,
            [
                new SecurityEventObservation("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, 5, 4,
                    500, EventTime(500), "processCreated"),
                Observation(Selection(4624), 501) with { Kind = "test-only-kind" }
            ],
            [
                Gap(SecurityEventChannels.Security, SecurityEventGapReasons.Rejected, 600, 600),
                Gap(SecurityEventChannels.Security, "test-only-reason", 601, null)
            ],
            [Status("Application"), Status(SecurityEventChannels.System, "paused")]));
        Check(unknown == new SecurityEventBatchResult(0, 0, 6, 0) && await store.CountAsync(a.EndpointId) == all.Length + 1 &&
              (await store.ListGapsAsync(a.EndpointId, 500)).Count == 1 &&
              (await store.ListSourcesAsync(a.EndpointId)).All(source => source.State == SecurityEventSourceStates.Collecting),
            "Unknown observations, statuses or gap reasons were stored or rejected.");
        var extended = JsonSerializer.SerializeToNode(Batch(a, [Observation(Selection(4625), 700)],
            [Gap(SecurityEventChannels.Defender, SecurityEventGapReasons.Overwritten, 40, 45)],
            [Status(SecurityEventChannels.PowerShell)]), SecurityEventContract.Json)!.AsObject();
        extended["testOnlyUnknown"] = Marker;
        extended["sources"]![0]!["testOnlyUnknown"] = Marker;
        extended["gaps"]![0]!["testOnlyUnknown"] = Marker;
        extended["events"]![0]!["testOnlyUnknown"] = Marker;
        extended["events"]![0]!["logon"]!["testOnlyUnknown"] = Marker;
        using (var response = await PostAsync(client, a, Raw(extended.ToJsonString())))
        {
            Check(response.StatusCode == HttpStatusCode.OK &&
                  await response.Content.ReadFromJsonAsync<SecurityEventBatchResult>(SecurityEventContract.Json) ==
                  new SecurityEventBatchResult(1, 0, 0, 0),
                "A batch from a newer Agent with additional members was not accepted.");
        }
        var json = await QueryAsync(app, """
            SELECT ObservationJson FROM SecurityEventObservations WHERE EndpointId = $e
            UNION ALL SELECT StatusJson FROM SecurityEventSources WHERE EndpointId = $e;
            """, a.EndpointId);
        Check(json.Count == all.Length + 2 + 4 && json.All(row =>
                  !row[0].Contains(Marker, StringComparison.Ordinal) &&
                  !row[0].Contains("testOnlyUnknown", StringComparison.OrdinalIgnoreCase)),
            "Core persisted unknown request members instead of its validated typed records.");

        // C4: one invalid observation is rejected and recorded as a gap; the rest are stored.
        var invalid = Observation(Selection(4625), 777) with
        {
            Logon = new LogonEvent(3, "S-1-5-21-test-only-invalid", null, null, null, null)
        };
        var mixed = await RecordAsync(client, a, Batch(a, [Observation(Selection(4625), 778), invalid, Observation(Selection(7045), 779)]));
        var recordIds = (await store.ListRecentAsync(a.EndpointId, 1000)).Select(row => row.Observation.RecordId).ToArray();
        Check(mixed == new SecurityEventBatchResult(2, 0, 0, 1) && recordIds.Contains(778) && recordIds.Contains(779) &&
              !recordIds.Contains(777), "Per-item validation did not keep valid observations and reject only the invalid one.");
        Check((await store.ListGapsAsync(a.EndpointId, 500)).Count(gap => gap is
              {
                  Channel: SecurityEventChannels.Security, Reason: SecurityEventGapReasons.Rejected, Cause: null,
                  FirstRecordId: 777, LastRecordId: 777, CoverageRestart: false
              }) == 1, "A rejected observation was not recorded as a durable rejected gap.");
        var warnings = logs.Entries.Where(entry => entry.Level == LogLevel.Warning &&
            entry.Category == typeof(SecurityEventStore).FullName).ToArray();
        Check(warnings.Length == 1 &&
              warnings[0].Message == $"Security event batch from endpoint {a.EndpointId:D}: 1 items rejected" &&
              warnings[0].Keys.Order(StringComparer.Ordinal).SequenceEqual(["EndpointId", "Rejected", "{OriginalFormat}"]),
            "The rejection warning carried more than the endpoint ID and count.");

        // Invalid gaps and statuses are rejected without being stored; an observation without a usable
        // record number is rejected without a gap row (it has no position to record).
        var gapsBefore = await store.ListGapsAsync(a.EndpointId, 500);
        var invalidItems = await RecordAsync(client, a, Batch(a,
            [Observation(Selection(4625), 0)],
            [Gap(SecurityEventChannels.System, SecurityEventGapReasons.Overwritten, 900, null)],
            [Status(SecurityEventChannels.System, SecurityEventSourceStates.Error) with { Scanned = -1 }]));
        Check(invalidItems == new SecurityEventBatchResult(0, 0, 0, 3) &&
              (await store.ListGapsAsync(a.EndpointId, 500)).SequenceEqual(gapsBefore) &&
              (await store.ListSourcesAsync(a.EndpointId)).All(source => source.State == SecurityEventSourceStates.Collecting),
            "An invalid gap, status or record number was stored instead of rejected.");

        await VerifyStatusGuardAndGapsAsync(client, store, c);
        await VerifyStrictnessAsync(client, store, a, b, logs);
        await VerifyStatusRouteAsync(app, client, store, a, username, password);
    }

    // C5 and C6.
    private static async Task VerifyStatusGuardAndGapsAsync(HttpClient client, SecurityEventStore store, Agent c)
    {
        var now = DateTimeOffset.UtcNow;
        var firstProcess = now.AddHours(-2);
        var secondProcess = now.AddHours(-1);
        await RecordAsync(client, c, Batch(c,
            gaps: [Gap(SecurityEventChannels.System, SecurityEventGapReasons.CoverageStarted, 101, null, SecurityEventCoverageCauses.NoCheckpoint)],
            sources: [Status(SecurityEventChannels.System, checkpoint: null)]) with
        {
            SentUtc = now.AddMinutes(-30), CountersSinceUtc = firstProcess
        });
        var uncovered = (await store.ListSourcesAsync(c.EndpointId)).Single();
        Check(uncovered is { CheckpointRecordId: null, CoveredSinceUtc: null } &&
              (await store.ListGapsAsync(c.EndpointId, 500)).Single().CoverageRestart == false,
            "A status without an acknowledged position marked the channel covered.");

        await RecordAsync(client, c, Batch(c, sources: [Status(SecurityEventChannels.System)]) with
        {
            SentUtc = now.AddMinutes(-20), CountersSinceUtc = firstProcess
        });
        var covered = (await store.ListSourcesAsync(c.EndpointId)).Single();
        Check(covered is { CheckpointRecordId: 100, CoveredSinceUtc: not null } && covered.AgentSentUtc == now.AddMinutes(-20),
            "A status with an acknowledged position did not record coverage.");

        await RecordAsync(client, c, Batch(c, sources: [Status(SecurityEventChannels.System, SecurityEventSourceStates.Error)]) with
        {
            SentUtc = now.AddMinutes(-25), CountersSinceUtc = firstProcess
        });
        var guarded = (await store.ListSourcesAsync(c.EndpointId)).Single();
        Check(guarded.State == SecurityEventSourceStates.Collecting && guarded.AgentSentUtc == now.AddMinutes(-20),
            "An older attempt from the same Agent process overwrote a newer status.");

        await RecordAsync(client, c, Batch(c, sources: [Status(SecurityEventChannels.System, SecurityEventSourceStates.Disabled, null)]) with
        {
            SentUtc = now.AddMinutes(-40), CountersSinceUtc = secondProcess
        });
        var restarted = (await store.ListSourcesAsync(c.EndpointId)).Single();
        Check(restarted is { State: SecurityEventSourceStates.Disabled, CheckpointRecordId: null } &&
              restarted.CoveredSinceUtc == covered.CoveredSinceUtc && restarted.CountersSinceUtc == secondProcess &&
              restarted.AgentSentUtc == now.AddMinutes(-40),
            "A new Agent process did not replace the status, or coverage history was cleared.");

        await RecordAsync(client, c, Batch(c, gaps:
        [
            Gap(SecurityEventChannels.System, SecurityEventGapReasons.CoverageStarted, 201, null, SecurityEventCoverageCauses.CheckpointInvalid),
            Gap(SecurityEventChannels.PowerShell, SecurityEventGapReasons.CoverageStarted, 301, null, SecurityEventCoverageCauses.NoCheckpoint)
        ]));
        var coverageGaps = await store.ListGapsAsync(c.EndpointId, 500);
        Check(coverageGaps.Single(gap => gap.FirstRecordId == 101).CoverageRestart == false &&
              coverageGaps.Single(gap => gap.FirstRecordId == 201) is
                  { CoverageRestart: true, Cause: SecurityEventCoverageCauses.CheckpointInvalid } &&
              coverageGaps.Single(gap => gap.FirstRecordId == 301).CoverageRestart == false,
            "Coverage restarts were not distinguished from first coverage of a channel.");

        await RecordAsync(client, c, Batch(c, gaps:
        [
            Gap(SecurityEventChannels.System, SecurityEventGapReasons.Overwritten, 10, 20),
            Gap(SecurityEventChannels.Security, SecurityEventGapReasons.LogReset, 50, null)
        ]));
        await RecordAsync(client, c, Batch(c, gaps:
        [
            Gap(SecurityEventChannels.System, SecurityEventGapReasons.Overwritten, 10, 30),
            Gap(SecurityEventChannels.Security, SecurityEventGapReasons.LogReset, 50, null)
        ]));
        await RecordAsync(client, c, Batch(c, gaps: [Gap(SecurityEventChannels.System, SecurityEventGapReasons.Overwritten, 10, 25)]));
        var merged = await store.ListGapsAsync(c.EndpointId, 500);
        Check(merged.Count(gap => gap.Reason == SecurityEventGapReasons.Overwritten) == 1 &&
              merged.Single(gap => gap.Reason == SecurityEventGapReasons.Overwritten).LastRecordId == 30 &&
              merged.Count(gap => gap.Reason == SecurityEventGapReasons.LogReset) == 1 &&
              merged.Single(gap => gap.Reason == SecurityEventGapReasons.LogReset).LastRecordId is null,
            "Repeated gaps were not merged to one row with the widest range.");
    }

    // C8: transport, authentication, media type, size, strict JSON and envelope ordering.
    private static async Task VerifyStrictnessAsync(HttpClient client, SecurityEventStore store, Agent a, Agent b,
        CapturingLoggerProvider logs)
    {
        var service = Selection(7045);
        var probe = Batch(a, [Observation(service, 9001)],
            [Gap(SecurityEventChannels.System, SecurityEventGapReasons.Dropped, 9002, 9002)],
            [Status(SecurityEventChannels.System, SecurityEventSourceStates.Error)]) with
        {
            SentUtc = DateTimeOffset.UtcNow.AddDays(1)
        };
        var valid = JsonSerializer.Serialize(probe, SecurityEventContract.Json);
        var oversized = valid.Insert(1, $"\"testOnlyPadding\":\"{new string('x', 300 * 1024)}\",");
        // An unknown member (skipped by Core) keeps bodies that must stay unread above the 1 KiB that
        // SocketsHttpHandler still sends after an early error response to Expect: 100-continue.
        var padded = valid.Insert(1, $"\"testOnlyPadding\":\"{new string('x', 4 * 1024)}\",");
        string Mutate(Action<JsonObject> change)
        {
            var node = JsonSerializer.SerializeToNode(probe, SecurityEventContract.Json)!.AsObject();
            change(node);
            return node.ToJsonString();
        }

        var wrongCredential = a with { Credential = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)) };
        // Bodies that Core must refuse unread are offered with Expect: 100-continue and no continue timeout that
        // a slow host could reach. Kestrel sends 100 Continue only when the route starts reading, so such a body
        // is transmitted only if Core reads it. A body Core cannot drain closes that connection, so every request
        // here uses its own connection.
        using var unreadClient = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false, Expect100ContinueTimeout = TimeSpan.FromSeconds(30)
        }) { BaseAddress = client.BaseAddress, Timeout = TimeSpan.FromSeconds(30) };
        var unread = new HashSet<string>(StringComparer.Ordinal)
        {
            "anonymous valid body", "anonymous malformed body", "anonymous oversized body", "wrong credential",
            "Content-Length over the cap"
        };
        var cases = new (string Name, HttpStatusCode Expected, Agent? Agent, Func<HttpContent> Content)[]
        {
            ("anonymous valid body", HttpStatusCode.Unauthorized, null, () => Raw(padded)),
            ("anonymous malformed body", HttpStatusCode.Unauthorized, null, () => Raw(padded[..^2])),
            ("anonymous oversized body", HttpStatusCode.Unauthorized, null, () => Raw(oversized)),
            ("wrong credential", HttpStatusCode.Unauthorized, wrongCredential, () => Raw(padded)),
            ("header and body endpoint differ", HttpStatusCode.Unauthorized, a,
                () => Raw(Mutate(node => node["endpointId"] = Guid.NewGuid()))),
            ("another endpoint's credential", HttpStatusCode.Unauthorized, b, () => Raw(valid)),
            ("not JSON", HttpStatusCode.UnsupportedMediaType, a, () => Raw(valid, "text/plain")),
            ("Content-Length over the cap", HttpStatusCode.RequestEntityTooLarge, a, () => Raw(oversized)),
            ("chunked body over the cap", HttpStatusCode.RequestEntityTooLarge, a, () => Chunked(probe with
            {
                AgentVersion = new string('x', SecurityEventContract.MaxRequestBytes)
            })),
            ("malformed JSON", HttpStatusCode.BadRequest, a, () => Raw(valid[..^2])),
            ("invalid UTF-8", HttpStatusCode.BadRequest, a, () => InvalidUtf8(valid)),
            ("duplicate key", HttpStatusCode.BadRequest, a,
                () => Raw(valid.Insert(1, $"\"format\":\"{SecurityEventContract.Format}\","))),
            ("null for a non-nullable member", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node["agentVersion"] = null))),
            ("missing required member", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node.Remove("format")))),
            ("number as string", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node["events"]![0]!["eventId"] = "7045"))),
            ("excessive depth", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node["testOnlyDeep"] = Nest(10)))),
            ("wrong format", HttpStatusCode.BadRequest, a, () => Json(probe with { Format = "sentinelai-security-events-v0" })),
            ("257 events", HttpStatusCode.BadRequest, a, () => Json(probe with
            {
                Events = Enumerable.Range(1, 257).Select(index => Observation(service, 10_000 + index)).ToArray()
            })),
            ("33 gaps", HttpStatusCode.BadRequest, a, () => Json(probe with
            {
                Gaps = Enumerable.Range(1, 33).Select(index =>
                    Gap(SecurityEventChannels.System, SecurityEventGapReasons.LogReset, 20_000 + index, null)).ToArray()
            })),
            ("9 sources", HttpStatusCode.BadRequest, a, () => Json(probe with
            {
                Sources = Enumerable.Range(0, 9).Select(index => Status($"test-only-channel-{index}")).ToArray()
            })),
            ("duplicate source channel", HttpStatusCode.BadRequest, a, () => Json(probe with
            {
                Sources = [Status(SecurityEventChannels.System), Status(SecurityEventChannels.System)]
            })),
            ("non-UTC sent time", HttpStatusCode.BadRequest, a, () => Json(probe with
            {
                SentUtc = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(2))
            }))
        };

        var baseline = await SnapshotAsync(store, a, b);
        foreach (var (name, expected, agent, content) in cases)
        {
            var tracked = unread.Contains(name) ? new TrackedContent(content()) : null;
            HttpResponseMessage response;
            try
            {
                response = await PostAsync(tracked is null ? client : unreadClient, agent, tracked ?? content(), headers =>
                {
                    headers.ConnectionClose = true;
                    headers.ExpectContinue = tracked is not null;
                });
            }
            catch (HttpRequestException exception)
            {
                throw new InvalidOperationException($"Security event ingest transport failed for: {name}.", exception);
            }
            using (response)
            {
                Check(response.StatusCode == expected,
                    $"Security event ingest returned HTTP {(int)response.StatusCode} instead of {(int)expected} for: {name}.");
                Check(tracked is not { Sent: true }, $"Core read a request body it must refuse unread: {name}.");
            }
        }
        Check(await SnapshotAsync(store, a, b) == baseline, "A rejected security event request changed Core state.");
        // Only authenticated refusals are logged, with the endpoint ID and status code alone (never parser text).
        var refusals = logs.Entries.Where(entry => entry.Level == LogLevel.Warning &&
            entry.Message.Contains("rejected with HTTP", StringComparison.Ordinal)).ToArray();
        var expectedRefusals = cases.Where(item => item.Agent == a && item.Expected != HttpStatusCode.Unauthorized)
            .Select(item => $"Security event batch from endpoint {a.EndpointId:D} rejected with HTTP {(int)item.Expected}")
            .Order(StringComparer.Ordinal);
        Check(refusals.Select(entry => entry.Message).Order(StringComparer.Ordinal).SequenceEqual(expectedRefusals) &&
              refusals.All(entry => entry.Category == typeof(SecurityEventStore).FullName &&
                  entry.Keys.Order(StringComparer.Ordinal).SequenceEqual(["EndpointId", "StatusCode", "{OriginalFormat}"])),
            "Refused security event batches were not logged with only the endpoint ID and status code.");

        // Endpoint clocks are never compared with Core's clock; TASK-028 clamps by receipt time.
        Check(await RecordAsync(client, a, probe with { SentUtc = DateTimeOffset.UtcNow.AddYears(1) }) ==
              new SecurityEventBatchResult(1, 0, 0, 0), "A batch with a far-future Agent clock was rejected.");
        var future = Observation(service, 9100, DateTimeOffset.UtcNow.AddDays(2));
        Check(await RecordAsync(client, a, Batch(a, [future])) == new SecurityEventBatchResult(1, 0, 0, 0) &&
              (await store.ListRecentAsync(a.EndpointId, 1))[0].Observation == future,
            "A future event time was rejected or altered.");
    }

    // C10: status-only administrator route.
    private static async Task VerifyStatusRouteAsync(WebApplication app, HttpClient client, SecurityEventStore store,
        Agent a, string username, string password)
    {
        var token = await LoginAsync(client, username, password);
        using (var anonymous = await client.GetAsync(SourcesPath(a.EndpointId)))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Anonymous event-source status read succeeded.");
        using (var agent = await GetAsync(client, SourcesPath(a.EndpointId), "SentinelAgent", a.Authorization))
            Check(agent.StatusCode == HttpStatusCode.Unauthorized, "An Agent credential granted administrator event-source access.");
        using (var missing = await GetAsync(client, SourcesPath(Guid.NewGuid()), "Bearer", token))
            Check(missing.StatusCode == HttpStatusCode.NotFound && missing.Headers.CacheControl?.NoStore == true,
                "An unknown endpoint fabricated event-source status.");

        using var response = await GetAsync(client, SourcesPath(a.EndpointId), "Bearer", token);
        var body = await response.Content.ReadAsStringAsync();
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            "The event-source status route was unavailable or cacheable.");
        Check(!ContainsSynthetic(body) && !body.Contains(Marker, StringComparison.Ordinal),
            "The event-source status route exposed observation content or identities.");
        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        var sources = root.GetProperty("sources").EnumerateArray().ToArray();
        var gaps = root.GetProperty("recentGaps").EnumerateArray().ToArray();
        Check(Names(root).SequenceEqual(new[] { "endpointId", "recentGaps", "sources" }) &&
              root.GetProperty("endpointId").GetGuid() == a.EndpointId &&
              sources.Length == 4 && sources.All(source => Names(source).SequenceEqual(SourceProperties.Order(StringComparer.Ordinal))) &&
              gaps.Length > 0 && gaps.All(gap => Names(gap).SequenceEqual(GapProperties.Order(StringComparer.Ordinal))),
            "The event-source status route did not return exactly the documented status properties.");

        var counts = (await QueryAsync(app, """
            SELECT Channel, COUNT(*) FROM SecurityEventObservations WHERE EndpointId = $e GROUP BY Channel;
            """, a.EndpointId)).ToDictionary(row => row[0], row => long.Parse(row[1], CultureInfo.InvariantCulture));
        Check(sources.All(source => source.GetProperty("storedObservations").GetInt64() ==
                  counts.GetValueOrDefault(source.GetProperty("channel").GetString()!)) &&
              counts.Values.Sum() == await store.CountAsync(a.EndpointId),
            "The event-source status route reported incorrect stored observation counts.");
        var expectedGaps = await store.ListGapsAsync(a.EndpointId, 50);
        Check(gaps.Length == expectedGaps.Count && gaps.Zip(expectedGaps).All(pair =>
                  pair.First.GetProperty("channel").GetString() == pair.Second.Channel &&
                  pair.First.GetProperty("reason").GetString() == pair.Second.Reason &&
                  pair.First.GetProperty("firstRecordId").GetInt64() == pair.Second.FirstRecordId &&
                  pair.First.GetProperty("coverageRestart").GetBoolean() == pair.Second.CoverageRestart),
            "The event-source status route did not return the newest stored gaps.");

        var idle = await EnrollAsync(app);
        using var empty = await GetAsync(client, SourcesPath(idle.EndpointId), "Bearer", token);
        using var emptyJson = JsonDocument.Parse(await empty.Content.ReadAsStringAsync());
        Check(empty.StatusCode == HttpStatusCode.OK &&
              emptyJson.RootElement.GetProperty("sources").GetArrayLength() == 0 &&
              emptyJson.RootElement.GetProperty("recentGaps").GetArrayLength() == 0,
            "An endpoint without event status did not return an explicit empty status view.");

        // The route lists at most the 50 newest gaps.
        var lossy = await EnrollAsync(app);
        foreach (var start in new[] { 1, 33 })
        {
            await RecordAsync(client, lossy, Batch(lossy, gaps: Enumerable.Range(start, 32).Select(first =>
                Gap(SecurityEventChannels.System, SecurityEventGapReasons.Dropped, first, first)).ToArray()));
        }
        using var bounded = await GetAsync(client, SourcesPath(lossy.EndpointId), "Bearer", token);
        using var boundedJson = JsonDocument.Parse(await bounded.Content.ReadAsStringAsync());
        Check(bounded.StatusCode == HttpStatusCode.OK &&
              boundedJson.RootElement.GetProperty("recentGaps").EnumerateArray()
                  .Select(gap => gap.GetProperty("firstRecordId").GetInt64())
                  .SequenceEqual(Enumerable.Range(15, 50).Reverse().Select(first => (long)first)),
            "The event-source status route did not list exactly the 50 newest gaps.");
    }

    // C11: concurrent IMMEDIATE writers and a concurrent status reader.
    private static async Task VerifyConcurrencyAsync(string directory, string username, string password,
        CapturingLoggerProvider logs)
    {
        await using var app = Build(directory, logs);
        using var client = await StartAsync(app);
        var store = app.Services.GetRequiredService<SecurityEventStore>();
        var token = await LoginAsync(client, username, password);
        Agent[] endpoints = [await EnrollAsync(app), await EnrollAsync(app)];
        var service = Selection(7045);
        using var stop = new CancellationTokenSource();
        var readStatuses = new ConcurrentBag<HttpStatusCode>();
        var reader = Task.Run(async () =>
        {
            do
            {
                foreach (var endpoint in endpoints)
                {
                    using var response = await GetAsync(client, SourcesPath(endpoint.EndpointId), "Bearer", token);
                    readStatuses.Add(response.StatusCode);
                }
            } while (!stop.IsCancellationRequested);
        });
        var posters = endpoints.SelectMany(endpoint => Enumerable.Range(0, 2).Select(poster => Task.Run(async () =>
        {
            for (var batch = 0; batch < 10; batch++)
            {
                var offset = 1 + poster * 1000 + batch * 10;
                var result = await RecordAsync(client, endpoint, Batch(endpoint,
                    Enumerable.Range(0, 5).Select(index => Observation(service, offset + index)).ToArray(),
                    [Gap(SecurityEventChannels.System, SecurityEventGapReasons.Dropped, 50_000 + offset, 50_000 + offset)],
                    [Status(SecurityEventChannels.System)]));
                Check(result == new SecurityEventBatchResult(5, 0, 0, 0), "A concurrent batch was not fully accepted.");
            }
        }))).ToArray();
        await Task.WhenAll(posters);
        await stop.CancelAsync();
        await reader;
        Check(!readStatuses.IsEmpty && readStatuses.All(status => status == HttpStatusCode.OK),
            "A concurrent event-source status read failed while batches were committed.");
        foreach (var endpoint in endpoints)
        {
            Check(await store.CountAsync(endpoint.EndpointId) == 100 &&
                  (await store.ListGapsAsync(endpoint.EndpointId, 500)).Count == 20,
                "Concurrent batches lost or duplicated observations or gaps.");
        }
    }

    // C9: the 61st request inside one window is refused before any work.
    private static async Task VerifyRateLimitAsync(string directory, CapturingLoggerProvider logs)
    {
        await using var app = Build(directory, logs);
        using var client = await StartAsync(app);
        var agent = await EnrollAsync(app);
        for (var request = 0; request < 60; request++)
        {
            using var accepted = await PostAsync(client, agent, Json(Batch(agent, sources: [Status(SecurityEventChannels.System)])));
            Check(accepted.StatusCode == HttpStatusCode.OK, "A security event request within the rate window was refused.");
        }
        using var limited = await PostAsync(client, agent, Json(Batch(agent, sources: [Status(SecurityEventChannels.System)])));
        Check(limited.StatusCode == HttpStatusCode.TooManyRequests, "The security event rate policy did not refuse the 61st request.");
    }

    // C7: per-endpoint caps, bounded receipt-time sweeps and the startup sweep.
    private static async Task VerifyRetentionAsync(string directory, CapturingLoggerProvider logs)
    {
        var retention = new SecurityEventRetention(5, TimeSpan.FromDays(1), 2, 3, 2, 10);
        var clock = new ManualTime(DateTimeOffset.UtcNow);
        var service = Selection(7045);
        Agent a, b;
        await using (var app = Build(directory, logs, builder =>
                     {
                         builder.Services.AddSingleton<TimeProvider>(clock);
                         builder.Services.AddSingleton(retention);
                     }))
        {
            using var client = await StartAsync(app);
            var store = app.Services.GetRequiredService<SecurityEventStore>();
            a = await EnrollAsync(app);
            b = await EnrollAsync(app);
            Check(await RecordAsync(client, a, Batch(a, Enumerable.Range(1, 8).Select(index => Observation(service, index)).ToArray())) ==
                  new SecurityEventBatchResult(8, 0, 0, 0) &&
                  (await store.ListRecentAsync(a.EndpointId, 100)).Select(row => row.Observation.RecordId).Order()
                      .SequenceEqual([4L, 5, 6, 7, 8]),
                "The per-endpoint cap did not keep exactly the newest observations.");
            clock.Advance(TimeSpan.FromMinutes(1));
            await RecordAsync(client, a, Batch(a, gaps: Enumerable.Range(1, 5).Select(index =>
                Gap(SecurityEventChannels.System, SecurityEventGapReasons.LogReset, 100 + index, null)).ToArray()));
            Check((await store.ListGapsAsync(a.EndpointId, 500)).Select(gap => gap.FirstRecordId).Order()
                  .SequenceEqual([103L, 104, 105]), "The per-endpoint gap cap did not keep exactly the newest gaps.");
            clock.Advance(TimeSpan.FromMinutes(1));
            await RecordAsync(client, b, Batch(b, Enumerable.Range(1, 3).Select(index => Observation(service, index)).ToArray()));
            Check(await store.CountAsync(b.EndpointId) == 3 && await store.CountAsync(a.EndpointId) == 5,
                "One endpoint's retention cap affected another endpoint.");

            clock.Advance(TimeSpan.FromDays(2));
            foreach (var (observations, gaps, recordId) in new[] { (3L, 1, 101L), (1L, 0, 102L) })
            {
                await RecordAsync(client, b, Batch(b, [Observation(service, recordId)]));
                Check(await store.CountAsync(a.EndpointId) == observations &&
                      (await store.ListGapsAsync(a.EndpointId, 500)).Count == gaps,
                    "The receipt-time sweep was not bounded per ingest or skipped endpoints that stopped reporting.");
            }
            Check(await store.CountAsync(b.EndpointId) == 5, "The bounded sweep removed newer observations first.");
        }

        await using (var restarted = Build(directory, logs, builder =>
                     {
                         builder.Services.AddSingleton<TimeProvider>(new ManualTime(clock.GetUtcNow()));
                         builder.Services.AddSingleton(retention);
                     }))
        {
            using var client = await StartAsync(restarted);
            var store = restarted.Services.GetRequiredService<SecurityEventStore>();
            Check(await store.CountAsync(a.EndpointId) == 0 &&
                  (await store.ListRecentAsync(b.EndpointId, 10)).Select(row => row.Observation.RecordId).Order()
                      .SequenceEqual([101L, 102]),
                "The startup sweep did not remove aged observations.");
        }
    }

    private static SecurityEventBatch Batch(Agent agent, IReadOnlyList<SecurityEventObservation>? events = null,
        IReadOnlyList<SecurityEventGap>? gaps = null, IReadOnlyList<SecurityEventSourceStatus>? sources = null) =>
        new(agent.EndpointId, SecurityEventContract.Format, AgentVersion, DateTimeOffset.UtcNow, CountersSince,
            sources ?? [], gaps ?? [], events ?? []);

    private static SecurityEventSelection Selection(int eventId) =>
        SecurityEventContract.Catalog.First(selection => selection.EventId == eventId);

    private static DateTimeOffset EventTime(long recordId) => EventEpoch.AddSeconds(recordId).AddTicks(1234567);

    private static SecurityEventObservation Observation(SecurityEventSelection selection, long recordId,
        DateTimeOffset? timeCreated = null)
    {
        var observation = new SecurityEventObservation(selection.Channel, selection.Provider, selection.EventId, 0,
            selection.Kind == SecurityEventKinds.ScriptBlockFlagged ? 3 : 4, recordId, timeCreated ?? EventTime(recordId),
            selection.Kind);
        var threat = new MalwareEvent(Guid.Parse("4d8f6a2e-1f3b-4c5d-9e7f-0a1b2c3d4e5f"), 2147735505, "test-only-threat",
            5, 8, null, null);
        return selection.Kind switch
        {
            SecurityEventKinds.LogonSucceeded => observation with
            {
                Logon = new LogonEvent(10, "S-1-5-21-1000-1000-1000-1001", "192.0.2.10", null, null, true)
            },
            SecurityEventKinds.LogonFailed => observation with
            {
                Logon = new LogonEvent(3, "S-1-5-21-1000-1000-1000-1002", "2001:db8::2", 3221225581, 3221225572, null)
            },
            SecurityEventKinds.ScheduledTaskCreated => observation with
            {
                ScheduledTask = new ScheduledTaskEvent(@"\test-only-task", "S-1-5-21-1000-1000-1000-1003")
            },
            SecurityEventKinds.LogCleared => observation with
            {
                LogCleared = new LogClearedEvent(selection.Channel == SecurityEventChannels.Security ? "Security" : "test-only-log")
            },
            SecurityEventKinds.ServiceInstalled => observation with
            {
                ServiceInstall = new ServiceInstallEvent("test-only-service", "svc.exe", ServiceImageLocations.ProgramFiles,
                    ServiceTypes.UserModeService, ServiceStartTypes.Demand, ServiceAccountKinds.LocalSystem)
            },
            SecurityEventKinds.ProtectionServiceStartTypeChanged => observation with
            {
                ServiceStartType = new ServiceStartTypeEvent("WinDefend", ServiceStartTypes.Disabled)
            },
            SecurityEventKinds.ScriptBlockFlagged => observation with
            {
                ScriptBlock = new ScriptBlockEvent(Guid.Parse("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"), 1)
            },
            SecurityEventKinds.MalwareDetected => observation with { Malware = threat },
            SecurityEventKinds.MalwareActionTaken => observation with { Malware = threat with { ActionId = 2 } },
            SecurityEventKinds.MalwareActionFailed => observation with { Malware = threat with { ActionId = 2, ErrorCode = 2147942402 } },
            SecurityEventKinds.DefenderSettingChanged => observation with
            {
                DefenderSetting = new DefenderSettingEvent(DefenderSettingAreas.ExclusionPath, DefenderSettingChanges.Added)
            },
            _ => observation
        };
    }

    private static SecurityEventGap Gap(string channel, string reason, long first, long? last, string? cause = null) =>
        new(channel, reason, first, last, DateTimeOffset.UtcNow, cause);

    private static SecurityEventSourceStatus Status(string channel, string state = SecurityEventSourceStates.Collecting,
        long? checkpoint = 100) =>
        new(channel, state, state == SecurityEventSourceStates.Error ? unchecked((int)0x800705B4) : null, 1, 120, checkpoint,
            20L * 1024 * 1024, DateTimeOffset.UtcNow, 120, 16, 16, 0, 0, 0, 0, 0, 0);

    private static async Task<string> SnapshotAsync(SecurityEventStore store, params Agent[] agents)
    {
        var state = new List<object>();
        foreach (var agent in agents)
        {
            state.Add(await store.CountAsync(agent.EndpointId));
            state.Add(await store.ListGapsAsync(agent.EndpointId, 500));
            state.Add(await store.ListSourcesAsync(agent.EndpointId));
        }

        return JsonSerializer.Serialize(state);
    }

    private static async Task<SecurityEventBatchResult> RecordAsync(HttpClient client, Agent agent, SecurityEventBatch batch)
    {
        // The Agent's own wire form: streamed JSON without a Content-Length.
        using var response = await PostAsync(client, agent, JsonContent.Create(batch, options: SecurityEventContract.Json));
        Check(response.StatusCode == HttpStatusCode.OK,
            $"Core refused a security event batch with HTTP {(int)response.StatusCode}.");
        return await response.Content.ReadFromJsonAsync<SecurityEventBatchResult>(SecurityEventContract.Json)
               ?? throw new InvalidOperationException("Core returned no security event batch result.");
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, Agent? agent, HttpContent content,
        Action<HttpRequestHeaders>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, IngestPath) { Content = content };
        if (agent is not null) request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
        configure?.Invoke(request.Headers);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string scheme, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        return await client.SendAsync(request);
    }

    private static HttpContent Json(SecurityEventBatch batch) =>
        new StringContent(JsonSerializer.Serialize(batch, SecurityEventContract.Json), Encoding.UTF8, "application/json");

    private static HttpContent Raw(string json, string mediaType = "application/json") =>
        new StringContent(json, Encoding.UTF8, mediaType);

    private static HttpContent Chunked(SecurityEventBatch batch)
    {
        // JsonContent streams without a Content-Length, exercising the reader's own byte cap.
        var content = JsonContent.Create(batch, options: SecurityEventContract.Json);
        Check(content.Headers.ContentLength is null, "The chunked test body unexpectedly declared its length.");
        return content;
    }

    private static HttpContent InvalidUtf8(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var start = bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(AgentVersion));
        Check(start > 0, "The invalid UTF-8 fixture could not locate its string value.");
        bytes[start] = 0xFF;
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static JsonNode Nest(int depth)
    {
        JsonNode node = new JsonObject();
        for (var level = 0; level < depth; level++) node = new JsonObject { ["level"] = node };
        return node;
    }

    private static IEnumerable<string> Names(JsonElement element) =>
        element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal);

    private static async Task<List<string[]>> QueryAsync(WebApplication app, string sql, Guid endpointId)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath,
            Mode = SqliteOpenMode.ReadOnly
        };
        await using var connection = new SqliteConnection(connectionString.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        var rows = new List<string[]>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            rows.Add(Enumerable.Range(0, reader.FieldCount)
                .Select(index => Convert.ToString(reader.GetValue(index), CultureInfo.InvariantCulture) ?? string.Empty)
                .ToArray());
        }

        return rows;
    }

    private static string Invariant(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static bool ContainsSynthetic(string text) =>
        text.Contains(Marker, StringComparison.Ordinal) ||
        SyntheticValues.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static string SourcesPath(Guid endpointId) => $"/api/admin/devices/{endpointId:D}/event-sources";

    private static WebApplication Build(string directory, CapturingLoggerProvider logs,
        Action<WebApplicationBuilder>? configure = null) =>
        CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"], builder =>
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logs);
            configure?.Invoke(builder);
        });

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private static async Task<Agent> EnrollAsync(WebApplication app)
    {
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrollment = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        var response = enrollment.Response ?? throw new InvalidOperationException("A synthetic event endpoint could not enroll.");
        return new Agent(response.EndpointId, response.AgentCredential);
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "The security event test administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    // Records whether the client transmitted the body; with Expect: 100-continue that happens only once Core reads.
    private sealed class TrackedContent : HttpContent
    {
        private readonly HttpContent _inner;

        public TrackedContent(HttpContent inner)
        {
            Check(inner.Headers.ContentLength > 1024, "A body that must stay unread would be sent after an error response.");
            _inner = inner;
            Headers.ContentType = inner.Headers.ContentType;
        }

        public bool Sent { get; private set; }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            Sent = true;
            await _inner.CopyToAsync(stream);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _inner.Headers.ContentLength ?? -1;
            return length >= 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class ManualTime(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed record LogEntry(string Category, LogLevel Level, string Message, IReadOnlyList<string> Keys);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();
        public IReadOnlyCollection<LogEntry> Entries => _entries;
        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
        public void Dispose() { }

        private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var keys = state is IReadOnlyList<KeyValuePair<string, object?>> values
                    ? values.Select(value => value.Key).ToArray()
                    : [];
                owner._entries.Enqueue(new LogEntry(category, logLevel, formatter(state, exception) + exception, keys));
            }
        }
    }
}
