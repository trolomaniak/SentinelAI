using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using SentinelAI.Agent;
using SentinelAI.Contracts.SecurityEvents;

/// <summary>
/// In-memory event log per catalog channel. Open returns exactly the records the generated server
/// query selects (catalog matches plus the anchor and newest members) and enforces the native seek
/// precondition against the last Describe, so pipeline bugs surface as exceptions.
/// </summary>
internal sealed class SyntheticEventLog : IEventLogAccess
{
    public const string NoiseProvider = "SentinelAI-Test-Noise";
    // A field value whose rendering throws, as a native render failure would.
    public static readonly object RenderFailure = new();
    private static readonly DateTimeOffset Origin = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly object _gate = new();
    private readonly SecurityEventCatalog _catalog;
    private readonly Dictionary<string, ChannelLog> _channels;
    private readonly ConcurrentDictionary<string, byte> _requestedFieldNames = new(StringComparer.Ordinal);
    private int _describeCalls;
    private int _openCalls;
    private int _readNewestCalls;
    private int _recordsYielded;

    public SyntheticEventLog(SecurityEventCatalog? catalog = null)
    {
        _catalog = catalog ?? SecurityEventCatalog.Production;
        _channels = _catalog.ChannelNames.ToDictionary(channel => channel, _ => new ChannelLog(), StringComparer.Ordinal);
    }

    public bool IsSupported => true;
    public IReadOnlyList<string> Channels => _catalog.ChannelNames;
    public int DescribeCalls => Volatile.Read(ref _describeCalls);
    public int OpenCalls => Volatile.Read(ref _openCalls);
    public int ReadNewestCalls => Volatile.Read(ref _readNewestCalls);
    public int RecordsYielded => Volatile.Read(ref _recordsYielded);
    public IReadOnlyCollection<string> RequestedFieldNames => _requestedFieldNames.Keys.ToArray();

    /// <summary>Runs after the seek precondition check and before the result set is taken (races).</summary>
    public Action<string>? BeforeOpen { get; set; }

    /// <summary>When set, appending beyond this many records overwrites the oldest.</summary>
    public int? Capacity { get; set; }

    public static DateTimeOffset TimeOf(int generation, long recordId) =>
        Origin + TimeSpan.FromDays(generation) + TimeSpan.FromSeconds(recordId) + TimeSpan.FromTicks(1234567);

    public long Append(string channel, string provider, int eventId, IReadOnlyDictionary<string, object?>? fields = null,
        int? level = 4, int version = 0, bool withoutTime = false)
    {
        lock (_gate)
        {
            var log = _channels[channel];
            var id = log.NextId++;
            log.Records.Add(new SyntheticRecord(id, log.Generation, provider, eventId, version, level,
                withoutTime ? null : TimeOf(log.Generation, id), fields ?? new Dictionary<string, object?>()));
            if (Capacity is { } capacity && log.Records.Count > capacity) log.Records.RemoveAt(0);
            return id;
        }
    }

    public void AppendNoise(string channel, int count)
    {
        for (var index = 0; index < count; index++) Append(channel, NoiseProvider, 1000 + index % 7);
    }

    /// <summary>Overwrites every record up to and including <paramref name="throughId"/>.</summary>
    public void Trim(string channel, long throughId)
    {
        lock (_gate)
        {
            _channels[channel].Records.RemoveAll(record => record.Id <= throughId);
        }
    }

    /// <summary>Clears the log into a new generation; record numbers restart at 1 or continue.</summary>
    public void Clear(string channel, bool restartIds)
    {
        lock (_gate)
        {
            var log = _channels[channel];
            log.Records.Clear();
            log.Generation++;
            if (restartIds) log.NextId = 1;
        }
    }

    public int Generation(string channel)
    {
        lock (_gate)
        {
            return _channels[channel].Generation;
        }
    }

    public IReadOnlyList<SyntheticRecord> Records(string channel)
    {
        lock (_gate)
        {
            return _channels[channel].Records.ToArray();
        }
    }

    public (long? Oldest, long? Newest) Extent(string channel)
    {
        lock (_gate)
        {
            var records = _channels[channel].Records;
            return records.Count == 0 ? (null, null) : (records[0].Id, records[^1].Id);
        }
    }

    public void SetUnavailable(string channel, string? state, int hresult = 0)
    {
        lock (_gate)
        {
            _channels[channel].Unavailable = state is null ? null : (state, hresult);
        }
    }

    public void ThrowOnDescribe(string channel, Exception? exception)
    {
        lock (_gate)
        {
            _channels[channel].DescribeFailure = exception;
        }
    }

    public void ThrowOnOpen(string channel, Exception? exception)
    {
        lock (_gate)
        {
            _channels[channel].OpenFailure = exception;
        }
    }

    public void FailBookmarkSeek(string channel, bool fail)
    {
        lock (_gate)
        {
            _channels[channel].FailBookmarkSeek = fail;
        }
    }

    /// <summary>The next seek lands after the anchor, as an undocumented non-member seek might.</summary>
    public void DropAnchorOnce(string channel)
    {
        lock (_gate)
        {
            _channels[channel].DropAnchorOnce = true;
        }
    }

    /// <summary>The next seek lands this many result-set records before the anchor (an undocumented landing).</summary>
    public void SeekLandsEarlyOnce(string channel, int records)
    {
        lock (_gate)
        {
            _channels[channel].SeekLandsEarly = records;
        }
    }

    /// <summary>Reading the given record throws once, as a timed-out or failed native read would.</summary>
    public void ThrowOnReadOnce(string channel, long recordId, Exception exception)
    {
        lock (_gate)
        {
            _channels[channel].ReadFailure = (recordId, exception);
        }
    }

    public void SetEnabled(string channel, bool? enabled)
    {
        lock (_gate)
        {
            _channels[channel].Enabled = enabled;
        }
    }

    public int DescribeCallsFor(string channel)
    {
        lock (_gate)
        {
            return _channels[channel].DescribeCalls;
        }
    }

    public ChannelExtent Describe(string channel)
    {
        lock (_gate)
        {
            var log = _channels[channel];
            Interlocked.Increment(ref _describeCalls);
            log.DescribeCalls++;
            ThrowIfUnavailable(log);
            if (log.DescribeFailure is { } failure) throw failure;
            var records = log.Records;
            log.LastDescribed = records.Count == 0 ? (null, null) : (records[0].Id, records[^1].Id);
            return new ChannelExtent(log.LastDescribed.Value.Oldest, log.LastDescribed.Value.Newest, 20 * 1024 * 1024,
                log.Enabled);
        }
    }

    public EventRecordHeader? ReadNewest(string channel)
    {
        lock (_gate)
        {
            var log = _channels[channel];
            Interlocked.Increment(ref _readNewestCalls);
            ThrowIfUnavailable(log);
            return log.Records.Count == 0 ? null : Header(log.Records[^1]);
        }
    }

    public IEventRecordCursor Open(string channel, long? after, long through, bool forceFallback = false)
    {
        bool fallback;
        bool dropAnchor;
        int early;
        lock (_gate)
        {
            var log = _channels[channel];
            Interlocked.Increment(ref _openCalls);
            ThrowIfUnavailable(log);
            if (log.OpenFailure is { } failure) throw failure;
            var (oldest, newest) = log.LastDescribed ?? (log.Records.FirstOrDefault()?.Id, log.Records.LastOrDefault()?.Id);
            if (after is { } anchor && (oldest is null || newest is null || anchor < oldest || anchor > newest))
                throw new InvalidOperationException("Open was called with an anchor outside the described log.");
            fallback = after is not null && (forceFallback || log.FailBookmarkSeek);
            dropAnchor = after is not null && !fallback && log.DropAnchorOnce;
            if (dropAnchor) log.DropAnchorOnce = false;
            early = after is not null && !fallback ? log.SeekLandsEarly : 0;
            log.SeekLandsEarly = 0;
        }

        BeforeOpen?.Invoke(channel);
        lock (_gate)
        {
            var log = _channels[channel];
            var selected = log.Records.Where(record =>
                    _catalog.MatchesHeader(channel, record.Provider, record.EventId, record.Level) ||
                    record.Id == after || record.Id == through)
                .ToList();
            var first = after is null ? 0 : selected.FindIndex(record => record.Id >= after);
            if (first < 0) first = selected.Count;
            var records = selected.Skip(Math.Max(0, first - early)).Where(record => !(dropAnchor && record.Id == after))
                .ToArray();
            return new Cursor(this, log, records, fallback);
        }
    }

    public void CancelPending()
    {
    }

    public void Dispose()
    {
    }

    private static void ThrowIfUnavailable(ChannelLog log)
    {
        if (log.Unavailable is { } unavailable)
            throw new EventChannelUnavailableException(unavailable.State, unavailable.HResult);
    }

    private static EventRecordHeader Header(SyntheticRecord record) =>
        new(record.Id, record.Provider, record.EventId, record.Version, record.Level, record.TimeCreated);

    // Mirrors the adapter's portable conversion for the value types fixtures use.
    private static object? Portable(object? value) => value switch
    {
        string text => text.Length > SecurityEventNormalizer.MaxFieldChars ? EventFieldValue.Oversize : text,
        int number => (long)number,
        uint number => (long)number,
        long or Guid or null => value,
        _ when ReferenceEquals(value, EventFieldValue.Oversize) => value,
        _ => null
    };

    public sealed record SyntheticRecord(long Id, int Generation, string Provider, int EventId, int Version, int? Level,
        DateTimeOffset? TimeCreated, IReadOnlyDictionary<string, object?> Fields);

    private sealed class ChannelLog
    {
        public List<SyntheticRecord> Records { get; } = [];
        public long NextId { get; set; } = 1;
        public int Generation { get; set; }
        public (long? Oldest, long? Newest)? LastDescribed { get; set; }
        public (string State, int HResult)? Unavailable { get; set; }
        public Exception? DescribeFailure { get; set; }
        public Exception? OpenFailure { get; set; }
        public bool FailBookmarkSeek { get; set; }
        public bool DropAnchorOnce { get; set; }
        public int SeekLandsEarly { get; set; }
        public (long RecordId, Exception Exception)? ReadFailure { get; set; }
        public bool? Enabled { get; set; } = true;
        public int DescribeCalls { get; set; }
    }

    private sealed class Cursor(SyntheticEventLog owner, ChannelLog log, SyntheticRecord[] records, bool usedFallback)
        : IEventRecordCursor
    {
        private int _index = -1;

        public bool UsedFallback => usedFallback;

        public bool TryNext(out EventRecordHeader header)
        {
            header = default;
            if (_index >= records.Length) return false;
            lock (owner._gate)
            {
                if (_index + 1 < records.Length && log.ReadFailure is { } failure && records[_index + 1].Id == failure.RecordId)
                {
                    log.ReadFailure = null;
                    throw failure.Exception;
                }
            }

            _index++;
            if (_index >= records.Length) return false;
            Interlocked.Increment(ref owner._recordsYielded);
            header = Header(records[_index]);
            return true;
        }

        public IReadOnlyList<object?> ReadFields(EventFieldSet fields)
        {
            if (_index < 0 || _index >= records.Length) throw new InvalidOperationException("No current record.");
            var values = new object?[fields.Fields.Count];
            for (var index = 0; index < values.Length; index++)
            {
                owner._requestedFieldNames.TryAdd(fields.Fields[index].Name, 0);
                records[_index].Fields.TryGetValue(fields.Fields[index].Name, out var value);
                if (ReferenceEquals(value, RenderFailure))
                    throw new InvalidDataException(SecurityEventFixtures.Marker);
                values[index] = Portable(value);
            }

            return values;
        }

        public void Dispose()
        {
        }
    }
}

internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private long _ticks = start.UtcTicks;

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

/// <summary>Returns scripted outcomes (Accepted when the script is empty) and records every attempt.</summary>
internal sealed class ScriptedUploader : ISecurityEventUploader
{
    private readonly object _gate = new();
    private readonly Queue<UploadOutcome> _outcomes = new();
    private readonly List<SecurityEventBatch> _attempts = [];
    private readonly List<SecurityEventBatch> _accepted = [];

    public static UploadOutcome Accepted => new(UploadResult.Accepted, 200, null);
    public static UploadOutcome Failed => new(UploadResult.Failed, 503, null);
    public static UploadOutcome Incompatible(int status) => new(UploadResult.Incompatible, status, null);

    /// <summary>Thrown by the next attempt instead of returning an outcome, as an unexpected client failure.</summary>
    public Exception? ThrowNext { get; set; }

    public IReadOnlyList<SecurityEventBatch> Attempts
    {
        get
        {
            lock (_gate)
            {
                return _attempts.ToArray();
            }
        }
    }

    public IReadOnlyList<SecurityEventBatch> AcceptedBatches
    {
        get
        {
            lock (_gate)
            {
                return _accepted.ToArray();
            }
        }
    }

    public void Enqueue(params UploadOutcome[] outcomes)
    {
        lock (_gate)
        {
            foreach (var outcome in outcomes) _outcomes.Enqueue(outcome);
        }
    }

    public Task<UploadOutcome> SendAsync(SecurityEventBatch batch, EnrollmentState enrollment,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _attempts.Add(batch);
            if (ThrowNext is { } failure)
            {
                ThrowNext = null;
                throw failure;
            }

            var outcome = _outcomes.Count > 0 ? _outcomes.Dequeue() : Accepted;
            if (outcome.Result == UploadResult.Accepted) _accepted.Add(batch);
            return Task.FromResult(outcome);
        }
    }
}

/// <summary>
/// Core's ingest semantics in memory with the shared validator: the unique observation key, gap
/// merge and coverage-restart flag. Scripted failures, incompatibility and lost acknowledgements.
/// </summary>
internal sealed class FakeCoreSink : ISecurityEventUploader
{
    private readonly object _gate = new();
    private readonly HashSet<string> _covered = new(StringComparer.Ordinal);

    public Dictionary<(string Channel, long RecordId, long Ticks), SecurityEventObservation> Rows { get; } = [];
    public Dictionary<(string Channel, string Reason, long First), SinkGap> Gaps { get; } = [];
    public List<SecurityEventGap> ReceivedGaps { get; } = [];
    public Dictionary<string, SecurityEventSourceStatus> Sources { get; } = new(StringComparer.Ordinal);
    public int FailNext { get; set; }
    public int IncompatibleNext { get; set; }
    public int LoseNextAcknowledgements { get; set; }
    public int Attempts { get; private set; }
    public int Duplicates { get; private set; }
    public int Rejected { get; private set; }

    public Task<UploadOutcome> SendAsync(SecurityEventBatch batch, EnrollmentState enrollment,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Attempts++;
            if (FailNext > 0)
            {
                FailNext--;
                return Task.FromResult(new UploadOutcome(UploadResult.Failed, 503, null));
            }

            if (IncompatibleNext > 0)
            {
                IncompatibleNext--;
                return Task.FromResult(new UploadOutcome(UploadResult.Incompatible, 404, null));
            }

            if (!SecurityEventContract.IsValidEnvelope(batch) || batch.EndpointId != enrollment.EndpointId)
                return Task.FromResult(new UploadOutcome(UploadResult.Incompatible, 400, null));

            int accepted = 0, duplicates = 0, ignored = 0, rejected = 0;
            foreach (var gap in batch.Gaps)
            {
                switch (SecurityEventContract.Classify(gap))
                {
                    case SecurityEventItemValidity.Unknown:
                        ignored++;
                        continue;
                    case SecurityEventItemValidity.Invalid:
                        rejected++;
                        continue;
                }

                ReceivedGaps.Add(gap);
                var key = (gap.Channel, gap.Reason, gap.FirstRecordId);
                var restart = gap.Reason == SecurityEventGapReasons.CoverageStarted && _covered.Contains(gap.Channel);
                if (Gaps.TryGetValue(key, out var existing))
                {
                    var last = existing.LastRecordId is null || gap.LastRecordId is null
                        ? existing.LastRecordId ?? gap.LastRecordId
                        : Math.Max(existing.LastRecordId.Value, gap.LastRecordId.Value);
                    Gaps[key] = existing with { LastRecordId = last };
                }
                else
                {
                    Gaps[key] = new SinkGap(gap.LastRecordId, gap.Cause, restart, gap.DetectedUtc);
                }
            }

            foreach (var observation in batch.Events)
            {
                switch (SecurityEventContract.Classify(observation))
                {
                    case SecurityEventItemValidity.Unknown:
                        ignored++;
                        continue;
                    case SecurityEventItemValidity.Invalid:
                        rejected++;
                        Rejected++;
                        continue;
                }

                if (Rows.TryAdd((observation.Channel, observation.RecordId, observation.TimeCreatedUtc.UtcTicks), observation))
                {
                    accepted++;
                }
                else
                {
                    duplicates++;
                    Duplicates++;
                }
            }

            foreach (var source in batch.Sources)
            {
                if (SecurityEventContract.Classify(source) != SecurityEventItemValidity.Valid) continue;
                Sources[source.Channel] = source;
                if (source.CheckpointRecordId is not null) _covered.Add(source.Channel);
            }

            if (LoseNextAcknowledgements > 0)
            {
                // Committed, but the acknowledgement never reaches the Agent.
                LoseNextAcknowledgements--;
                return Task.FromResult(new UploadOutcome(UploadResult.Failed, null, null));
            }

            return Task.FromResult(new UploadOutcome(UploadResult.Accepted, 200,
                new SecurityEventBatchResult(accepted, duplicates, ignored, rejected)));
        }
    }

    public sealed record SinkGap(long? LastRecordId, string? Cause, bool CoverageRestart, DateTimeOffset DetectedUtc);
}

/// <summary>
/// Synthetic raw records, one positive per selection, each carrying markers in fields that must never
/// be collected. SIDs, IPs and names follow the test-only conventions.
/// </summary>
internal static class SecurityEventFixtures
{
    public static readonly string Marker = $"test-only-secret-{Guid.NewGuid():N}";
    public const string UserSid = "S-1-5-21-1000-1000-1000-1001";
    public const string SubjectSid = "S-1-5-21-1000-1000-1000-1002";
    public const string RemoteIp = "192.0.2.10";
    public static readonly Guid ScriptBlockId = Guid.Parse("6f1b3c2a-0000-4000-8000-00000000a001");
    public static readonly Guid DetectionId = Guid.Parse("6f1b3c2a-0000-4000-8000-00000000b001");

    public static IReadOnlyList<string> ExcludedFields { get; } =
    [
        "TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName", "WorkstationName",
        "ScriptBlockText", "Path", "TaskContent", "Process Name", "Detection User", "Remediation User", "FWLink",
        "IpPort", "LogonGuid", "AuthenticationPackageName", "param1", "param2"
    ];

    public static IReadOnlyList<Fixture> Positive { get; } =
    [
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4624, 0, 2, new()
        {
            ["LogonType"] = 10, ["TargetUserSid"] = UserSid, ["IpAddress"] = RemoteIp, ["ElevatedToken"] = "%%1842",
            ["TargetUserName"] = Marker, ["TargetDomainName"] = Marker, ["WorkstationName"] = Marker,
            ["LogonGuid"] = Marker, ["IpPort"] = Marker, ["AuthenticationPackageName"] = Marker
        }),
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4625, 0, 0, new()
        {
            ["LogonType"] = 3, ["TargetUserSid"] = "S-1-0-0", ["IpAddress"] = "2001:db8::10",
            ["Status"] = -1073741715, ["SubStatus"] = "0xC000006A", ["TargetUserName"] = Marker,
            ["SubjectUserName"] = Marker, ["WorkstationName"] = Marker
        }),
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4698, 0, 0, new()
        {
            ["TaskName"] = @"\test-only-task", ["SubjectUserSid"] = SubjectSid, ["TaskContent"] = Marker,
            ["SubjectUserName"] = Marker
        }),
        new(SecurityEventChannels.Security, SecurityEventProviders.Eventlog, 1102, 4, 0, new()
        {
            ["SubjectUserName"] = Marker, ["SubjectDomainName"] = Marker
        }),
        new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7045, 4, 0, new()
        {
            ["ServiceName"] = "test-only-service",
            ["ImagePath"] = "\"C:\\Program Files\\Test Only\\svc.exe\" --password=" + Marker,
            ["ServiceType"] = "user mode service", ["StartType"] = "demand start", ["AccountName"] = "LocalSystem"
        }),
        new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7040, 4, 0, new()
        {
            ["param1"] = Marker, ["param2"] = "auto start", ["param3"] = "disabled", ["param4"] = "windefend"
        }),
        new(SecurityEventChannels.System, SecurityEventProviders.Eventlog, 104, 4, 0, new()
        {
            ["Channel"] = "Application", ["SubjectUserName"] = Marker, ["BackupPath"] = Marker
        }),
        new(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104, 3, 1, new()
        {
            ["MessageNumber"] = 1, ["MessageTotal"] = 2, ["ScriptBlockId"] = ScriptBlockId.ToString("D"),
            ["ScriptBlockText"] = Marker, ["Path"] = Marker
        }),
        Malware(1116),
        Malware(1117),
        Malware(1118),
        Malware(1119),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5001, 2, 0, new() { ["Path"] = Marker }),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5010, 2, 0, new() { ["Path"] = Marker }),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5012, 2, 0, new() { ["Path"] = Marker }),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5007, 4, 0, new()
        {
            ["Old Value"] = "",
            ["New Value"] = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\" + Marker + " = 0x0"
        })
    ];

    public static Fixture For(int eventId) => Positive.Single(fixture => fixture.EventId == eventId);

    public static long Append(SyntheticEventLog log, Fixture fixture, Dictionary<string, object?>? overrides = null)
    {
        var fields = new Dictionary<string, object?>(fixture.Fields);
        foreach (var (name, value) in overrides ?? []) fields[name] = value;
        return log.Append(fixture.Channel, fixture.Provider, fixture.EventId, fields, fixture.Level, fixture.Version);
    }

    private static Fixture Malware(int eventId) =>
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, eventId, 3, 0, new()
        {
            ["Detection ID"] = "{" + DetectionId.ToString("D").ToUpperInvariant() + "}", ["Threat ID"] = "2147735505",
            ["Threat Name"] = "Test-Only:Win32/Fixture", ["Severity ID"] = "5", ["Category ID"] = "8",
            ["Action ID"] = "2", ["Error Code"] = "0x80508023", ["Path"] = Marker, ["Process Name"] = Marker,
            ["Detection User"] = Marker, ["Remediation User"] = Marker, ["FWLink"] = Marker
        });

    public sealed record Fixture(string Channel, string Provider, int EventId, int Level, int Version,
        Dictionary<string, object?> Fields);
}

/// <summary>Captures rendered log text, including any exception text, for privacy assertions.</summary>
internal sealed class CapturingEventLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<(LogLevel Level, string Text)> _entries = new();

    public string Text => string.Join("\n", _entries.Select(entry => entry.Text));
    public IReadOnlyList<(LogLevel Level, string Text)> Entries => _entries.ToArray();

    public ILogger CreateLogger(string categoryName) => new Logger(_entries);

    public ILogger<T> LoggerFor<T>() =>
        LoggerFactory.Create(builder => builder.AddProvider(this).SetMinimumLevel(LogLevel.Debug)).CreateLogger<T>();

    public int Count(LogLevel level, string fragment) =>
        _entries.Count(entry => entry.Level == level && entry.Text.Contains(fragment, StringComparison.Ordinal));

    public void Dispose()
    {
    }

    private sealed class Logger(ConcurrentQueue<(LogLevel Level, string Text)> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            entries.Enqueue((logLevel, formatter(state, exception) + (exception?.ToString() ?? string.Empty)));
    }
}

/// <summary>Answers every request with a scripted response and records what was sent.</summary>
internal sealed class StubHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
    : HttpMessageHandler
{
    public HttpMethod? LastMethod { get; private set; }
    public string? LastPath { get; private set; }
    public string? LastAuthorization { get; private set; }
    public string? LastMediaType { get; private set; }
    public string? LastBody { get; private set; }

    public static StubHttpHandler Status(HttpStatusCode status, string? body = null) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = body is null ? null : new StringContent(body, System.Text.Encoding.UTF8, "application/json")
        }));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        LastMethod = request.Method;
        LastPath = request.RequestUri?.AbsolutePath;
        LastAuthorization = request.Headers.Authorization?.ToString();
        LastMediaType = request.Content?.Headers.ContentType?.MediaType;
        LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        return await respond(request, cancellationToken);
    }
}
