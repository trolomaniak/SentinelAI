using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>Every event timing, derived from the one bounded option Agent:EventPollInterval (P).</summary>
public sealed record SecurityEventTimings(
    TimeSpan PollInterval,
    TimeSpan BacklogPollDelay,
    TimeSpan DeliverySpacing,
    TimeSpan ChannelRetry,
    TimeSpan IncompatibleRetry,
    TimeSpan StatusCounterInterval,
    TimeSpan StatusLivenessInterval,
    TimeSpan ScanFlushInterval,
    TimeSpan ConfigurationRefresh)
{
    public static SecurityEventTimings From(AgentOptions options)
    {
        var poll = options.EventPollInterval;
        return new(
            poll,
            Min(TimeSpan.FromSeconds(1), poll),
            Min(TimeSpan.FromSeconds(2), poll * 4),
            poll * 12,
            Min(TimeSpan.FromMinutes(15), poll * 180),
            Min(TimeSpan.FromMinutes(5), poll * 60),
            Min(TimeSpan.FromMinutes(60), poll * 720),
            Min(TimeSpan.FromMinutes(5), poll * 60),
            Min(TimeSpan.FromMinutes(5), poll * 60));
    }

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left <= right ? left : right;
}

public sealed record SecurityEventPipelineSnapshot(
    bool Active,
    IReadOnlyList<SecurityEventSourceStatus> Sources,
    int PreparedEvents,
    int PreparedGaps,
    long Polls,
    long DeliveryAttempts,
    long CheckpointWrites,
    DateTimeOffset NextDeliveryUtc,
    TimeSpan RetryDelay);

/// <summary>
/// Continuous collection of the compiled security event catalog. One loop reads each channel from
/// its acknowledged position, prepares at most one bounded batch, delivers it and only then advances
/// and persists positions; nothing is read while a batch is pending, so the Windows channel itself is
/// the bounded buffer. Overwrites, resets, coverage starts and dropped records travel to Core as gap
/// items in the same batch. The pipeline stays dormant until <see cref="AgentLink"/> reports an
/// enrolled, acknowledged Agent. All state belongs to the loop; there are no locks.
/// </summary>
public sealed class SecurityEventPipeline : BackgroundService
{
    public const int MaxScanPerChannel = 1024;
    public const int MaxScanPerPoll = 2048;
    // A reset plus an overwrite at the start of the new generation, before any dropped record.
    private const int MaxContinuityGapsPerChannel = 2;
    private static readonly TimeSpan FailureLogInterval = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan FlushTimeout = TimeSpan.FromSeconds(5);
    private static readonly string AgentVersion =
        typeof(SecurityEventPipeline).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";

    private readonly AgentOptions _options;
    private readonly IEventLogAccess _access;
    private readonly EventCheckpointStore _checkpoints;
    private readonly AgentLink _link;
    private readonly ISecurityEventUploader _uploader;
    private readonly TimeProvider _time;
    private readonly ILogger<SecurityEventPipeline> _logger;
    private readonly SecurityEventTimings _timings;
    private readonly SecurityEventCatalog _catalog = SecurityEventCatalog.Production;
    private readonly ChannelState[] _channels;
    private readonly Dictionary<string, ChannelState> _byName;

    private bool _initialized;
    private Guid _boundEndpointId;
    private bool _endpointChangeLogged;
    private DateTimeOffset _countersSinceUtc;
    private long _rotation;
    private Draft? _prepared;
    private DateTimeOffset _nextPollUtc;
    private DateTimeOffset _nextDeliveryUtc;
    private TimeSpan _retryDelay;
    private FailureClass _failureClass;
    private int _failedAttempts;
    private DateTimeOffset _lastFailureLogUtc;
    private bool _wasUnlinked;
    private bool _invalidEnvelopeLogged;
    private SecurityEventSourceStatus[]? _lastAckedSources;
    private DateTimeOffset _lastStatusAckUtc;
    private Dirty _dirty;
    private DateTimeOffset _lastScanFlushUtc;
    private DateTimeOffset _lastSaveFailureLogUtc = DateTimeOffset.MinValue;
    private long _polls;
    private long _deliveryAttempts;
    private SecurityEventPipelineSnapshot _snapshot;

    public SecurityEventPipeline(AgentOptions options, IEventLogAccess access, EventCheckpointStore checkpoints,
        AgentLink link, ISecurityEventUploader uploader, TimeProvider time, ILogger<SecurityEventPipeline> logger)
    {
        _options = options;
        _access = access;
        _checkpoints = checkpoints;
        _link = link;
        _uploader = uploader;
        _time = time;
        _logger = logger;
        _timings = SecurityEventTimings.From(options);
        _retryDelay = options.RetryDelay;
        _channels = access.IsSupported
            ? _catalog.ChannelNames.Select(channel => new ChannelState(channel)).ToArray()
            : [];
        _byName = _channels.ToDictionary(channel => channel.Channel, StringComparer.Ordinal);
        _snapshot = CreateSnapshot();
    }

    private enum FailureClass { None, Failed, Incompatible }

    private enum Dirty { None, Deferred, Immediate }

    public SecurityEventPipelineSnapshot Snapshot => Volatile.Read(ref _snapshot);

    /// <summary>When the loop next has work: a poll, a delivery or a status report.</summary>
    public DateTimeOffset NextWakeUtc
    {
        get
        {
            // Before initialization nothing is due until the link appears; the loop also wakes on link changes.
            if (!_initialized) return DateTimeOffset.MaxValue;
            if (_prepared is not null) return _link.Current is null ? DateTimeOffset.MaxValue : _nextDeliveryUtc;
            var now = _time.GetUtcNow();
            return _initialized && _link.Current is not null && StatusDue(now) && _nextDeliveryUtc < _nextPollUtc
                ? _nextDeliveryUtc
                : _nextPollUtc;
        }
    }

    /// <summary>False while unlinked or unsupported; idempotent; never throws except for cancellation.</summary>
    public async Task<bool> InitializeAsync(CancellationToken cancellationToken)
    {
        if (_initialized) return true;
        if (!_access.IsSupported || _link.Current is not { } linked) return false;

        var now = _time.GetUtcNow();
        EventCheckpointLoad load;
        try
        {
            load = await _checkpoints.LoadAsync(linked.EndpointId, cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("Security event checkpoints could not be loaded ({ExceptionType}, 0x{HResult:X8})",
                exception.GetType().Name, exception.HResult);
            load = new EventCheckpointLoad(new Dictionary<string, EventCheckpoint>(),
                SecurityEventCoverageCauses.CheckpointInvalid);
        }

        if (load.Cause == SecurityEventCoverageCauses.CheckpointInvalid)
            _logger.LogWarning("Security event checkpoints are invalid; coverage restarts on every channel");
        else if (load.Cause == SecurityEventCoverageCauses.EndpointChanged)
            _logger.LogWarning("Security event checkpoints belong to another endpoint; coverage restarts on every channel");

        foreach (var channel in _channels)
        {
            if (load.Checkpoints.TryGetValue(channel.Channel, out var checkpoint))
            {
                channel.Position = checkpoint.RecordId;
                channel.AnchorTicks = checkpoint.AnchorUtcTicks;
            }
            else
            {
                channel.CoverageCause = load.Cause;
            }
        }

        _boundEndpointId = linked.EndpointId;
        _countersSinceUtc = now;
        _nextPollUtc = now;
        _nextDeliveryUtc = now;
        _lastScanFlushUtc = now;
        _initialized = true;
        _logger.LogInformation("Security event collection started for {ChannelCount} channels", _channels.Length);
        return true;
    }

    /// <summary>One iteration: poll if due, deliver if due, persist if due.</summary>
    public async Task StepAsync(CancellationToken cancellationToken)
    {
        if (!_initialized && !await InitializeAsync(cancellationToken))
        {
            PublishSnapshot();
            return;
        }

        var now = _time.GetUtcNow();
        var linked = _link.Current;
        if (linked is null)
        {
            _wasUnlinked = true;
        }
        else if (_wasUnlinked)
        {
            // The link returned: attempt at once with a fresh backoff.
            _wasUnlinked = false;
            _retryDelay = _options.RetryDelay;
            _nextDeliveryUtc = now;
        }

        if (linked is not null && linked.EndpointId != _boundEndpointId && !_endpointChangeLogged)
        {
            _endpointChangeLogged = true;
            _logger.LogWarning("The Agent endpoint changed while security event collection was running");
        }

        if (_prepared is null && now >= _nextPollUtc) Poll(now, cancellationToken);
        if ((_prepared is not null || StatusDue(now)) && linked is not null && now >= _nextDeliveryUtc)
            await DeliverAsync(linked, now, cancellationToken);
        if (_dirty == Dirty.Immediate || _dirty == Dirty.Deferred && now - _lastScanFlushUtc >= _timings.ScanFlushInterval)
            await SaveAsync(now, cancellationToken);
        PublishSnapshot();
    }

    /// <summary>Persists changed positions; used at graceful stop.</summary>
    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (!_initialized || _dirty == Dirty.None) return;
        await _checkpoints.SaveAsync(_boundEndpointId, Positions(), cancellationToken);
        _dirty = Dirty.None;
        PublishSnapshot();
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // The stopping token's registration cancels a native read in progress (see ExecuteAsync).
        await base.StopAsync(cancellationToken);
        if (ExecuteTask is { IsCompleted: false }) return;
        using var flush = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        flush.CancelAfter(FlushTimeout);
        try
        {
            await FlushAsync(flush.Token);
        }
        catch (Exception exception)
        {
            _logger.LogWarning("Security event checkpoints could not be saved at stop ({ExceptionType}, 0x{HResult:X8})",
                exception.GetType().Name, exception.HResult);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!_access.IsSupported)
        {
            _logger.LogInformation("Security event collection is unavailable on this platform");
            return;
        }

        // Runs after the token is marked cancelled, so a cancelled read is never reported as a channel error.
        using var cancelReads = stoppingToken.Register(_access.CancelPending);
        try
        {
            while (true)
            {
                // Dormant until enrolled and acknowledged: no reads, no file and no traffic.
                var linkChanged = _link.Changed;
                if (_link.Current is not null) break;
                await linkChanged.WaitAsync(stoppingToken);
            }

            while (true)
            {
                // Capture the signal before reading state so a concurrent link change still wakes us.
                var linkChanged = _link.Changed;
                try
                {
                    await StepAsync(stoppingToken);
                }
                catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                {
                    // Includes EventLog cancellations (1223/1818) that are not this host stopping.
                    _logger.LogWarning("Security event collection step failed ({ExceptionType}, 0x{HResult:X8})",
                        exception.GetType().Name, exception.HResult);
                    _nextPollUtc = _time.GetUtcNow() + _timings.PollInterval;
                }

                var wait = NextWakeUtc - _time.GetUtcNow();
                if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
                if (wait > _timings.PollInterval) wait = _timings.PollInterval;
                using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                await Task.WhenAny(Task.Delay(wait, _time, waitCancellation.Token),
                    linkChanged.WaitAsync(waitCancellation.Token));
                await waitCancellation.CancelAsync();
                stoppingToken.ThrowIfCancellationRequested();
            }
        }
        catch (Exception) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private void Poll(DateTimeOffset now, CancellationToken cancellationToken)
    {
        _polls++;
        var draft = new Draft();
        var totalScanned = 0;
        var budgetFull = false;
        var backlog = false;
        var start = (int)(_rotation++ % _channels.Length);
        for (var offset = 0; offset < _channels.Length; offset++)
        {
            var state = _channels[(start + offset) % _channels.Length];
            // Each channel not yet visited may still add its continuity gaps before its scan; reserve room for them.
            var reserve = (_channels.Length - offset - 1) * MaxContinuityGapsPerChannel;
            if (state.IsUnavailable && now < state.RetryAtUtc) continue;

            var pass = new ChannelPass(state.Position ?? 0, state.AnchorTicks);
            IEventRecordCursor? cursor = null;
            try
            {
                var extent = _access.Describe(state.Channel);
                SetDescribed(state, extent, now);
                if (state.Position is not { } position)
                {
                    // Coverage starts at the tail; history before it is never delivered.
                    var newest = _access.ReadNewest(state.Channel);
                    var tail = newest?.RecordId ?? 0;
                    AddGap(draft, state, SecurityEventGapReasons.CoverageStarted, tail + 1, null,
                        state.CoverageCause ?? SecurityEventCoverageCauses.NoCheckpoint, now);
                    // Position 0 (an empty log) is the start of a generation and never carries an anchor.
                    draft.End[state.Channel] = (tail, tail > 0 ? newest?.TimeCreatedUtc?.UtcTicks : null);
                    continue;
                }

                var anchor = state.AnchorTicks;
                if (extent.NewestRecordId is not { } newestId || extent.OldestRecordId is not { } oldestId)
                {
                    // Emptied: the log was reset; its next generation is read from the start.
                    if (position > 0) ResetChannel(draft, state, position, now);
                    continue;
                }

                long? from = null;
                if (newestId < position)
                {
                    // Shrunk: the log was reset; the new generation is read in this same pass.
                    pass = StartGeneration(draft, state, position, oldestId, now);
                }
                else if (oldestId > position + 1)
                {
                    // Records after the position were overwritten unread (including from a generation start).
                    AddGap(draft, state, SecurityEventGapReasons.Overwritten, position + 1, oldestId - 1, null, now);
                    pass = new ChannelPass(oldestId - 1, null);
                }
                else if (newestId == position)
                {
                    // Nothing new; the anchor is verified again when the next record arrives.
                    continue;
                }
                else if (position > 0 && oldestId <= position)
                {
                    // The position is in the log: seek on it and prove the generation by its time. A
                    // below-oldest marker (no time) verifies only against a record without a time.
                    from = position;
                }
                // Otherwise (position 0, or only the anchor itself overwritten) read from the oldest record.

                if (budgetFull || totalScanned >= MaxScanPerPoll)
                {
                    backlog = true;
                    Commit(draft, state, pass);
                    continue;
                }

                cursor = _access.Open(state.Channel, from, newestId);
                if (cursor.UsedFallback) state.SeekFallbacks++;
                if (from is not null && !VerifyAnchor(draft, state, ref cursor, ref pass, position, anchor, newestId, now))
                    continue;

                var scanned = 0;
                while (scanned < MaxScanPerChannel && totalScanned < MaxScanPerPoll && cursor!.TryNext(out var header))
                {
                    scanned++;
                    totalScanned++;
                    if (header.RecordId is not { } id)
                    {
                        state.DroppedUnparsed++;
                        continue;
                    }

                    if (id <= pass.End) continue;
                    var definition = _catalog.Find(state.Channel, header.Provider, header.EventId, header.Level);
                    if (definition is null)
                    {
                        // An anchor or newest member of the result set that is not a catalog record.
                        Advance(state, ref pass, id, header);
                        continue;
                    }

                    IReadOnlyList<object?>? predicateValues = null;
                    if (definition.Predicate is { } predicate)
                    {
                        predicateValues = ReadFieldsSafe(cursor, predicate, cancellationToken);
                        if (!SecurityEventNormalizer.PassesPredicate(definition, predicateValues, out var discarded))
                        {
                            state.FieldsDiscarded += discarded;
                            Advance(state, ref pass, id, header);
                            continue;
                        }
                    }

                    if (header.TimeCreatedUtc is null)
                    {
                        if (!HasGapRoom(draft, reserve))
                        {
                            budgetFull = backlog = true;
                            break;
                        }

                        state.DroppedUnparsed++;
                        AddGap(draft, state, SecurityEventGapReasons.Dropped, id, id, null, now);
                        Advance(state, ref pass, id, header);
                        continue;
                    }

                    var result = SecurityEventNormalizer.Normalize(definition, header, predicateValues,
                        ReadFieldsSafe(cursor, definition.Fields, cancellationToken));
                    if (result.Outcome == NormalizationOutcome.NotSelected)
                    {
                        state.FieldsDiscarded += result.FieldsDiscarded;
                        Advance(state, ref pass, id, header);
                        continue;
                    }

                    if (result.Outcome != NormalizationOutcome.Selected)
                    {
                        if (!HasGapRoom(draft, reserve))
                        {
                            budgetFull = backlog = true;
                            break;
                        }

                        if (result.Outcome == NormalizationOutcome.Oversize) state.DroppedOversize++;
                        else state.DroppedUnparsed++;
                        state.FieldsDiscarded += result.FieldsDiscarded;
                        AddGap(draft, state, SecurityEventGapReasons.Dropped, id, id, null, now);
                        Advance(state, ref pass, id, header);
                        continue;
                    }

                    if (draft.Events.Count >= SecurityEventContract.MaxEventsPerBatch ||
                        draft.EventBytes + result.Size > SecurityEventContract.MaxBatchEventBytes)
                    {
                        // Not consumed: the record is read again for the next batch.
                        budgetFull = backlog = true;
                        break;
                    }

                    draft.Events.Add(result.Observation!);
                    draft.EventBytes += result.Size;
                    draft.EventCounts[state.Channel] = draft.EventCounts.GetValueOrDefault(state.Channel) + 1;
                    state.Observed++;
                    state.FieldsDiscarded += result.FieldsDiscarded;
                    Advance(state, ref pass, id, header);
                }

                if (scanned >= MaxScanPerChannel || totalScanned >= MaxScanPerPoll) backlog = true;
                Commit(draft, state, pass);
            }
            catch (EventChannelUnavailableException exception) when (!cancellationToken.IsCancellationRequested)
            {
                Commit(draft, state, pass);
                SetUnavailable(state, exception.State, exception.ErrorCode, null, now);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Includes read timeouts and EventLog cancellations that are not this host stopping.
                Commit(draft, state, pass);
                SetUnavailable(state, SecurityEventSourceStates.Error, exception.HResult, exception.GetType().Name, now);
            }
            finally
            {
                cursor?.Dispose();
            }
        }

        if (draft.HasItems)
        {
            draft.Full = budgetFull;
            _prepared = draft;
        }

        _nextPollUtc = now + (backlog ? _timings.BacklogPollDelay : _timings.PollInterval);
    }

    /// <summary>
    /// The first returned record at or above the position must be the position with its stored time;
    /// then the cursor continues after it. Otherwise the channel is described again and read from the
    /// start of what the log holds now, with the reset or overwrite recorded. Returns false only when
    /// the pass ends because the log is empty.
    /// </summary>
    private bool VerifyAnchor(Draft draft, ChannelState state, ref IEventRecordCursor? cursor, ref ChannelPass pass,
        long position, long? anchor, long newest, DateTimeOffset now)
    {
        var first = FirstAtOrAbove(cursor!, position);
        if (first?.RecordId != position)
        {
            // Absent: a Describe-to-Open race or an undocumented seek landing. Retry without the seek.
            cursor!.Dispose();
            cursor = null;
            cursor = _access.Open(state.Channel, position, newest, forceFallback: true);
            state.SeekFallbacks++;
            first = FirstAtOrAbove(cursor, position);
        }

        if (first?.RecordId == position && first.Value.TimeCreatedUtc?.UtcTicks == anchor) return true;

        // Same number with a different time: the log was cleared and has regrown past the position.
        var regrown = first?.RecordId == position;
        cursor!.Dispose();
        cursor = null;
        var extent = _access.Describe(state.Channel);
        SetDescribed(state, extent, now);
        if (extent.NewestRecordId is not { } newestId || extent.OldestRecordId is not { } oldestId)
        {
            ResetChannel(draft, state, position, now);
            return false;
        }

        if (regrown || newestId < position || oldestId <= position)
        {
            // A reset (the record should exist but does not, or is another record): read the new generation now.
            pass = StartGeneration(draft, state, position, oldestId, now);
        }
        else if (oldestId > position + 1)
        {
            AddGap(draft, state, SecurityEventGapReasons.Overwritten, position + 1, oldestId - 1, null, now);
            pass = new ChannelPass(oldestId - 1, null);
        }

        // Oldest == position + 1: only the anchor itself was overwritten and nothing was lost.
        cursor = _access.Open(state.Channel, null, newestId);
        return true;
    }

    private static EventRecordHeader? FirstAtOrAbove(IEventRecordCursor cursor, long position)
    {
        for (var read = 0; read < MaxScanPerChannel && cursor.TryNext(out var header); read++)
        {
            if (header.RecordId is { } id && id >= position) return header;
        }

        return null;
    }

    /// <summary>An emptied log: the reset is recorded and the next generation is read from its first record.</summary>
    private void ResetChannel(Draft draft, ChannelState state, long position, DateTimeOffset now)
    {
        AddGap(draft, state, SecurityEventGapReasons.LogReset, position + 1, null, null, now);
        draft.End[state.Channel] = (0, null);
    }

    /// <summary>
    /// A reset with records in the new generation, which is read in the same pass so its position never
    /// rests at 0. Unread old records are inside the reset gap; the new generation is numbered from 1,
    /// so records below its oldest were overwritten before they could be read.
    /// </summary>
    private ChannelPass StartGeneration(Draft draft, ChannelState state, long position, long oldest, DateTimeOffset now)
    {
        AddGap(draft, state, SecurityEventGapReasons.LogReset, position + 1, null, null, now);
        if (oldest <= 1) return new ChannelPass(0, null);
        AddGap(draft, state, SecurityEventGapReasons.Overwritten, 1, oldest - 1, null, now);
        return new ChannelPass(oldest - 1, null);
    }

    private static void Advance(ChannelState state, ref ChannelPass pass, long id, EventRecordHeader header)
    {
        pass = new ChannelPass(id, header.TimeCreatedUtc?.UtcTicks);
        state.Scanned++;
    }

    /// <summary>
    /// Ends a channel's pass: with batch items the position moves only on acknowledgement; a scan that
    /// selected nothing advances at once (it skipped nothing collectable) and is persisted lazily.
    /// </summary>
    private void Commit(Draft draft, ChannelState state, ChannelPass pass)
    {
        if (draft.HasItemsFor(state.Channel))
        {
            draft.End[state.Channel] = (pass.End, pass.EndTicks);
        }
        else if (state.Position is { } position && pass.End > position)
        {
            state.Position = pass.End;
            state.AnchorTicks = pass.EndTicks;
            if (_dirty == Dirty.None) _dirty = Dirty.Deferred;
        }
    }

    private static bool HasGapRoom(Draft draft, int reserve) =>
        draft.Gaps.Count + 1 + reserve <= SecurityEventContract.MaxGapsPerBatch;

    private IReadOnlyList<object?>? ReadFieldsSafe(IEventRecordCursor cursor, EventFieldSet fields,
        CancellationToken cancellationToken)
    {
        if (fields.Fields.Count == 0) return [];
        try
        {
            return cursor.ReadFields(fields);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // A render failure discards the fields; the occurrence is still reported.
            return null;
        }
    }

    private void AddGap(Draft draft, ChannelState state, string reason, long first, long? last, string? cause,
        DateTimeOffset now)
    {
        draft.Gaps.Add(new SecurityEventGap(state.Channel, reason, first, last, now, cause));
        draft.GapCounts[state.Channel] = draft.GapCounts.GetValueOrDefault(state.Channel) + 1;
        _logger.LogWarning("Security event gap on {Channel}: {Reason} {Cause} from record {FirstRecordId} to {LastRecordId}",
            state.Channel, reason, cause ?? "-", first, last?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-");
    }

    private async Task DeliverAsync(EnrollmentState linked, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var prepared = _prepared;
        var sources = BuildSources();
        var batch = new SecurityEventBatch(linked.EndpointId, SecurityEventContract.Format, AgentVersion, now,
            _countersSinceUtc, sources, prepared?.Gaps ?? [], prepared?.Events ?? []);
        if (!SecurityEventContract.IsValidEnvelope(batch))
        {
            // A bug path: hold the batch as if Core were incompatible.
            if (!_invalidEnvelopeLogged)
            {
                _invalidEnvelopeLogged = true;
                _logger.LogError("A security event batch failed local validation and was not sent");
            }

            _nextDeliveryUtc = now + _timings.IncompatibleRetry;
            return;
        }

        _deliveryAttempts++;
        UploadOutcome outcome;
        string? exceptionType = null;
        try
        {
            outcome = await _uploader.SendAsync(batch, linked, cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Contained as a transient failure so the backoff still spaces the attempts.
            exceptionType = $"{exception.GetType().Name}, 0x{exception.HResult:X8}";
            outcome = new UploadOutcome(UploadResult.Failed, null, null);
        }

        switch (outcome.Result)
        {
            case UploadResult.Accepted:
                Acknowledge(prepared, sources, now);
                if (_failureClass != FailureClass.None)
                {
                    _logger.LogInformation("Security event delivery recovered after {Attempts} attempts", _failedAttempts + 1);
                }

                _failureClass = FailureClass.None;
                _failedAttempts = 0;
                _logger.LogDebug("Security event batch accepted: {Events} events, {Gaps} gaps",
                    batch.Events.Count, batch.Gaps.Count);
                break;
            case UploadResult.Incompatible:
                // Older Core or format skew: hold the batch (events stay in the Windows logs) and retry rarely.
                if (_failureClass != FailureClass.Incompatible)
                {
                    _logger.LogWarning(
                        "Core does not accept security event batches (HTTP {StatusCode}); holding the batch and retrying in {RetryDelay}",
                        outcome.StatusCode, _timings.IncompatibleRetry);
                }

                _failureClass = FailureClass.Incompatible;
                _failedAttempts++;
                _nextDeliveryUtc = now + _timings.IncompatibleRetry;
                break;
            default:
                if (_failureClass != FailureClass.Failed || now - _lastFailureLogUtc >= FailureLogInterval)
                {
                    _lastFailureLogUtc = now;
                    _logger.LogWarning("Security event delivery failed ({Failure}); retrying in {RetryDelay}",
                        outcome.StatusCode is { } status
                            ? "HTTP " + status.ToString(System.Globalization.CultureInfo.InvariantCulture)
                            : exceptionType ?? "no response", _retryDelay);
                }

                _failureClass = FailureClass.Failed;
                _failedAttempts++;
                _nextDeliveryUtc = now + _retryDelay;
                _retryDelay = _retryDelay.Ticks >= _options.MaxRetryDelay.Ticks / 2
                    ? _options.MaxRetryDelay
                    : TimeSpan.FromTicks(_retryDelay.Ticks * 2);
                break;
        }
    }

    private void Acknowledge(Draft? prepared, SecurityEventSourceStatus[] sources, DateTimeOffset now)
    {
        if (prepared is not null)
        {
            var changed = false;
            foreach (var (channel, end) in prepared.End)
            {
                var state = _byName[channel];
                changed |= state.Position != end.RecordId || state.AnchorTicks != end.AnchorTicks;
                state.Position = end.RecordId;
                state.AnchorTicks = end.AnchorTicks;
                state.CoverageCause = null;
            }

            foreach (var state in _channels)
            {
                state.Delivered += prepared.EventCounts.GetValueOrDefault(state.Channel);
                state.Gaps += prepared.GapCounts.GetValueOrDefault(state.Channel);
            }

            foreach (var gap in prepared.Gaps)
            {
                if (gap.Reason == SecurityEventGapReasons.Overwritten && gap.LastRecordId is { } last)
                    _byName[gap.Channel].SkippedRecords += last - gap.FirstRecordId + 1;
            }

            _prepared = null;
            if (changed) _dirty = Dirty.Immediate;
            if (prepared.Full) _nextPollUtc = now;
        }

        _lastAckedSources = sources;
        _lastStatusAckUtc = now;
        _retryDelay = _options.RetryDelay;
        _nextDeliveryUtc = now + _timings.DeliverySpacing;
    }

    /// <summary>
    /// A status-only report is due on any state change or coverage being established, on counter changes
    /// at most every StatusCounterInterval, and for liveness every StatusLivenessInterval.
    /// </summary>
    private bool StatusDue(DateTimeOffset now)
    {
        if (_lastAckedSources is not { } last) return true;
        var current = BuildSources();
        var countersChanged = false;
        for (var index = 0; index < current.Length; index++)
        {
            if (current[index].State != last[index].State ||
                current[index].CheckpointRecordId is null != last[index].CheckpointRecordId is null)
                return true;
            countersChanged |= current[index] with { LastReadUtc = null } != last[index] with { LastReadUtc = null };
        }

        var sinceAcknowledged = now - _lastStatusAckUtc;
        return sinceAcknowledged >= _timings.StatusLivenessInterval ||
               countersChanged && sinceAcknowledged >= _timings.StatusCounterInterval;
    }

    private async Task SaveAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            await _checkpoints.SaveAsync(_boundEndpointId, Positions(), cancellationToken);
            _dirty = Dirty.None;
            _lastScanFlushUtc = now;
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Positions stay dirty and the save is retried on a later step.
            if (now - _lastSaveFailureLogUtc >= FailureLogInterval)
            {
                _lastSaveFailureLogUtc = now;
                _logger.LogWarning("Security event checkpoints could not be saved ({ExceptionType}, 0x{HResult:X8})",
                    exception.GetType().Name, exception.HResult);
            }
        }
    }

    private List<(string Channel, EventCheckpoint Checkpoint)> Positions() =>
        _channels.Where(channel => channel.Position is not null)
            .Select(channel => (channel.Channel, new EventCheckpoint(channel.Position!.Value, channel.AnchorTicks)))
            .ToList();

    private void SetDescribed(ChannelState state, ChannelExtent extent, DateTimeOffset now)
    {
        state.Oldest = extent.OldestRecordId;
        state.Newest = extent.NewestRecordId;
        state.MaxBytes = extent.MaximumSizeBytes;
        state.LastReadUtc = now;
        Transition(state, extent.Enabled == false ? SecurityEventSourceStates.Disabled : SecurityEventSourceStates.Collecting,
            null);
    }

    private void SetUnavailable(ChannelState state, string sourceState, int errorCode, string? exceptionType,
        DateTimeOffset now)
    {
        state.RetryAtUtc = now + _timings.ChannelRetry;
        Transition(state, sourceState, errorCode, exceptionType);
    }

    private void Transition(ChannelState state, string sourceState, int? errorCode, string? exceptionType = null)
    {
        state.State = sourceState;
        state.LastErrorCode = errorCode;
        if (state.LoggedState == sourceState) return;
        state.LoggedState = sourceState;
        if (sourceState == SecurityEventSourceStates.Collecting)
            _logger.LogInformation("Security event channel {Channel} is collecting", state.Channel);
        else if (errorCode is { } code)
            _logger.LogWarning("Security event channel {Channel} is {State} ({ExceptionType}, 0x{HResult:X8})",
                state.Channel, sourceState, exceptionType ?? "-", code);
        else
            _logger.LogWarning("Security event channel {Channel} is {State}", state.Channel, sourceState);
    }

    private SecurityEventSourceStatus[] BuildSources() =>
        _channels.Select(state => new SecurityEventSourceStatus(state.Channel, state.State, state.LastErrorCode,
            state.Oldest, state.Newest, state.Position, state.MaxBytes, state.LastReadUtc, state.Scanned, state.Observed,
            state.Delivered, state.DroppedUnparsed, state.DroppedOversize, state.FieldsDiscarded, state.Gaps,
            state.SkippedRecords, state.SeekFallbacks)).ToArray();

    private void PublishSnapshot() => Volatile.Write(ref _snapshot, CreateSnapshot());

    private SecurityEventPipelineSnapshot CreateSnapshot() =>
        new(_initialized, BuildSources(), _prepared?.Events.Count ?? 0, _prepared?.Gaps.Count ?? 0, _polls,
            _deliveryAttempts, _checkpoints.Writes, _nextDeliveryUtc, _retryDelay);

    /// <summary>Progress through one channel: the scanned-through record and its creation ticks.</summary>
    private readonly record struct ChannelPass(long End, long? EndTicks);

    private sealed class ChannelState(string channel)
    {
        public string Channel { get; } = channel;
        public string State { get; set; } = SecurityEventSourceStates.Collecting;
        public int? LastErrorCode { get; set; }
        public string? LoggedState { get; set; }
        // Acknowledged scanned-through position; null until coverage is acknowledged.
        public long? Position { get; set; }
        public long? AnchorTicks { get; set; }
        public string? CoverageCause { get; set; }
        public long? Oldest { get; set; }
        public long? Newest { get; set; }
        public long? MaxBytes { get; set; }
        public DateTimeOffset? LastReadUtc { get; set; }
        public DateTimeOffset RetryAtUtc { get; set; }
        public long Scanned { get; set; }
        public long Observed { get; set; }
        public long Delivered { get; set; }
        public long DroppedUnparsed { get; set; }
        public long DroppedOversize { get; set; }
        public long FieldsDiscarded { get; set; }
        public long Gaps { get; set; }
        public long SkippedRecords { get; set; }
        public long SeekFallbacks { get; set; }

        public bool IsUnavailable => State is SecurityEventSourceStates.AccessDenied or SecurityEventSourceStates.NotFound
            or SecurityEventSourceStates.Error;
    }

    /// <summary>The one prepared batch and the positions it moves to when Core acknowledges it.</summary>
    private sealed class Draft
    {
        public List<SecurityEventObservation> Events { get; } = [];
        public List<SecurityEventGap> Gaps { get; } = [];
        public Dictionary<string, (long RecordId, long? AnchorTicks)> End { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, int> EventCounts { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, int> GapCounts { get; } = new(StringComparer.Ordinal);
        public long EventBytes { get; set; }
        public bool Full { get; set; }
        public bool HasItems => Events.Count > 0 || Gaps.Count > 0;
        public bool HasItemsFor(string channel) =>
            EventCounts.GetValueOrDefault(channel) > 0 || GapCounts.GetValueOrDefault(channel) > 0;
    }
}
