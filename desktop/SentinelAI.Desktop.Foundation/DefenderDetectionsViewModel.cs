using System.ComponentModel;
using System.Globalization;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.SecurityEvents;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum DefenderHistoryState { None, Loading, Ready, NotFound, Unavailable }
public sealed record DefenderDetectionRow(string ThreatName, string EventText, string TimeText, string IdentifiersText, string ResultText);

/// <summary>Retained event history only: no inference that a threat is active or remediation succeeded.</summary>
public sealed class DefenderDetectionsViewModel(IDefenderDetectionsClient client) : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 50;
    private readonly object _gate = new();
    private DefenderDetectionsView? _value;
    private DefenderHistoryState _state;
    private DeviceReadOutcome _outcome;
    private Guid? _endpointId;
    private long _generation;
    private CancellationTokenSource? _operation;
    private bool _disposed;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public DefenderHistoryState State { get { lock (_gate) return _state; } }
    public Guid? EndpointId { get { lock (_gate) return _endpointId; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _endpointId is not null && _operation is null; } }
    public bool CanPreviousPage { get { lock (_gate) return _operation is null && _value is { Offset: > 0 }; } }
    public bool CanNextPage { get { lock (_gate) return _operation is null && _value is { } value && value.Offset + value.Detections.Count < value.TotalCount; } }
    public IReadOnlyList<DefenderDetectionRow> Detections
    {
        get
        {
            lock (_gate)
                return _value?.Detections.Select(item => new DefenderDetectionRow(item.ThreatName ?? T("Unknown threat name"),
                    item.Kind switch
                    {
                        SecurityEventKinds.MalwareDetected => T("Threat detected"),
                        SecurityEventKinds.MalwareActionTaken => T("Defender reported an action"),
                        SecurityEventKinds.MalwareActionFailed => T("Defender action failed"),
                        _ => T("Unknown")
                    },
                    F("Event time: {0}; received by Core: {1}", Format(item.TimeCreatedUtc), Format(item.ReceivedUtc)),
                    F("Threat ID: {0}; detection ID: {1}; event ID: {2}", Number(item.ThreatId), item.DetectionId?.ToString("D") ?? T("Unknown"), item.EventId),
                    F("Defender severity ID: {0}; category ID: {1}; action ID: {2}; error code: {3}",
                        Number(item.SeverityId), Number(item.CategoryId), Number(item.ActionId), Number(item.ErrorCode)))).ToArray() ?? [];
        }
    }

    public string StatusText
    {
        get
        {
            lock (_gate) return _state switch
            {
                DefenderHistoryState.None => string.Empty,
                DefenderHistoryState.Loading => T("Reading Defender history…"),
                DefenderHistoryState.NotFound => T("This computer is no longer enrolled."),
                DefenderHistoryState.Unavailable when _outcome == DeviceReadOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
                DefenderHistoryState.Unavailable => T("Defender history is unavailable. Refresh to try again."),
                DefenderHistoryState.Ready when _value is { TotalCount: 0 } => T("No Defender detection or action events are stored for this computer. This does not establish that it is safe."),
                _ => T("Stored Defender detection and action events, newest event time first.")
            };
        }
    }

    public string SourceText
    {
        get
        {
            lock (_gate)
            {
                if (_value is not { } value) return string.Empty;
                var state = value.SourceState switch
                {
                    "collecting" => T("Collecting Defender events"),
                    "disabled" => T("Defender event collection is disabled"),
                    "accessDenied" => T("Access to the Defender event log was denied"),
                    "notFound" => T("The Defender event log was not found"),
                    "error" => T("The Defender event log could not be read"),
                    _ => T("Defender event source: Unknown; no status has been reported")
                };
                if (value.SourceReportedUtc is not { } reported) return state;
                var freshness = value.GeneratedUtc - reported > TimeSpan.FromHours(2)
                    ? T("Source status is stale; current collection is unknown.") : string.Empty;
                return state + ". " + F("Source status received: {0}; last log read: {1}.", Format(reported), Format(value.LastReadUtc)) +
                       (freshness.Length == 0 ? string.Empty : " " + freshness);
            }
        }
    }

    public string RetentionText
    {
        get
        {
            lock (_gate) return _value is not { } value ? string.Empty :
                F("History is limited to retained events (up to {0} days and the endpoint event limit). Gaps and events before collection began may be missing. These records do not establish whether a threat is currently active or removed.", value.RetentionDays);
        }
    }

    public string PageText
    {
        get
        {
            lock (_gate) return _value is not { } value ? string.Empty : F("Events {0}–{1} of {2}",
                value.Detections.Count == 0 ? 0 : value.Offset + 1, value.Offset + value.Detections.Count, value.TotalCount);
        }
    }

    public Task LoadAsync(Guid endpointId) => ReadAsync(endpointId, 0);
    public Task RefreshAsync() { lock (_gate) return _endpointId is { } id && _operation is null ? ReadAsync(id, 0) : Task.CompletedTask; }
    public Task PreviousPageAsync() { lock (_gate) return CanPreviousPage && _value is { } value ? ReadAsync(value.EndpointId, Math.Max(0, value.Offset - PageSize)) : Task.CompletedTask; }
    public Task NextPageAsync() { lock (_gate) return CanNextPage && _value is { } value ? ReadAsync(value.EndpointId, value.Offset + PageSize) : Task.CompletedTask; }

    private async Task ReadAsync(Guid endpointId, int offset)
    {
        CancellationTokenSource operation;
        long generation;
        lock (_gate)
        {
            if (_disposed) return;
            _operation?.Cancel();
            operation = _operation = new CancellationTokenSource();
            generation = ++_generation;
            _endpointId = endpointId;
            _value = null;
            _state = DefenderHistoryState.Loading;
        }
        NotifyAll();
        DeviceReadResult<DefenderDetectionsView> result;
        try { result = await client.GetDefenderDetectionsAsync(endpointId, offset, PageSize, operation.Token); }
        catch (OperationCanceledException) { result = new(DeviceReadOutcome.Unavailable); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }
        var expired = false;
        lock (_gate)
        {
            operation.Dispose();
            if (generation != _generation || _disposed) return;
            _operation = null;
            _outcome = result.Outcome;
            if (result.Outcome == DeviceReadOutcome.Unauthenticated) { ClearLocked(); expired = true; }
            else
            {
                // The client contract and transport validate endpoint and page; retain this guard for alternate clients.
                _value = result is { Outcome: DeviceReadOutcome.Success, Value: { } value } && value.EndpointId == endpointId &&
                         value.Offset == offset && value.Limit == PageSize ? value : null;
                _state = _value is not null ? DefenderHistoryState.Ready : result.Outcome == DeviceReadOutcome.NotFound
                    ? DefenderHistoryState.NotFound : DefenderHistoryState.Unavailable;
            }
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    public void Clear()
    {
        lock (_gate) { if (_disposed) return; ClearLocked(); }
        NotifyAll();
    }
    private void ClearLocked()
    {
        _generation++;
        _operation?.Cancel();
        _operation = null;
        _value = null;
        _endpointId = null;
        _state = DefenderHistoryState.None;
    }
    public void Dispose() { lock (_gate) { if (_disposed) return; ClearLocked(); _disposed = true; } }
    private static string Format(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? T("Unknown");
    private static string Number(long? value) => value?.ToString(CultureInfo.InvariantCulture) ?? T("Unknown");
    private void NotifyAll()
    {
        foreach (var name in new[] { nameof(State), nameof(EndpointId), nameof(Detections), nameof(StatusText), nameof(SourceText), nameof(RetentionText),
                     nameof(PageText), nameof(CanRefresh), nameof(CanPreviousPage), nameof(CanNextPage) })
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
