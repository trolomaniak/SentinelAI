using SentinelAI.Contracts.RiskHistory;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class RiskViewModel
{
    private const int DefaultHistoryPeriodHours = 168;
    private readonly IRiskHistoryClient? _historyClient;
    private int _historyPeriodHours = DefaultHistoryPeriodHours;
    private long _historyGeneration;
    private bool _historyActive;
    private Pending? _historyPending;
    private RiskHistoryPresentation? _history;
    private RiskHistoryPointRow? _selectedHistoryPoint;
    private string _historyStatusText = string.Empty;

    public IReadOnlyList<RiskHistoryPeriod> HistoryPeriods { get; } = Array.AsReadOnly(new[]
    {
        new RiskHistoryPeriod(24, T("24 hours")), new RiskHistoryPeriod(168, T("7 days")),
        new RiskHistoryPeriod(720, T("30 days")), new RiskHistoryPeriod(2160, T("90 days"))
    });

    public bool CanShowHistory { get { lock (_gate) return _historyActive && (_detailState == RiskDetailState.None || _detailEndpointId != Guid.Empty); } }
    public string HistoryHeading { get { lock (_gate) return _detailEndpointId == Guid.Empty ? T("Organization risk history") : T("Endpoint risk history"); } }
    public RiskHistoryPresentation? History { get { lock (_gate) return _history; } }
    public string HistoryStatusText { get { lock (_gate) return _historyStatusText; } }

    public int HistoryPeriodHours
    {
        get { lock (_gate) return _historyPeriodHours; }
        set
        {
            lock (_gate)
            {
                if (_disposed || !CanShowHistory || _historyPeriodHours == value || !RiskHistoryContract.PeriodHours.Contains(value)) return;
                _historyPeriodHours = value;
                BeginHistoryLoadLocked();
            }
        }
    }

    public RiskHistoryPointRow? SelectedHistoryPoint
    {
        get { lock (_gate) return _selectedHistoryPoint; }
        set
        {
            lock (_gate)
            {
                if (_disposed || ReferenceEquals(_selectedHistoryPoint, value) || value is not null && _history?.Points.Contains(value) != true) return;
                _selectedHistoryPoint = value;
                Notify(nameof(SelectedHistoryPoint));
            }
        }
    }

    private void BeginHistoryLoadLocked()
    {
        if (_historyClient is null || !CanShowHistory) return;
        ClearHistoryLocked();
        var pending = new Pending(_historyGeneration);
        Guid? endpointId = _detailEndpointId == Guid.Empty ? null : _detailEndpointId;
        var periodHours = _historyPeriodHours;
        _historyPending = pending;
        _historyStatusText = T("Loading recorded risk measurements…");
        NotifyHistory();
        if (HistoryCurrent(pending)) _ = LoadHistoryAsync(_historyClient, pending, endpointId, periodHours);
        else pending.Complete();
    }

    private async Task LoadHistoryAsync(IRiskHistoryClient client, Pending pending, Guid? endpointId, int periodHours)
    {
        try
        {
            var result = await client.GetRiskHistoryAsync(endpointId, periodHours, pending.Token);
            lock (_gate)
            {
                if (!HistoryCurrent(pending)) return;
                if (result.Outcome == RiskReadOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result is { Outcome: RiskReadOutcome.Success, Value: { } history } &&
                    history.EndpointId == endpointId && history.PeriodHours == periodHours)
                {
                    _history = history.Points.Count == 0 ? null : new RiskHistoryPresentation(history);
                    _historyStatusText = _history is null
                        ? T("No recorded risk measurements for this period.")
                        : F("Recorded measurements ({0})", history.Points.Count);
                    Notify(nameof(History), nameof(HistoryStatusText));
                    if (!HistoryCurrent(pending)) return;
                    _selectedHistoryPoint = _history?.Points.FirstOrDefault();
                    Notify(nameof(SelectedHistoryPoint));
                }
                else SetHistoryFailure(result.Outcome);
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (HistoryCurrent(pending)) SetHistoryFailure(RiskReadOutcome.Unavailable);
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_historyPending, pending)) _historyPending = null;
                pending.Complete();
            }
        }
    }

    private bool HistoryCurrent(Pending pending) => !_disposed && _historyActive && pending.Generation == _historyGeneration && !pending.Token.IsCancellationRequested;

    private void SetHistoryFailure(RiskReadOutcome outcome)
    {
        _historyStatusText = outcome switch
        {
            RiskReadOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
            RiskReadOutcome.Success or RiskReadOutcome.InvalidResponse => T("Core returned invalid risk history. Refresh Risk."),
            RiskReadOutcome.TooLarge => T("The risk history response exceeds the supported size."),
            _ => T("Risk history is unavailable. Refresh Risk to try again.")
        };
        Notify(nameof(HistoryStatusText));
    }

    public void LeaveHistory()
    {
        lock (_gate)
        {
            if (_disposed || !_historyActive) return;
            _historyActive = false;
            ClearHistoryLocked();
            NotifyHistory();
        }
    }

    private void ClearHistoryLocked()
    {
        _historyGeneration++;
        _historyPending?.Cancel();
        _historyPending = null;
        _history = null;
        _selectedHistoryPoint = null;
        _historyStatusText = string.Empty;
    }

    private void NotifyHistory() => Notify(nameof(CanShowHistory), nameof(HistoryHeading), nameof(HistoryPeriodHours),
        nameof(History), nameof(SelectedHistoryPoint), nameof(HistoryStatusText));
}
