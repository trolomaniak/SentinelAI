using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum RiskRegisterListState { None, Loading, Ready, Unavailable }

public enum RiskRegisterEditorMode { None, Create, Edit }

/// <summary>One register row as shown: Core's values in words, nothing calculated here.</summary>
public sealed record RiskRegisterRow(Guid RiskId, string Reference, string Title, string Residual, string Status, string Treatment, string Owner,
    string ReviewDate, string Attention);

public sealed record RiskRegisterOption(string Value, string Text);

/// <summary>A computer or alert the administrator can link; ticking it adds the link on the next save.</summary>
public sealed class RiskRegisterChoice(Guid id, string text, bool selected) : INotifyPropertyChanged
{
    private bool _selected = selected;
    public Guid Id { get; } = id;
    public string Text { get; } = text;
    public event PropertyChangedEventHandler? PropertyChanged;

    public bool IsSelected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }
}

/// <summary>
/// TASK-032: the Risk Register page. Lists Core's records with filters, opens one for editing or review and saves with
/// the version that was read, so another administrator's change is never overwritten. The register is a business
/// record: it does not change alerts, detection or the technical risk score, and the page says so. Used from the UI
/// thread.
/// </summary>
public sealed class RiskRegisterViewModel : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 50;
    private const int MaximumAlertChoicesPerComputer = 50;
    private readonly IRiskRegisterClient _client;
    private readonly IDevicesClient? _devices;
    private readonly IAlertsClient? _alerts;
    private CancellationTokenSource _cancellation = new();
    private long _listGeneration;
    private long _detailGeneration;
    private RiskRegisterPage? _page;
    private RiskRegisterDetail? _detail;
    private RiskRegisterListState _listState;
    private RiskRegisterEditorMode _mode;
    private RiskRegisterRow? _selectedRow;
    private bool _saving;
    private bool _disposed;
    private int _offset;
    private string _statusFilter = "active", _treatmentFilter = "any", _levelFilter = "any";
    private bool _attentionOnly;
    private string _title = string.Empty, _description = string.Empty, _owner = string.Empty, _controls = string.Empty;
    private string _treatment = string.Empty, _rationale = string.Empty, _status = "open", _tickets = string.Empty, _note = string.Empty;
    private string _reviewNote = string.Empty, _messageText = string.Empty, _validationText = string.Empty;
    private int _likelihood = 3, _impact = 3, _residualLikelihood = 2, _residualImpact = 2;
    private DateTime? _acceptanceExpiresOn, _targetDate, _reviewDate, _nextReviewDate;

    public RiskRegisterViewModel(IRiskRegisterClient client, IDevicesClient? devices = null, IAlertsClient? alerts = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _devices = devices;
        _alerts = alerts;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public static IReadOnlyList<RiskRegisterOption> StatusFilters { get; } =
        [new("active", T("Open and monitoring")), new("open", T("Open")), new("monitoring", T("Monitoring")), new("closed", T("Closed")), new("all", T("All records"))];
    public static IReadOnlyList<RiskRegisterOption> TreatmentFilters { get; } =
        [new("any", T("Any treatment")), new("none", T("Not decided")), new("avoid", T("Avoid")), new("mitigate", T("Mitigate")), new("transfer", T("Transfer")), new("accept", T("Accept"))];
    public static IReadOnlyList<RiskRegisterOption> LevelFilters { get; } =
        [new("any", T("Any residual level")), new("low", T("Low")), new("medium", T("Medium")), new("high", T("High")), new("critical", T("Critical"))];
    public static IReadOnlyList<RiskRegisterOption> Statuses { get; } = [new("open", T("Open")), new("monitoring", T("Monitoring")), new("closed", T("Closed"))];
    public static IReadOnlyList<RiskRegisterOption> Treatments { get; } =
        [new(string.Empty, "Not decided"), new("avoid", T("Avoid")), new("mitigate", T("Mitigate")), new("transfer", T("Transfer")), new("accept", T("Accept"))];
    public static IReadOnlyList<int> Scale { get; } = [1, 2, 3, 4, 5];

    public string DistinctionText =>
        T("Register ratings are business judgements recorded by administrators: likelihood × impact from 1 to 5, before and after existing ") +
        T("controls. They never change alerts, detection or the technical risk score shown in Risk.");

    // Filters (applied with ApplyFiltersAsync).
    public string StatusFilter { get => _statusFilter; set => Set(ref _statusFilter, value); }
    public string TreatmentFilter { get => _treatmentFilter; set => Set(ref _treatmentFilter, value); }
    public string LevelFilter { get => _levelFilter; set => Set(ref _levelFilter, value); }
    public bool AttentionOnly { get => _attentionOnly; set => Set(ref _attentionOnly, value); }

    // List.
    public RiskRegisterListState ListState => _listState;
    public IReadOnlyList<RiskRegisterRow> Rows { get; private set; } = [];
    public bool CanPreviousPage => !_disposed && _listState == RiskRegisterListState.Ready && _offset > 0;
    public bool CanNextPage => !_disposed && _listState == RiskRegisterListState.Ready && _page is { } page && _offset + page.Records.Count < page.Total;

    public string ListText => _listState switch
    {
        RiskRegisterListState.Loading => T("Reading the Risk Register…"),
        RiskRegisterListState.Unavailable => T("Local Core is unavailable. Restore Core, then select Refresh."),
        RiskRegisterListState.Ready when _page is { Total: 0 } => T("No risk matches these filters. Select New risk to record one."),
        RiskRegisterListState.Ready when _page is { } page => "Showing " + (_offset + 1).ToString(CultureInfo.InvariantCulture) + "–" +
                                                              (_offset + page.Records.Count).ToString(CultureInfo.InvariantCulture) + " of " +
                                                              page.Total.ToString(CultureInfo.InvariantCulture) + T(". Records needing attention come first."),
        _ => string.Empty
    };

    public string CountsText => _page is not { Counts: var counts } ? string.Empty :
        T("Open: ") + counts.Open.ToString(CultureInfo.InvariantCulture) + T(" · Monitoring: ") + counts.Monitoring.ToString(CultureInfo.InvariantCulture) +
        T(" · Closed: ") + counts.Closed.ToString(CultureInfo.InvariantCulture) + T(" · Needing attention: ") + counts.NeedsAttention.ToString(CultureInfo.InvariantCulture);

    public RiskRegisterRow? SelectedRow
    {
        get => _selectedRow;
        set
        {
            if (Equals(_selectedRow, value)) return;
            _selectedRow = value;
            Notify();
            if (value is not null) _ = OpenAsync(value.RiskId);
        }
    }

    // Editor.
    public RiskRegisterEditorMode EditorMode => _mode;
    public bool IsEditing => _mode != RiskRegisterEditorMode.None;
    public bool CanEdit => IsEditing && !_saving && !_disposed;
    public bool CanSave => CanEdit;
    public bool CanReview => _mode == RiskRegisterEditorMode.Edit && _detail is { Status: not "closed" } && !_saving && !_disposed;
    public string EditorTitle => _mode switch
    {
        RiskRegisterEditorMode.Create => T("New risk"),
        RiskRegisterEditorMode.Edit when _detail is { } detail => detail.Reference + " · " + detail.Title,
        _ => string.Empty
    };

    public string Title { get => _title; set => Set(ref _title, value ?? string.Empty); }
    public string Description { get => _description; set => Set(ref _description, value ?? string.Empty); }
    public string Owner { get => _owner; set => Set(ref _owner, value ?? string.Empty); }
    public int Likelihood { get => _likelihood; set => Set(ref _likelihood, value); }
    public int Impact { get => _impact; set => Set(ref _impact, value); }
    public string Controls { get => _controls; set => Set(ref _controls, value ?? string.Empty); }
    public int ResidualLikelihood { get => _residualLikelihood; set => Set(ref _residualLikelihood, value); }
    public int ResidualImpact { get => _residualImpact; set => Set(ref _residualImpact, value); }
    public string Treatment { get => _treatment; set => Set(ref _treatment, value ?? string.Empty); }
    public bool IsAcceptance => _treatment == "accept";
    public string AcceptanceRationale { get => _rationale; set => Set(ref _rationale, value ?? string.Empty); }
    public DateTime? AcceptanceExpiresOn { get => _acceptanceExpiresOn; set => Set(ref _acceptanceExpiresOn, value); }
    public DateTime? TargetDate { get => _targetDate; set => Set(ref _targetDate, value); }
    public DateTime? ReviewDate { get => _reviewDate; set => Set(ref _reviewDate, value); }
    public string Status { get => _status; set => Set(ref _status, value ?? "open"); }
    /// <summary>Ticket references, one per line.</summary>
    public string TicketsText { get => _tickets; set => Set(ref _tickets, value ?? string.Empty); }
    public string Note { get => _note; set => Set(ref _note, value ?? string.Empty); }
    public string InherentText => RatingText(_likelihood, _impact);
    public string ResidualText => RatingText(_residualLikelihood, _residualImpact);
    public ObservableCollection<RiskRegisterChoice> EndpointChoices { get; } = [];
    public ObservableCollection<RiskRegisterChoice> AlertChoices { get; } = [];

    // Review.
    public DateTime? NextReviewDate { get => _nextReviewDate; set => Set(ref _nextReviewDate, value); }
    public string ReviewNote { get => _reviewNote; set => Set(ref _reviewNote, value ?? string.Empty); }

    // Record facts, flags and history.
    public string FlagsText
    {
        get
        {
            if (_mode != RiskRegisterEditorMode.Edit || _detail is not { } detail) return string.Empty;
            var lines = new List<string>();
            if (detail.Flags.ReviewOverdue) lines.Add(T("Review overdue: it was due on ") + detail.ReviewDate + ".");
            if (detail.Flags.AcceptanceExpired) lines.Add(T("Acceptance expired on ") + detail.AcceptanceExpiresOn + T(": decide again, with its owner."));
            if (detail.Flags.TargetDatePassed) lines.Add(T("Target date ") + detail.TargetDate + T(" has passed while the risk is still open."));
            return string.Join(Environment.NewLine, lines);
        }
    }

    public string RecordText => _mode != RiskRegisterEditorMode.Edit || _detail is not { } detail ? string.Empty :
        "Created " + Format(detail.CreatedUtc) + " by " + detail.CreatedBy + ". Last changed " + Format(detail.UpdatedUtc) + " by " + detail.UpdatedBy + "." +
        (detail.LastReviewedUtc is { } reviewed ? " Last reviewed " + Format(reviewed) + " by " + detail.LastReviewedBy + "." : " Not reviewed yet.") +
        " Version " + detail.Version.ToString(CultureInfo.InvariantCulture) + ".";

    public IReadOnlyList<string> HistoryRows { get; private set; } = [];

    private static IReadOnlyList<string> History(RiskRegisterDetail detail) =>
        detail.History.Select(entry =>
        {
            var action = entry.Action switch { "created" => T("Created"), "reviewed" => T("Reviewed"), _ => T("Changed") };
            var text = Format(entry.ChangedUtc) + " · " + entry.ChangedBy + " · " + action;
            if (entry.Changes.Count > 0)
                text += ": " + string.Join("; ", entry.Changes.Select(change => FieldLabel(change.Field) + " " + (change.From ?? "—") + " → " + (change.To ?? "—")));
            return entry.Note is { } note ? text + Environment.NewLine + T("Note: ") + note : text;
        }).ToArray();

    public string MessageText => _messageText;
    public string ValidationText => _validationText;

    public Task ApplyFiltersAsync()
    {
        _offset = 0;
        return LoadPageAsync();
    }

    public Task RefreshAsync() => LoadPageAsync();

    public Task NextPageAsync()
    {
        if (!CanNextPage) return Task.CompletedTask;
        _offset += PageSize;
        return LoadPageAsync();
    }

    public Task PreviousPageAsync()
    {
        if (!CanPreviousPage) return Task.CompletedTask;
        _offset = Math.Max(0, _offset - PageSize);
        return LoadPageAsync();
    }

    private async Task LoadPageAsync()
    {
        if (_disposed) return;
        var generation = ++_listGeneration;
        _listState = RiskRegisterListState.Loading;
        Notify();
        var query = new RiskRegisterQuery(_statusFilter == "all" ? null : _statusFilter, _treatmentFilter == "any" ? null : _treatmentFilter,
            _levelFilter == "any" ? null : _levelFilter, _attentionOnly, Offset: _offset, Limit: PageSize);
        RiskRegisterResult<RiskRegisterPage> result;
        try { result = await _client.GetRiskRegisterAsync(query, _cancellation.Token); }
        catch (OperationCanceledException) { return; }
        if (_disposed || generation != _listGeneration) return;
        if (result.Outcome == RiskRegisterOutcome.Unauthenticated)
        {
            ExpireSession();
            return;
        }

        if (result is { Outcome: RiskRegisterOutcome.Success, Value: { } page })
        {
            _page = page;
            _listState = RiskRegisterListState.Ready;
            Rows = page.Records.Select(Row).ToArray();
        }
        else
        {
            _page = null;
            _listState = RiskRegisterListState.Unavailable;
            Rows = [];
        }

        Notify();
    }

    /// <summary>Starts a new record with a review three months out; computers to link are read from Core.</summary>
    public async Task NewRiskAsync()
    {
        if (_disposed || _saving) return;
        _detailGeneration++;
        _detail = null;
        _selectedRow = null;
        _mode = RiskRegisterEditorMode.Create;
        HistoryRows = [];
        LoadEditor(null);
        Notify();
        await LoadChoicesAsync(_detailGeneration, [], []);
    }

    public async Task OpenAsync(Guid riskId)
    {
        if (_disposed || _saving) return;
        var generation = ++_detailGeneration;
        _messageText = T("Reading the record…");
        _validationText = string.Empty;
        Notify();
        RiskRegisterResult<RiskRegisterDetail> result;
        try { result = await _client.GetRiskRecordAsync(riskId, _cancellation.Token); }
        catch (OperationCanceledException) { return; }
        if (_disposed || generation != _detailGeneration) return;
        switch (result.Outcome)
        {
            case RiskRegisterOutcome.Unauthenticated:
                ExpireSession();
                return;
            case RiskRegisterOutcome.Success when result.Value is { } detail:
                Show(detail, string.Empty);
                await LoadChoicesAsync(_detailGeneration, detail.Endpoints, detail.Alerts);
                return;
            case RiskRegisterOutcome.NotFound:
                _messageText = T("This record no longer exists.");
                break;
            default:
                _messageText = T("Local Core is unavailable. Restore Core, then open the record again.");
                break;
        }

        Notify();
    }

    public void CancelEdit()
    {
        if (_saving) return;
        if (_mode == RiskRegisterEditorMode.Edit && _detail is { } detail) Show(detail, string.Empty);
        else Close();
    }

    public async Task SaveAsync()
    {
        if (!CanSave) return;
        var draft = Draft();
        _saving = true;
        _validationText = string.Empty;
        _messageText = T("Saving…");
        Notify();
        var editing = _mode == RiskRegisterEditorMode.Edit ? _detail : null;
        RiskRegisterResult<RiskRegisterDetail> result;
        try
        {
            result = editing is null
                ? await _client.CreateRiskRecordAsync(draft, _cancellation.Token)
                : await _client.UpdateRiskRecordAsync(editing.RiskId, editing.Version, draft, _cancellation.Token);
        }
        catch (OperationCanceledException) { return; }
        finally { _saving = false; }

        if (_disposed) return;
        await AfterWriteAsync(result, editing is null ? T("Risk recorded.") : T("Changes saved."));
    }

    public async Task RecordReviewAsync()
    {
        if (!CanReview || _detail is not { } detail) return;
        if (_nextReviewDate is not { } next)
        {
            _validationText = T("Choose the date of the next review.");
            Notify();
            return;
        }

        _saving = true;
        _validationText = string.Empty;
        _messageText = T("Recording the review…");
        Notify();
        RiskRegisterResult<RiskRegisterDetail> result;
        try
        {
            result = await _client.ReviewRiskRecordAsync(detail.RiskId, detail.Version, Day(next)!, Optional(_reviewNote), _cancellation.Token);
        }
        catch (OperationCanceledException) { return; }
        finally { _saving = false; }

        if (_disposed) return;
        await AfterWriteAsync(result, T("Review recorded."));
    }

    /// <summary>Lists the alerts of the ticked computers, keeping alerts already linked.</summary>
    public async Task LoadAlertChoicesAsync()
    {
        if (_alerts is null || !IsEditing) return;
        var generation = _detailGeneration;
        var selected = AlertChoices.Where(choice => choice.IsSelected).ToDictionary(choice => choice.Id);
        var choices = new List<RiskRegisterChoice>(selected.Values);
        foreach (var endpoint in EndpointChoices.Where(choice => choice.IsSelected).ToArray())
        {
            AlertResult<AlertPage> result;
            try { result = await _alerts.GetAlertsAsync(new AlertQuery(EndpointId: endpoint.Id, Limit: MaximumAlertChoicesPerComputer), _cancellation.Token); }
            catch (OperationCanceledException) { return; }
            if (_disposed || generation != _detailGeneration) return;
            if (result.Outcome == AlertOutcome.Unauthenticated)
            {
                ExpireSession();
                return;
            }

            if (result is not { Outcome: AlertOutcome.Success, Value: { } page })
            {
                _messageText = T("The alerts of ") + endpoint.Text + T(" could not be read.");
                continue;
            }

            foreach (var alert in page.Alerts.Where(alert => !selected.ContainsKey(alert.AlertId)))
                choices.Add(new RiskRegisterChoice(alert.AlertId, alert.EndpointName + " · " + T(alert.Title) + " (" + AlertRow.Label(alert.Severity) + ", " + AlertRow.Label(alert.Status) + ")", false));
        }

        Replace(AlertChoices, choices.DistinctBy(choice => choice.Id));
        Notify();
    }

    /// <summary>Forgets every record and choice, as at sign-out.</summary>
    public void Clear()
    {
        _listGeneration++;
        _detailGeneration++;
        _cancellation.Cancel();
        _cancellation.Dispose();
        _cancellation = new CancellationTokenSource();
        _page = null;
        Rows = [];
        _listState = RiskRegisterListState.None;
        _offset = 0;
        _selectedRow = null;
        Close();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cancellation.Cancel();
        _cancellation.Dispose();
    }

    private async Task AfterWriteAsync(RiskRegisterResult<RiskRegisterDetail> result, string success)
    {
        switch (result.Outcome)
        {
            case RiskRegisterOutcome.Unauthenticated:
                ExpireSession();
                return;
            case RiskRegisterOutcome.Success when result.Value is { } detail:
                Show(detail, success);
                await LoadChoicesAsync(_detailGeneration, detail.Endpoints, detail.Alerts);
                await LoadPageAsync();
                return;
            case RiskRegisterOutcome.Rejected when result.Errors is { Count: > 0 } errors:
                _messageText = T("Core did not save the record:");
                _validationText = string.Join(Environment.NewLine, errors.Select(ErrorText).Distinct());
                break;
            case RiskRegisterOutcome.Conflict:
                _messageText = T("Another administrator changed this record after you opened it. Nothing was saved; open it again to see the latest version.");
                break;
            case RiskRegisterOutcome.NotFound:
                _messageText = T("This record no longer exists. Nothing was saved.");
                break;
            default:
                // A lost answer may still have been saved: never repeat it automatically.
                _messageText = T("Core did not confirm the save. Refresh the register to see whether it was recorded before trying again.");
                break;
        }

        Notify();
    }

    private void Show(RiskRegisterDetail detail, string message)
    {
        _detailGeneration++;
        _detail = detail;
        _mode = RiskRegisterEditorMode.Edit;
        HistoryRows = History(detail);
        LoadEditor(detail);
        _messageText = message;
        _validationText = string.Empty;
        Notify();
    }

    private void Close()
    {
        _detail = null;
        _mode = RiskRegisterEditorMode.None;
        HistoryRows = [];
        LoadEditor(null);
        EndpointChoices.Clear();
        AlertChoices.Clear();
        _messageText = string.Empty;
        _validationText = string.Empty;
        Notify();
    }

    private void LoadEditor(RiskRegisterDetail? detail)
    {
        _title = detail?.Title ?? string.Empty;
        _description = detail?.Description ?? string.Empty;
        _owner = detail?.Owner ?? string.Empty;
        _likelihood = detail?.Inherent.Likelihood ?? 3;
        _impact = detail?.Inherent.Impact ?? 3;
        _controls = detail?.Controls ?? string.Empty;
        _residualLikelihood = detail?.Residual.Likelihood ?? 2;
        _residualImpact = detail?.Residual.Impact ?? 2;
        _treatment = detail?.Treatment ?? string.Empty;
        _rationale = detail?.AcceptanceRationale ?? string.Empty;
        _acceptanceExpiresOn = Date(detail?.AcceptanceExpiresOn);
        _targetDate = Date(detail?.TargetDate);
        _reviewDate = detail is null ? Today().AddDays(90) : Date(detail.ReviewDate);
        _status = detail?.Status ?? "open";
        _tickets = detail is null ? string.Empty : string.Join(Environment.NewLine, detail.Tickets);
        _note = string.Empty;
        _nextReviewDate = null;
        _reviewNote = string.Empty;
    }

    private async Task LoadChoicesAsync(long generation, IReadOnlyList<RiskRegisterLinkedEndpoint> linkedEndpoints, IReadOnlyList<RiskRegisterLinkedAlert> linkedAlerts)
    {
        var endpoints = linkedEndpoints.Select(endpoint => new RiskRegisterChoice(endpoint.EndpointId,
            endpoint.Enrolled ? endpoint.Name! : "Computer no longer enrolled (" + endpoint.EndpointId.ToString("D") + ")", true)).ToList();
        Replace(AlertChoices, linkedAlerts.Select(alert => new RiskRegisterChoice(alert.AlertId,
            alert.Exists ? alert.EndpointName + " · " + T(alert.Title!) + " (" + AlertRow.Label(alert.Severity) + ", " + AlertRow.Label(alert.Status) + ")" : T("Alert no longer recorded"), true)));
        Replace(EndpointChoices, endpoints);
        if (_devices is null) return;
        DeviceReadResult<IReadOnlyList<DeviceSummary>> result;
        try { result = await _devices.GetDevicesAsync(_cancellation.Token); }
        catch (OperationCanceledException) { return; }
        if (_disposed || generation != _detailGeneration) return;
        if (result.Outcome == DeviceReadOutcome.Unauthenticated)
        {
            ExpireSession();
            return;
        }

        if (result is not { Outcome: DeviceReadOutcome.Success, Value: { } devices })
        {
            _messageText = T("The list of computers could not be read; only the linked ones are shown.");
            Notify();
            return;
        }

        var linked = endpoints.Select(choice => choice.Id).ToHashSet();
        endpoints.AddRange(devices.Where(device => !linked.Contains(device.EndpointId)).OrderBy(device => device.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(device => new RiskRegisterChoice(device.EndpointId, device.Name, false)));
        Replace(EndpointChoices, endpoints);
    }

    private RiskRegisterDraft Draft() => new(_title.Trim(), Optional(_description), Optional(_owner), _likelihood, _impact, Optional(_controls),
        _residualLikelihood, _residualImpact, _treatment.Length == 0 ? null : _treatment, _treatment == "accept" ? Optional(_rationale) : null,
        _treatment == "accept" ? Day(_acceptanceExpiresOn) : null, Day(_targetDate), Day(_reviewDate), _status,
        EndpointChoices.Where(choice => choice.IsSelected).Select(choice => choice.Id).ToArray(),
        AlertChoices.Where(choice => choice.IsSelected).Select(choice => choice.Id).ToArray(),
        _tickets.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToArray(), Optional(_note));

    private void ExpireSession()
    {
        Clear();
        SessionExpired?.Invoke(this, EventArgs.Empty);
    }

    private DateTime Today() =>
        (_page?.Today ?? _detail?.Today) is { } text && Date(text) is { } today ? today : DateTime.UtcNow.Date;

    private static RiskRegisterRow Row(RiskRegisterSummary summary)
    {
        var attention = new List<string>();
        if (summary.Flags.ReviewOverdue) attention.Add(T("Review overdue"));
        if (summary.Flags.AcceptanceExpired) attention.Add(T("Acceptance expired"));
        if (summary.Flags.TargetDatePassed) attention.Add(T("Target date passed"));
        return new RiskRegisterRow(summary.RiskId, summary.Reference, summary.Title,
            summary.Residual.Score.ToString(CultureInfo.InvariantCulture) + " · " + LevelText(summary.Residual.Level), StatusText(summary.Status),
            TreatmentText(summary.Treatment), summary.Owner ?? "—", summary.ReviewDate ?? "—", string.Join(", ", attention));
    }

    private static string RatingText(int likelihood, int impact) => likelihood is >= 1 and <= 5 && impact is >= 1 and <= 5
        ? (likelihood * impact).ToString(CultureInfo.InvariantCulture) + " · " + LevelText((likelihood * impact) switch
        {
            <= 4 => "low", <= 9 => "medium", <= 16 => "high", _ => "critical"
        })
        : string.Empty;

    private static string LevelText(string level) => level switch { "low" => T("Low"), "medium" => T("Medium"), "high" => T("High"), _ => T("Critical") };

    private static string StatusText(string status) => status switch { "open" => T("Open"), "monitoring" => T("Monitoring"), _ => T("Closed") };

    private static string TreatmentText(string? treatment) => treatment switch
    {
        "avoid" => T("Avoid"), "mitigate" => T("Mitigate"), "transfer" => T("Transfer"), "accept" => T("Accept"), _ => T("Not decided")
    };

    private static string FieldLabel(string field) => field switch
    {
        "title" => T("Title"), "description" => T("Description"), "owner" => T("Owner"), "likelihood" => T("Likelihood"), "impact" => T("Impact"),
        "controls" => T("Existing controls"), "residualLikelihood" => T("Residual likelihood"), "residualImpact" => T("Residual impact"),
        "residual" => T("Residual risk"), "treatment" => T("Treatment"), "acceptanceRationale" => T("Acceptance rationale"),
        "acceptanceExpiresOn" => T("Acceptance expires on"), "targetDate" => T("Target date"), "reviewDate" => T("Review date"), "nextReviewDate" => T("Next review"),
        "status" => T("Status"), "endpointIds" => T("Computers"), "alertIds" => T("Alerts"), "tickets" => T("Tickets"), "note" => T("Note"), _ => field
    };

    /// <summary>Core's field codes in words.</summary>
    public static string ErrorText(RiskRegisterError error) => (error.Field, error.Code) switch
    {
        ("residual", "exceedsInherent") => T("Residual risk cannot be higher than the risk before controls."),
        ("owner", "requiredForAcceptance") => T("An accepted risk needs a named owner."),
        ("register", "full") => T("The Risk Register is full (2,000 records)."),
        ("history", "full") => T("This record has reached its limit of 200 changes. Close it and record a new one."),
        ("status", "closed") => T("A closed risk is not reviewed."),
        (var field, "required") => FieldLabel(field) + T(" is required."),
        (var field, "tooLong") => FieldLabel(field) + T(" is too long."),
        (var field, "invalid") => FieldLabel(field) + T(" contains a value or characters that cannot be saved."),
        (var field, "range") => FieldLabel(field) + T(" must be from 1 to 5."),
        (var field, "notFuture") => FieldLabel(field) + T(" must be after today."),
        (var field, "tooFar") => FieldLabel(field) + T(" can be at most one year ahead."),
        (var field, "past") => FieldLabel(field) + T(" cannot be in the past."),
        (var field, "onlyForAcceptance") => FieldLabel(field) + T(" applies only to an accepted risk."),
        (var field, "unknown") => FieldLabel(field) + T(" include one that no longer exists. Refresh the choices."),
        (var field, "duplicate") => FieldLabel(field) + T(" list the same entry twice."),
        (var field, "tooMany") => FieldLabel(field) + T(" list too many entries."),
        (var field, var code) => FieldLabel(field) + ": " + code + "."
    };

    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";

    private static string? Optional(string text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    private static string? Day(DateTime? date) => date?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static DateTime? Date(string? text) =>
        text is not null && DateTime.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;

    private static void Replace(ObservableCollection<RiskRegisterChoice> target, IEnumerable<RiskRegisterChoice> items)
    {
        target.Clear();
        foreach (var item in items) target.Add(item);
    }

    private void Set<T>(ref T field, T value)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        Notify();
    }

    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
}
