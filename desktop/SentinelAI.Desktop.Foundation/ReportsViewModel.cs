using System.ComponentModel;
using System.Globalization;

namespace SentinelAI.Desktop.Foundation;

public enum ReportState { NotGenerated, Generating, Ready, Unavailable }

/// <summary>
/// Explicit Core report generation and native saving. Views see metadata only;
/// this owner erases retained HTML when dates, navigation or the session change.
/// The authentication/composition owner retains both shared service lifetimes.
/// </summary>
public sealed class ReportsViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private readonly IReportsClient _client;
    private readonly IReportSaveService _saver;
    private readonly TimeProvider _time;
    private DateTime? _fromDate;
    private DateTime? _toDate;
    private SecurityReportDocument? _document;
    private ReportState _state;
    private string _statusText = "Choose inclusive UTC dates, then generate a security report.";
    private string _errorText = string.Empty;
    private string _saveStatusText = string.Empty;
    private long _generation;
    private Pending? _generatePending;
    private Pending? _savePending;
    private bool _disposed;

    public ReportsViewModel(IReportsClient client, IReportSaveService saveService, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(saveService);
        _client = client;
        _saver = saveService;
        _time = timeProvider ?? TimeProvider.System;
        SetDefaultDatesLocked();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public DateTime? FromDate
    {
        get { lock (_gate) return _fromDate; }
        set { lock (_gate) SetDateLocked(ref _fromDate, value); }
    }
    public DateTime? ToDate
    {
        get { lock (_gate) return _toDate; }
        set { lock (_gate) SetDateLocked(ref _toDate, value); }
    }
    public ReportState State { get { lock (_gate) return _state; } }
    public bool IsGenerating { get { lock (_gate) return _generatePending is not null; } }
    public bool IsSaving { get { lock (_gate) return _savePending is not null; } }
    public bool IsBusy { get { lock (_gate) return _generatePending is not null || _savePending is not null; } }
    public bool HasReport { get { lock (_gate) return _document is { ByteCount: > 0 }; } }
    public bool CanGenerate { get { lock (_gate) return !_disposed && !IsBusy && TryReadPeriodLocked(out _); } }
    public bool CanSave { get { lock (_gate) return !_disposed && !IsBusy && _state == ReportState.Ready && HasReport; } }
    public int ByteCount { get { lock (_gate) return _document?.ByteCount ?? 0; } }
    public string PeriodText { get { lock (_gate) return _document?.Period.DisplayText ?? string.Empty; } }
    public string SuggestedFileName { get { lock (_gate) return _document?.SuggestedFileName ?? string.Empty; } }
    public string ReportSizeText { get { lock (_gate) return _document is null ? string.Empty : ByteCount.ToString("N0", CultureInfo.InvariantCulture) + " bytes"; } }
    public string StatusText { get { lock (_gate) return _statusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public string SaveStatusText { get { lock (_gate) return _saveStatusText; } }
    public string ValidationText
    {
        get
        {
            lock (_gate) return TryReadPeriodLocked(out _) ? string.Empty :
                "Select ordered inclusive UTC dates, at most 366 days, ending before 9999-12-31.";
        }
    }

    private void SetDateLocked(ref DateTime? field, DateTime? value)
    {
        if (_disposed) return;
        // A DatePicker selects calendar dates, independent of the machine's
        // timezone or the Kind/time component on a programmatic value.
        DateTime? date = value is { } selected ? new DateTime(selected.Year, selected.Month, selected.Day) : null;
        if (field == date) return;
        field = date;
        ResetLocked(resetDates: false);
        NotifyAll();
    }

    public Task GenerateAsync()
    {
        lock (_gate)
        {
            if (_disposed || _savePending is not null) return Task.CompletedTask;
            if (_generatePending is not null) return _generatePending.Task;
            if (!TryReadPeriodLocked(out var period))
            {
                _errorText = ValidationText;
                NotifyAll();
                return Task.CompletedTask;
            }
            _document?.Dispose();
            _document = null;
            var pending = new Pending(++_generation);
            _generatePending = pending;
            _state = ReportState.Generating;
            _statusText = "Generating the security report through local Core…";
            _errorText = string.Empty;
            _saveStatusText = string.Empty;
            NotifyAll();
            _ = GenerateCoreAsync(pending, period!);
            return pending.Task;
        }
    }

    private async Task GenerateCoreAsync(Pending pending, ReportDateRange period)
    {
        SecurityReportDocument? received = null;
        try
        {
            var result = await _client.GenerateSecurityReportAsync(period, pending.Token);
            received = result.Document;
            lock (_gate)
            {
                if (!GenerateCurrent(pending)) return;
                if (result.Outcome == ReportOutcome.Unauthenticated)
                {
                    received?.Dispose();
                    received = null;
                    ExpireLocked();
                    return;
                }
                if (result.Outcome == ReportOutcome.Success && received is not null &&
                    received.Period == period && received.ByteCount is > 0 and <= SecurityReportDocument.MaximumBytes)
                {
                    _document = received;
                    received = null;
                    _state = ReportState.Ready;
                    _statusText = "Report generated. Save HTML to choose a destination.";
                    _errorText = string.Empty;
                }
                else SetFailureLocked(result.Outcome);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (GenerateCurrent(pending)) { SetFailureLocked(ReportOutcome.Unavailable); NotifyAll(); }
        }
        finally
        {
            // Includes canceled generations whose transport ignored cancellation.
            received?.Dispose();
            lock (_gate)
            {
                if (ReferenceEquals(_generatePending, pending)) _generatePending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(IsGenerating), nameof(IsBusy), nameof(CanGenerate), nameof(CanSave));
            }
        }
    }

    public Task SaveAsync()
    {
        lock (_gate)
        {
            if (_disposed || _generatePending is not null) return Task.CompletedTask;
            if (_savePending is not null) return _savePending.Task;
            if (!CanSave) return Task.CompletedTask;
            var pending = new Pending(++_generation);
            _savePending = pending;
            _saveStatusText = "Choose a destination for the generated HTML report.";
            _errorText = string.Empty;
            NotifyAll();
            // Pass ownership by reference, without copying HTML before the
            // destination dialog. Clear disposes this same object immediately.
            _ = SaveCoreAsync(pending, _document!);
            return pending.Task;
        }
    }

    private async Task SaveCoreAsync(Pending pending, SecurityReportDocument document)
    {
        try
        {
            var result = await _saver.SaveAsync(document, pending.Token);
            lock (_gate)
            {
                if (!SaveCurrent(pending, document)) return;
                switch (result.Outcome)
                {
                    case ReportSaveOutcome.Saved:
                        _saveStatusText = string.IsNullOrEmpty(result.FileName) ? "Report saved." : "Report saved as " + result.FileName + ".";
                        break;
                    case ReportSaveOutcome.Cancelled:
                        _saveStatusText = "Save cancelled. The generated report remains available.";
                        break;
                    default:
                        SetSaveFailureLocked();
                        break;
                }
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (SaveCurrent(pending, document)) { SetSaveFailureLocked(); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_savePending, pending)) _savePending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(IsSaving), nameof(IsBusy), nameof(CanGenerate), nameof(CanSave));
            }
        }
    }

    private bool GenerateCurrent(Pending pending) => !_disposed && pending.Generation == _generation &&
        ReferenceEquals(_generatePending, pending) && !pending.Token.IsCancellationRequested;
    private bool SaveCurrent(Pending pending, SecurityReportDocument document) => !_disposed && pending.Generation == _generation &&
        ReferenceEquals(_savePending, pending) && ReferenceEquals(_document, document) && !pending.Token.IsCancellationRequested;

    private bool TryReadPeriodLocked(out ReportDateRange? period)
    {
        period = _fromDate is { } from && _toDate is { } to
            ? new ReportDateRange(DateOnly.FromDateTime(from), DateOnly.FromDateTime(to)) : null;
        return period is { IsValid: true };
    }

    private void SetFailureLocked(ReportOutcome outcome)
    {
        _state = ReportState.Unavailable;
        _statusText = "The report was not generated.";
        _errorText = outcome switch
        {
            ReportOutcome.CapacityExceeded => "The report exceeds Core's supported dataset or output capacity.",
            ReportOutcome.TooLarge => "The report exceeds the supported download size. Choose a shorter period.",
            ReportOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
            ReportOutcome.InvalidResponse or ReportOutcome.Success => "Core returned an invalid security report.",
            ReportOutcome.InvalidPeriod => "Core rejected the report period. Choose ordered inclusive UTC dates of at most 366 days.",
            _ => "Local Core is unavailable. Restore Core, then generate the report again."
        };
    }
    private void SetSaveFailureLocked()
    {
        _saveStatusText = "The report was not saved.";
        _errorText = "The report could not be saved. Choose a destination and try again.";
    }
    private void SetDefaultDatesLocked()
    {
        var today = DateOnly.FromDateTime(_time.GetUtcNow().UtcDateTime);
        var thisMonth = new DateOnly(today.Year, today.Month, 1);
        if (thisMonth == DateOnly.MinValue)
        {
            _fromDate = null;
            _toDate = null;
            return;
        }
        var last = thisMonth.AddDays(-1);
        _fromDate = new DateTime(last.Year, last.Month, 1);
        _toDate = new DateTime(last.Year, last.Month, last.Day);
    }
    private void ResetLocked(bool resetDates)
    {
        _generation++;
        _generatePending?.Cancel();
        _savePending?.Cancel();
        _generatePending = null;
        _savePending = null;
        _document?.Dispose();
        _document = null;
        if (resetDates) SetDefaultDatesLocked();
        _state = ReportState.NotGenerated;
        _statusText = "Choose inclusive UTC dates, then generate a security report.";
        _errorText = string.Empty;
        _saveStatusText = string.Empty;
    }
    private void ExpireLocked()
    {
        ResetLocked(resetDates: true);
        NotifyAll();
        SessionExpired?.Invoke(this, EventArgs.Empty);
    }
    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            ResetLocked(resetDates: true);
            NotifyAll();
        }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ResetLocked(resetDates: true);
        }
    }
    private void NotifyAll() => Notify(nameof(FromDate), nameof(ToDate), nameof(State), nameof(IsGenerating),
        nameof(IsSaving), nameof(IsBusy), nameof(CanGenerate), nameof(CanSave), nameof(HasReport), nameof(ByteCount),
        nameof(PeriodText), nameof(SuggestedFileName), nameof(ReportSizeText), nameof(StatusText), nameof(ErrorText),
        nameof(ValidationText), nameof(SaveStatusText));
    private void Notify(params string[] properties)
    {
        foreach (var property in properties) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
    }

    private sealed class Pending
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Pending(long generation) { Generation = generation; Token = _cancellation.Token; }
        internal long Generation { get; }
        internal CancellationToken Token { get; }
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _cancellation.Dispose(); _completion.TrySetResult(); }
    }
}
