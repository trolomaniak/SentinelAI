using System.ComponentModel;
using System.Globalization;

namespace SentinelAI.Desktop.Foundation;

public enum LicenseState { NotLoaded, Loading, Ready, Renewing, Unavailable }

/// <summary>Public Core licensing state with one explicit, non-retried manual renewal.</summary>
public sealed class LicenseViewModel : INotifyPropertyChanged, IDisposable
{
    private const string InitialStatus = "Refresh to read the current Core licensing state.";
    private const string InitialRenewal = "No manual renewal requested in this session.";
    private readonly object _gate = new();
    private readonly ILicenseClient _client;
    private LicenseStatus? _status;
    private LicenseState _state;
    private string _statusText = InitialStatus;
    private string _renewalStatusText = InitialRenewal;
    private string _errorText = string.Empty;
    private bool _requiresRefresh;
    private long _generation;
    private Pending? _pending;
    private bool _disposed;

    public LicenseViewModel(ILicenseClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public LicenseState State { get { lock (_gate) return _state; } }
    public LicenseStatus? Status { get { lock (_gate) return _status; } }
    public string StatusText { get { lock (_gate) return _statusText; } }
    public string RenewalStatusText { get { lock (_gate) return _renewalStatusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public bool IsBusy { get { lock (_gate) return _pending is not null; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _pending is null; } }
    public bool CanRenew { get { lock (_gate) return !_disposed && _pending is null && !_requiresRefresh && _status is not null && _status.Mode != "RECOVERING"; } }
    public bool RequiresRefresh { get { lock (_gate) return _requiresRefresh; } }
    public string ModeText { get { lock (_gate) return _status?.Mode ?? "Not loaded"; } }
    public string FeaturesText { get { lock (_gate) return _status is null ? "Not loaded" : _status.EnabledFeatures.Count == 0 ? "No optional features permitted." : string.Join(", ", _status.EnabledFeatures); } }
    public string LastValidationText { get { lock (_gate) return _status is null ? "Not loaded" : Timestamp(_status.LastSuccessfulValidationUtc, "No signed validation"); } }
    public string FullModeUntilText { get { lock (_gate) return _status is null ? "Not loaded" : Timestamp(_status.FullModeUntil, "No signed expiry"); } }
    public string EffectiveTimeText { get { lock (_gate) return _status is null ? "Not loaded" : Timestamp(_status.EffectiveUtc, string.Empty); } }
    public string ClockRollbackText { get { lock (_gate) return _status is null ? "Not loaded" : _status.ClockRollbackDetected ? "Detected. Core retains its effective UTC time floor." : "Not detected by Core."; } }
    public string LocalSecurityText
    {
        get
        {
            lock (_gate)
            {
                if (_status is null) return "Local monitoring remains independent of license renewal.";
                var capabilities = _status.Capabilities;
                return capabilities.CriticalTelemetryCollection && capabilities.LocalDetectionRules && capabilities.CriticalAlerts && capabilities.RecentIncidents && capabilities.EmergencyExport
                    ? "Local monitoring, detection, alerts, incidents and emergency export remain permitted."
                    : "Review Core's reported local capabilities.";
            }
        }
    }

    public Task RefreshAsync() => BeginRequest(renew: false);
    public Task RenewAsync() => BeginRequest(renew: true);
    private Task BeginRequest(bool renew)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_pending is not null) return _pending.Task;
            if (renew && !CanRenew) return Task.CompletedTask;
            var pending = new Pending(++_generation, renew);
            _pending = pending;
            _status = null;
            _state = renew ? LicenseState.Renewing : LicenseState.Loading;
            _statusText = renew ? "Core is attempting license renewal…" : "Reading the current Core licensing state…";
            _errorText = string.Empty;
            if (renew) _renewalStatusText = "One manual renewal attempt is in progress.";
            NotifyAll();
            _ = CompleteRequestAsync(pending);
            return pending.Task;
        }
    }
    private async Task CompleteRequestAsync(Pending pending)
    {
        try
        {
            var result = pending.Renew
                ? await _client.RenewLicenseAsync(pending.Token)
                : await _client.GetLicenseAsync(pending.Token);
            lock (_gate)
            {
                if (!Current(pending)) return;
                if (result.Outcome == LicenseRequestOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome == LicenseRequestOutcome.Success && ValidStatus(result.Status))
                {
                    _status = result.Status! with { EnabledFeatures = Array.AsReadOnly(result.Status!.EnabledFeatures.ToArray()) };
                    _state = LicenseState.Ready;
                    _statusText = ModeDescription(_status!.Mode);
                    _requiresRefresh = false;
                    _errorText = string.Empty;
                    if (pending.Renew) _renewalStatusText = _status.Mode switch
                    {
                        "FULL" => "Renewal completed. Core reports FULL.",
                        "RECOVERING" => "Core reports renewal in progress. Refresh for its current status.",
                        _ => "Renewal completed without restoring FULL. Core reports " + _status.Mode + "."
                    };
                    else if (_renewalStatusText != InitialRenewal) _renewalStatusText = "Status refreshed. Core's current mode is " + _status.Mode + ".";
                }
                else SetFailureLocked(result.Outcome, pending.Renew);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (Current(pending))
                {
                    SetFailureLocked(pending.Renew ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable, pending.Renew);
                    NotifyAll();
                }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(IsBusy), nameof(CanRefresh), nameof(CanRenew));
            }
        }
    }
    private void SetFailureLocked(LicenseRequestOutcome outcome, bool renew)
    {
        _status = null;
        _state = LicenseState.Unavailable;
        // A malformed successful write response is just as uncertain as a lost response.
        if (renew && outcome is LicenseRequestOutcome.Indeterminate or LicenseRequestOutcome.InvalidResponse or LicenseRequestOutcome.TooLarge or LicenseRequestOutcome.Success)
        {
            _requiresRefresh = true;
            _errorText = "The renewal result is unknown. Refresh license status before requesting another renewal.";
        }
        else _errorText = outcome switch
        {
            LicenseRequestOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
            LicenseRequestOutcome.Throttled => "Core rate limited this request. Wait, then refresh license status.",
            LicenseRequestOutcome.InvalidResponse or LicenseRequestOutcome.Success => "Core returned an invalid license response. Refresh license status.",
            LicenseRequestOutcome.TooLarge => "The license response exceeds the supported size.",
            _ => renew ? "License renewal is unavailable. Check Core's renewal configuration, then refresh license status." : "Local Core is unavailable. Restore Core, then refresh license status."
        };
        _statusText = _errorText;
        if (renew) _renewalStatusText = _errorText;
    }
    private static string ModeDescription(string mode) => mode switch
    {
        "FULL" => "Core reports FULL. Its permitted optional features are available.",
        "GRACE" => "Core reports GRACE after a failed renewal. Its retained optional permissions remain authoritative.",
        "SAFE_MODE" => "Core reports SAFE_MODE. Local security functions remain available; optional features are withheld.",
        _ => "Core reports RECOVERING. An attempt is in progress; underlying permissions remain authoritative."
    };
    private static bool ValidStatus(LicenseStatus? status) => status is { Capabilities: not null, EnabledFeatures: not null } &&
        status.Mode is "FULL" or "GRACE" or "SAFE_MODE" or "RECOVERING" && status.EnabledFeatures.Count <= 64 &&
        status.EnabledFeatures.All(feature => feature is { Length: > 0 and <= 64 } && feature.All(character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-')) &&
        status.EnabledFeatures.Distinct(StringComparer.Ordinal).Count() == status.EnabledFeatures.Count &&
        status.EffectiveUtc.Offset == TimeSpan.Zero && status.LastSuccessfulValidationUtc?.Offset is null or { Ticks: 0 } &&
        status.FullModeUntil?.Offset is null or { Ticks: 0 };
    private static string Timestamp(DateTimeOffset? value, string missing) => value?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? missing;
    private bool Current(Pending pending) => !_disposed && pending.Generation == _generation && ReferenceEquals(_pending, pending) && !pending.Token.IsCancellationRequested;
    private void ExpireLocked()
    {
        ClearLocked();
        NotifyAll();
        SessionExpired?.Invoke(this, EventArgs.Empty);
    }
    private void ClearLocked()
    {
        _generation++;
        _pending?.Cancel();
        _pending = null;
        _status = null;
        _state = LicenseState.NotLoaded;
        _statusText = InitialStatus;
        _renewalStatusText = InitialRenewal;
        _errorText = string.Empty;
        _requiresRefresh = false;
    }
    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            ClearLocked();
            NotifyAll();
        }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ClearLocked();
        }
    }
    private void NotifyAll() => Notify(nameof(State), nameof(Status), nameof(StatusText), nameof(RenewalStatusText), nameof(ErrorText),
        nameof(IsBusy), nameof(CanRefresh), nameof(CanRenew), nameof(RequiresRefresh), nameof(ModeText), nameof(FeaturesText),
        nameof(LastValidationText), nameof(FullModeUntilText), nameof(EffectiveTimeText), nameof(ClockRollbackText), nameof(LocalSecurityText));
    private void Notify(params string[] names)
    {
        foreach (var name in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
    private sealed class Pending(long generation, bool renew)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal bool Renew { get; } = renew;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _cancellation.Dispose(); _completion.TrySetResult(); }
    }
}
