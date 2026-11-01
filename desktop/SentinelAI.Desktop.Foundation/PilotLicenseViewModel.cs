using System.ComponentModel;
using System.Globalization;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum PilotLicenseState { NotLoaded, Loading, Ready, Submitting, Unavailable }

/// <summary>
/// MVP-3 pilot license for Settings → License and the shell notices. Core decides the state; monitoring never depends
/// on it. The warning and the ended notice can be hidden until sign-out; "Uninstall SentinelAI" opens the existing
/// Setup uninstall view, which retains data unless DELETE is typed there.
/// </summary>
public sealed class PilotLicenseViewModel : INotifyPropertyChanged, IDisposable
{
    private static string NotApplicable => T("Not applicable");
    private readonly object _gate = new();
    private readonly IPilotLicenseClient _client;
    private readonly ISetupUninstallLauncher? _uninstall;
    private PilotLicenseInfo? _info;
    private PilotLicenseState _state;
    private string _errorText = string.Empty;
    private string _submitStatusText = string.Empty;
    private string _uninstallStatusText = string.Empty;
    private string _keyText = string.Empty;
    private string? _hiddenState;
    private long _generation;
    private Pending? _pending;
    private bool _disposed;

    public PilotLicenseViewModel(IPilotLicenseClient client, ISetupUninstallLauncher? uninstall)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _uninstall = uninstall;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    /// <summary>Setup's uninstall refuses to run beside Desktop, so Desktop exits once Setup has started.</summary>
    public event EventHandler? ExitRequested;
    public PilotLicenseState State { get { lock (_gate) return _state; } }
    public PilotLicenseInfo? Info { get { lock (_gate) return _info; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public string SubmitStatusText { get { lock (_gate) return _submitStatusText; } }
    public string UninstallStatusText { get { lock (_gate) return _uninstallStatusText; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _pending is null; } }
    public bool CanSubmit { get { lock (_gate) return !_disposed && _pending is null && _keyText.Trim().Length > 0 && _info?.State != "unavailable"; } }
    public bool CanUninstall { get { lock (_gate) return !_disposed && _uninstall is not null && _info?.State == "ended"; } }

    public string KeyText
    {
        get { lock (_gate) return _keyText; }
        set
        {
            lock (_gate)
            {
                if (_disposed || _keyText == (value ?? string.Empty)) return;
                _keyText = value ?? string.Empty;
            }
            Notify(nameof(KeyText), nameof(CanSubmit));
        }
    }

    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (_info is not { } info) return _state == PilotLicenseState.Loading ? T("Reading the pilot license…") : T("Not loaded");
                return info.State switch
                {
                    "unavailable" => T("This SentinelAI build does not use pilot license keys."),
                    "none" => T("No pilot license key has been entered."),
                    "invalid" => T("The stored pilot license key is not valid. Enter a new key."),
                    "scheduled" => T("The pilot for ") + info.Customer + T(" starts on ") + Date(info.StartsUtc) + ".",
                    "active" => T("The pilot for ") + info.Customer + T(" is active."),
                    "ending" => EndingText(info.DaysLeft),
                    _ => T("The pilot for ") + info.Customer + T(" has ended. All monitoring continues.")
                };
            }
        }
    }
    public string CustomerText { get { lock (_gate) return _info?.Customer ?? NotApplicable; } }
    public string ExpiresText { get { lock (_gate) return _info?.ExpiresUtc is { } expires ? Date(expires) : NotApplicable; } }
    public string DaysLeftText { get { lock (_gate) return _info?.DaysLeft?.ToString(CultureInfo.InvariantCulture) ?? NotApplicable; } }

    public bool IsNoticeVisible { get { lock (_gate) return _info?.State is "ending" or "ended" && _info.State != _hiddenState; } }
    public bool IsEnded { get { lock (_gate) return _info?.State == "ended"; } }
    public string NoticeTitle
    {
        get
        {
            lock (_gate)
                return _info?.State switch
                {
                    "ending" => EndingText(_info.DaysLeft),
                    "ended" => T("Your SentinelAI pilot has ended"),
                    _ => string.Empty
                };
        }
    }
    public string NoticeText
    {
        get
        {
            lock (_gate)
                return _info?.State switch
                {
                    "ending" => T("Monitoring continues after the pilot ends. To keep using SentinelAI, contact us for a license key."),
                    "ended" => T("All monitoring continues. To keep using SentinelAI, contact us for a license key. To remove SentinelAI, use Uninstall SentinelAI below: your data is kept unless you choose to delete it in Setup."),
                    _ => string.Empty
                };
        }
    }
    public string ContactText
    {
        get
        {
            lock (_gate)
            {
                if (_info?.Contact is not { } contact) return T("Contact your SentinelAI provider.");
                var lines = new List<string> { contact.Company };
                if (contact.Email.Length != 0) lines.Add(T("E-mail: ") + contact.Email);
                if (contact.Phone.Length != 0) lines.Add(T("Phone: ") + contact.Phone);
                if (contact.Website.Length != 0) lines.Add(T("Website: ") + contact.Website);
                return string.Join(Environment.NewLine, lines);
            }
        }
    }

    public Task RefreshAsync() => Begin(null);

    public Task SubmitAsync()
    {
        string key;
        lock (_gate)
        {
            if (!CanSubmit) return _pending?.Task ?? Task.CompletedTask;
            key = _keyText;
        }
        return Begin(key);
    }

    /// <summary>Hides the current notice until sign-out; a new state (warning → ended) shows again.</summary>
    public void HideNotice()
    {
        lock (_gate)
        {
            if (_disposed || _info?.State is not ("ending" or "ended")) return;
            _hiddenState = _info.State;
        }
        Notify(nameof(IsNoticeVisible));
    }

    public void StartUninstall()
    {
        ISetupUninstallLauncher launcher;
        lock (_gate)
        {
            if (!CanUninstall) return;
            launcher = _uninstall!;
        }
        UninstallLaunchOutcome outcome;
        try { outcome = launcher.Start(); }
        catch (Exception) { outcome = UninstallLaunchOutcome.Unavailable; }
        lock (_gate)
        {
            if (_disposed) return;
            _uninstallStatusText = outcome switch
            {
                UninstallLaunchOutcome.Started => T("SentinelAI Setup opened with Uninstall selected, and Desktop closes so it can continue. Your data is kept unless you type DELETE there."),
                UninstallLaunchOutcome.Cancelled => T("Uninstall was not started."),
                _ => T("SentinelAI Setup could not be started. Uninstall SentinelAI from Windows Settings → Apps instead.")
            };
        }
        Notify(nameof(UninstallStatusText));
        if (outcome == UninstallLaunchOutcome.Started) ExitRequested?.Invoke(this, EventArgs.Empty);
    }

    private Task Begin(string? key)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_pending is not null) return _pending.Task;
            var pending = new Pending(++_generation, key);
            _pending = pending;
            if (key is null)
            {
                // Keep the shown pilot while rereading so the shell notice does not flicker on navigation.
                _state = PilotLicenseState.Loading;
                _errorText = string.Empty;
            }
            else
            {
                _state = PilotLicenseState.Submitting;
                _submitStatusText = T("Core is checking the pilot license key…");
            }
            NotifyAll();
            _ = CompleteAsync(pending);
            return pending.Task;
        }
    }

    private async Task CompleteAsync(Pending pending)
    {
        try
        {
            var result = pending.Key is null
                ? await _client.GetPilotLicenseAsync(pending.Token)
                : await _client.SetPilotLicenseKeyAsync(pending.Key, pending.Token);
            lock (_gate)
            {
                if (!Current(pending)) return;
                if (result.Outcome == PilotLicenseOutcome.Unauthenticated)
                {
                    ClearLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == PilotLicenseOutcome.Success && result.Info is not null)
                {
                    _info = result.Info;
                    _state = PilotLicenseState.Ready;
                    _errorText = string.Empty;
                    if (pending.Key is not null)
                    {
                        _keyText = string.Empty;
                        _submitStatusText = T("Pilot license key accepted. ") + StatusText;
                    }
                }
                else if (pending.Key is not null && result.Outcome is PilotLicenseOutcome.Rejected or PilotLicenseOutcome.Expired or PilotLicenseOutcome.NotConfigured)
                {
                    // Core refused the key and kept the current one.
                    _state = _info is null ? PilotLicenseState.NotLoaded : PilotLicenseState.Ready;
                    _submitStatusText = result.Outcome switch
                    {
                        PilotLicenseOutcome.Rejected => T("This is not a valid SentinelAI pilot license key. Check that the whole key was copied."),
                        PilotLicenseOutcome.Expired => T("This pilot license key has already expired. Contact us for a new key."),
                        _ => T("This SentinelAI build does not accept pilot license keys.")
                    };
                }
                else SetFailureLocked(result.Outcome, pending.Key is not null);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (Current(pending))
                {
                    SetFailureLocked(PilotLicenseOutcome.Unavailable, pending.Key is not null);
                    NotifyAll();
                }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanRefresh), nameof(CanSubmit), nameof(CanUninstall));
            }
        }
    }

    private void SetFailureLocked(PilotLicenseOutcome outcome, bool submitted)
    {
        // Whether a submitted key was stored is unknown; only a fresh read is authoritative. A failed read keeps the last
        // state Core reported, so the ended notice stays while Core restarts or is busy.
        if (submitted) _info = null;
        _state = PilotLicenseState.Unavailable;
        _errorText = outcome switch
        {
            PilotLicenseOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
            PilotLicenseOutcome.InvalidResponse or PilotLicenseOutcome.TooLarge or PilotLicenseOutcome.Success => T("Core returned an invalid pilot license response. Refresh license status."),
            _ => T("Local Core is unavailable. Restore Core, then refresh license status.")
        };
        if (submitted) _submitStatusText = T("The result is unknown. Refresh license status to see whether the key was accepted.");
    }

    private static string EndingText(int? daysLeft) => daysLeft == 1 ? T("Pilot ends in 1 day — contact us") : F("Pilot ends in {0} days — contact us", daysLeft);
    private static string Date(DateTimeOffset? value) => value?.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) ?? NotApplicable;
    private bool Current(Pending pending) => !_disposed && pending.Generation == _generation && ReferenceEquals(_pending, pending) && !pending.Token.IsCancellationRequested;

    private void ClearLocked()
    {
        _generation++;
        _pending?.Cancel();
        _pending = null;
        _info = null;
        _state = PilotLicenseState.NotLoaded;
        _errorText = string.Empty;
        _submitStatusText = string.Empty;
        _uninstallStatusText = string.Empty;
        _keyText = string.Empty;
        _hiddenState = null;
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

    private void NotifyAll() => Notify(nameof(State), nameof(Info), nameof(ErrorText), nameof(SubmitStatusText), nameof(UninstallStatusText),
        nameof(CanRefresh), nameof(CanSubmit), nameof(CanUninstall), nameof(KeyText), nameof(StatusText), nameof(CustomerText), nameof(ExpiresText),
        nameof(DaysLeftText), nameof(IsNoticeVisible), nameof(IsEnded), nameof(NoticeTitle), nameof(NoticeText), nameof(ContactText));

    private void Notify(params string[] names)
    {
        foreach (var name in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private sealed class Pending(long generation, string? key)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal string? Key { get; } = key;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _cancellation.Dispose(); _completion.TrySetResult(); }
    }
}
