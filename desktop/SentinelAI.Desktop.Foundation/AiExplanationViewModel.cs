using System.ComponentModel;
using SentinelAI.Contracts.Ai;

namespace SentinelAI.Desktop.Foundation;

public enum AiExplanationState
{
    NoAlert, Unsupported, AvailabilityUnknown, Disabled, NotRequested, Requesting, Ready, Unavailable
}

/// <summary>Read-only assistive analysis owned by the current alert and authenticated workspace.</summary>
public sealed class AiExplanationViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private readonly IAiExplanationClient _client;
    private Guid? _alertId;
    private long _alertVersion;
    private bool _supported;
    private bool? _permitted;
    private bool _cloudRequestsEnabled;
    private AiExplanation? _analysis;
    private AiExplanationState _state;
    private string _statusText = "Select a supported local alert to request AI assistive analysis.";
    private string _errorText = string.Empty;
    private long _generation;
    private Pending? _pending;
    private bool _disposed;

    public AiExplanationViewModel(IAiExplanationClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public Guid? SelectedAlertId { get { lock (_gate) return _alertId; } }
    public bool IsSupportedAlert { get { lock (_gate) return _supported; } }
    public bool CanExplain { get { lock (_gate) return !_disposed && _cloudRequestsEnabled && _supported && _permitted == true && _pending is null; } }
    /// <summary>Explicit local opt-in for this workspace session; it never changes Core configuration.</summary>
    public bool CloudRequestsEnabled
    {
        get { lock (_gate) return _cloudRequestsEnabled; }
        set
        {
            lock (_gate)
            {
                if (_disposed || _cloudRequestsEnabled == value) return;
                ResetOperationLocked();
                _cloudRequestsEnabled = value;
                SetIdleStateLocked();
                NotifyAll();
            }
        }
    }
    public bool IsBusy { get { lock (_gate) return _pending is not null; } }
    public bool HasAnalysis { get { lock (_gate) return _analysis is not null; } }
    public AiExplanationState State { get { lock (_gate) return _state; } }
    public string Label => AiContract.AssistiveLabel;
    public AiExplanation? Analysis { get { lock (_gate) return _analysis; } }
    public string StatusText { get { lock (_gate) return _statusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }

    public void SetAlert(AlertDetail? detail)
    {
        lock (_gate)
        {
            if (_disposed) return;
            var id = detail?.Alert?.AlertId is { } value && value != Guid.Empty ? value : (Guid?)null;
            var version = detail?.Alert?.Version ?? 0;
            var supported = AiExplanationSupport.IsSupported(detail);
            if (_alertId == id && _alertVersion == version && _supported == supported) return;
            ResetOperationLocked();
            _alertId = id;
            _alertVersion = version;
            _supported = supported;
            SetIdleStateLocked();
            NotifyAll();
        }
    }

    public void SetAvailability(bool? cloudAiPermitted)
    {
        lock (_gate)
        {
            if (_disposed || _permitted == cloudAiPermitted) return;
            ResetOperationLocked();
            _permitted = cloudAiPermitted;
            SetIdleStateLocked();
            NotifyAll();
        }
    }

    public Task ExplainAsync()
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_pending is not null) return _pending.Task;
            if (!CanExplain) return Task.CompletedTask;
            _analysis = null;
            _errorText = string.Empty;
            var pending = new Pending(++_generation);
            _pending = pending;
            _state = AiExplanationState.Requesting;
            _statusText = "Requesting AI assistive analysis through Core… Local security functions remain available.";
            NotifyAll();
            _ = ExplainCoreAsync(pending, _alertId!.Value);
            return pending.Task;
        }
    }

    private async Task ExplainCoreAsync(Pending pending, Guid alertId)
    {
        try
        {
            var result = await _client.ExplainAlertAsync(alertId, pending.Token);
            lock (_gate)
            {
                if (!Current(pending)) return;
                if (result.Outcome == AiExplanationOutcome.Unauthenticated)
                {
                    ResetAllLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == AiExplanationOutcome.Success && AiContract.IsValidAnalysis(result.Analysis))
                {
                    // Clone bounded lists so an injected service cannot mutate visible analysis.
                    var analysis = result.Analysis!;
                    _analysis = analysis with
                    {
                        RecommendedInvestigation = Array.AsReadOnly(analysis.RecommendedInvestigation.ToArray()),
                        SuggestedRemediation = Array.AsReadOnly(analysis.SuggestedRemediation.ToArray())
                    };
                    _state = AiExplanationState.Ready;
                    _statusText = "AI suggestions require administrator review. Confidence is qualitative, not a detection probability.";
                    _errorText = string.Empty;
                }
                else SetFailureLocked(result.Outcome);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (Current(pending)) { SetFailureLocked(AiExplanationOutcome.Unavailable); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(IsBusy), nameof(CanExplain));
            }
        }
    }

    private bool Current(Pending pending) => !_disposed && pending.Generation == _generation &&
        ReferenceEquals(_pending, pending) && !pending.Token.IsCancellationRequested;

    private void SetFailureLocked(AiExplanationOutcome outcome)
    {
        _analysis = null;
        _state = outcome == AiExplanationOutcome.Disabled ? AiExplanationState.Disabled :
            outcome == AiExplanationOutcome.Unsupported ? AiExplanationState.Unsupported : AiExplanationState.Unavailable;
        if (outcome == AiExplanationOutcome.Disabled) _permitted = false;
        if (outcome is AiExplanationOutcome.Unsupported or AiExplanationOutcome.NotFound) _supported = false;
        _statusText = "AI analysis was not produced. Local alert, risk and monitoring functions remain available.";
        _errorText = outcome switch
        {
            AiExplanationOutcome.Disabled => "Core does not currently permit cloud AI. Check licensing; Safe Mode preserves local security functions.",
            AiExplanationOutcome.Unsupported => "Core cannot explain this alert's supported evidence.",
            AiExplanationOutcome.NotFound => "The selected alert is no longer available. Refresh local alerts.",
            AiExplanationOutcome.Throttled => "AI requests are temporarily limited. Wait before explicitly trying again.",
            AiExplanationOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
            AiExplanationOutcome.InvalidResponse or AiExplanationOutcome.Success => "Core returned invalid AI analysis. No suggestions are shown.",
            _ => "AI is unavailable or not configured. Restore availability, then explicitly try again."
        };
    }

    private void SetIdleStateLocked()
    {
        _errorText = string.Empty;
        if (_alertId is null)
        {
            _state = AiExplanationState.NoAlert;
            _statusText = "Select a supported local alert to request AI assistive analysis.";
        }
        else if (!_supported)
        {
            _state = AiExplanationState.Unsupported;
            _statusText = "AI explanation is unavailable for this alert's rule or evidence. Local alert details remain available.";
        }
        else if (!_cloudRequestsEnabled)
        {
            _state = AiExplanationState.Disabled;
            _statusText = "Cloud AI requests are turned off in this Desktop session. Enable them in Settings before explicitly requesting an explanation.";
        }
        else if (_permitted is null)
        {
            _state = AiExplanationState.AvailabilityUnknown;
            _statusText = "Cloud AI permission has not been verified. Refresh licensing before requesting an explanation.";
        }
        else if (_permitted == false)
        {
            _state = AiExplanationState.Disabled;
            _statusText = "Cloud AI is not permitted by the current license. Safe Mode preserves local security functions.";
        }
        else
        {
            _state = AiExplanationState.NotRequested;
            _statusText = "Explain with AI sends only this stored alert's minimized supported context through Core. No request starts automatically.";
        }
    }

    private void ResetOperationLocked()
    {
        _generation++;
        _pending?.Cancel();
        _pending = null;
        _analysis = null;
        _errorText = string.Empty;
    }

    private void ResetAllLocked()
    {
        ResetOperationLocked();
        _alertId = null;
        _alertVersion = 0;
        _supported = false;
        _permitted = null;
        _cloudRequestsEnabled = false;
        SetIdleStateLocked();
    }

    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            ResetAllLocked();
            NotifyAll();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ResetAllLocked();
            NotifyAll();
        }
    }

    private void NotifyAll() => Notify(nameof(SelectedAlertId), nameof(IsSupportedAlert), nameof(CanExplain),
        nameof(CloudRequestsEnabled), nameof(IsBusy), nameof(HasAnalysis), nameof(State), nameof(Label), nameof(Analysis), nameof(StatusText), nameof(ErrorText));
    private void Notify(params string[] names)
    {
        foreach (var name in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private sealed class Pending(long generation)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _completion.TrySetResult(); _cancellation.Dispose(); }
    }
}
