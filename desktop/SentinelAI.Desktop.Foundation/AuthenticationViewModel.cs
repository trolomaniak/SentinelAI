using System.ComponentModel;

namespace SentinelAI.Desktop.Foundation;

public enum AuthenticationState
{
    Initializing,
    SetupRequired,
    SignedOut,
    SignedIn,
    Unavailable,
    PermissionRequired,
    UntrustedInstallation
}

/// <summary>
/// Native authentication flow with no password/session properties. One operation runs
/// at a time, and sign-out/shutdown cancel work and reject every obsolete completion.
/// </summary>
public sealed class AuthenticationViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private readonly IAuthenticationClient _authentication;
    private readonly IAdministratorSetupClient _setup;
    private CancellationTokenSource? _operationCancellation;
    private Task? _activeOperation;
    private long _generation;
    private bool _disposed;
    private bool _isBusy;
    private AuthenticationState _state = AuthenticationState.Initializing;
    private string _username = string.Empty;
    private string _displayName = string.Empty;
    private string _statusText = "Checking local administrator setup…";
    private string _errorText = string.Empty;

    public AuthenticationViewModel(IAuthenticationClient authentication, IAdministratorSetupClient setup)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(setup);
        _authentication = authentication;
        _setup = setup;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public AuthenticationState State { get { lock (_gate) return _state; } }
    public string DisplayName { get { lock (_gate) return _displayName; } }
    public string StatusText { get { lock (_gate) return _statusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public bool IsBusy { get { lock (_gate) return _isBusy; } }
    public bool IsSignedIn { get { lock (_gate) return _state == AuthenticationState.SignedIn; } }
    public bool RequiresElevation { get { lock (_gate) return !_disposed && _state == AuthenticationState.PermissionRequired; } }
    public bool CanSignIn
    {
        get
        {
            lock (_gate) return CanOperate && ValidUsername(_username) &&
                _state is AuthenticationState.SignedOut or AuthenticationState.Unavailable or AuthenticationState.PermissionRequired;
        }
    }
    public bool CanCreateAdministrator
    {
        get { lock (_gate) return CanOperate && ValidUsername(_username) && _state == AuthenticationState.SetupRequired; }
    }

    public string Username
    {
        get { lock (_gate) return _username; }
        set
        {
            lock (_gate)
            {
                if (_disposed) return;
                value ??= string.Empty;
                if (_username == value) return;
                _username = value;
                _errorText = string.Empty;
                Notify(nameof(Username), nameof(ErrorText), nameof(CanSignIn), nameof(CanCreateAdministrator));
            }
        }
    }

    public Task InitializeAsync() => RunOperationAsync(async (generation, cancellationToken) =>
    {
        var state = await _setup.GetStateAsync(cancellationToken);
        Apply(generation, () =>
        {
            _displayName = string.Empty;
            switch (state)
            {
                case AdministratorSetupState.Required:
                    SetState(AuthenticationState.SetupRequired, "Create your local administrator account.");
                    break;
                case AdministratorSetupState.Initialized:
                    SetState(AuthenticationState.SignedOut, "Sign in to local Core.");
                    break;
                case AdministratorSetupState.PermissionRequired:
                    SetState(AuthenticationState.PermissionRequired, "Sign in to local Core, or use administrator permission for initial setup.");
                    break;
                case AdministratorSetupState.UntrustedInstallation:
                    SetState(AuthenticationState.UntrustedInstallation, "Local Core installation unavailable.", "The local Core installation could not be trusted.");
                    break;
                default:
                    SetState(AuthenticationState.Unavailable, "Local Core unavailable.", "Local administrator setup could not be checked. Restore Core, then try again.");
                    break;
            }
        });
    }, () => _state != AuthenticationState.SignedIn);

    public Task SignInAsync(ReadOnlyMemory<char> password)
    {
        string username;
        lock (_gate)
        {
            if (!CanSignIn) return Task.CompletedTask;
            username = _username.Trim();
        }
        return RunOperationAsync(async (generation, cancellationToken) =>
        {
            if (password.Length is < 1 or > 1024)
            {
                Apply(generation, () => SetState(AuthenticationState.SignedOut, "Sign in to local Core.", "The username or password is incorrect."));
                return;
            }
            var result = await _authentication.SignInAsync(username, password, cancellationToken);
            Apply(generation, () =>
            {
                _displayName = string.Empty;
                if (result.Outcome == AuthenticationOutcome.Authenticated && ValidUsername(result.Username))
                {
                    _displayName = result.Username!;
                    SetState(AuthenticationState.SignedIn, $"Signed in as {_displayName}.");
                    return;
                }
                _authentication.SignOut();
                switch (result.Outcome)
                {
                    case AuthenticationOutcome.InvalidCredentials:
                        SetState(AuthenticationState.SignedOut, "Sign in to local Core.", "The username or password is incorrect.");
                        break;
                    case AuthenticationOutcome.Throttled:
                        SetState(AuthenticationState.SignedOut, "Sign in to local Core.", "Too many sign-in attempts. Try again later.");
                        break;
                    case AuthenticationOutcome.UntrustedConnection:
                        SetState(AuthenticationState.UntrustedInstallation, "Local Core connection unavailable.", "The local Core connection could not be trusted.");
                        break;
                    default:
                        SetState(AuthenticationState.Unavailable, "Local Core unavailable.", "Local Core is unavailable. Start or restore Core, then try again.");
                        break;
                }
            });
        }, () => _state is AuthenticationState.SignedOut or AuthenticationState.Unavailable or AuthenticationState.PermissionRequired);
    }

    public Task CreateAdministratorAsync(ReadOnlyMemory<char> password)
    {
        string username;
        lock (_gate)
        {
            if (!CanCreateAdministrator) return Task.CompletedTask;
            username = _username.Trim();
        }
        return RunOperationAsync(async (generation, cancellationToken) =>
        {
            if (password.Length is < 12 or > 1024)
            {
                Apply(generation, () => SetState(AuthenticationState.SetupRequired, "Create your local administrator account.", "Use a password with at least 12 characters."));
                return;
            }
            var result = await _setup.InitializeAsync(username, password, cancellationToken);
            Apply(generation, () =>
            {
                _displayName = string.Empty;
                switch (result)
                {
                    case AdministratorSetupResult.Created:
                        _authentication.SignOut();
                        SetState(AuthenticationState.SignedOut, "Administrator created. Start local Core, then sign in.");
                        break;
                    case AdministratorSetupResult.AlreadyInitialized:
                        _authentication.SignOut();
                        SetState(AuthenticationState.SignedOut, "Administrator already exists. Sign in to local Core.");
                        break;
                    case AdministratorSetupResult.InvalidInput:
                        SetState(AuthenticationState.SetupRequired, "Create your local administrator account.", "Enter a valid username and a password of at least 12 characters.");
                        break;
                    case AdministratorSetupResult.PermissionRequired:
                        SetState(AuthenticationState.PermissionRequired, "Administrator permission is required for initial setup.");
                        break;
                    case AdministratorSetupResult.UntrustedInstallation:
                        SetState(AuthenticationState.UntrustedInstallation, "Local Core installation unavailable.", "The local Core installation could not be trusted.");
                        break;
                    default:
                        SetState(AuthenticationState.Unavailable, "Local Core unavailable.", "Initial administrator setup could not complete. Restore Core, then try again.");
                        break;
                }
            });
        }, () => _state == AuthenticationState.SetupRequired);
    }

    public Task CheckSessionAsync() => RunOperationAsync(async (generation, cancellationToken) =>
    {
        var result = await _authentication.ValidateSessionAsync(cancellationToken);
        Apply(generation, () =>
        {
            if (result.Status == SessionStatus.Authenticated && ValidUsername(result.Username))
            {
                _displayName = result.Username!;
                SetState(AuthenticationState.SignedIn, $"Signed in as {_displayName}.");
                return;
            }
            _authentication.SignOut();
            _displayName = string.Empty;
            switch (result.Status)
            {
                case SessionStatus.Expired:
                    SetState(AuthenticationState.SignedOut, "Your session ended. Sign in again.", "Your session has expired. Sign in again.");
                    break;
                case SessionStatus.SignedOut:
                    SetState(AuthenticationState.SignedOut, "Sign in to local Core.");
                    break;
                case SessionStatus.UntrustedConnection:
                    SetState(AuthenticationState.UntrustedInstallation, "Local Core connection unavailable.", "The local Core connection could not be trusted.");
                    break;
                default:
                    SetState(AuthenticationState.Unavailable, "Local Core unavailable.", "Local Core is unavailable. Restore Core, then sign in again.");
                    break;
            }
        });
    }, () => _state == AuthenticationState.SignedIn);

    private bool CanOperate => !_disposed && !_isBusy && _activeOperation is null;

    private Task RunOperationAsync(Func<long, CancellationToken, Task> action, Func<bool> allowed)
    {
        lock (_gate)
        {
            if (!CanOperate || !allowed()) return Task.CompletedTask;
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _activeOperation = completion.Task;
            _operationCancellation = new CancellationTokenSource();
            var generation = ++_generation;
            _isBusy = true;
            _errorText = string.Empty;
            Notify(nameof(IsBusy), nameof(ErrorText), nameof(CanSignIn), nameof(CanCreateAdministrator));
            _ = CompleteOperationAsync(completion, generation, _operationCancellation, action);
            return completion.Task;
        }
    }

    private async Task CompleteOperationAsync(TaskCompletionSource completion, long generation,
        CancellationTokenSource cancellation, Func<long, CancellationToken, Task> action)
    {
        try { await action(generation, cancellation.Token); }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception)
        {
            Apply(generation, () =>
            {
                _authentication.SignOut();
                _displayName = string.Empty;
                SetState(AuthenticationState.Unavailable, "Local Core unavailable.", "The operation could not complete. Restore Core, then try again.");
            });
        }
        finally
        {
            lock (_gate)
            {
                _activeOperation = null;
                _operationCancellation = null;
                _isBusy = false;
                cancellation.Dispose();
                if (!_disposed) Notify(nameof(IsBusy), nameof(CanSignIn), nameof(CanCreateAdministrator));
                completion.TrySetResult();
            }
        }
    }

    private void Apply(long generation, Action update)
    {
        lock (_gate)
        {
            if (_disposed || generation != _generation) return;
            update();
            Notify(nameof(State), nameof(DisplayName), nameof(StatusText), nameof(ErrorText),
                nameof(IsSignedIn), nameof(CanSignIn), nameof(CanCreateAdministrator), nameof(RequiresElevation));
        }
    }

    private void SetState(AuthenticationState state, string status, string error = "")
    {
        _state = state;
        _statusText = status;
        _errorText = error;
    }

    public void SignOut()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _generation++;
            _operationCancellation?.Cancel();
            _authentication.SignOut();
            _username = string.Empty;
            _displayName = string.Empty;
            _isBusy = false;
            SetState(AuthenticationState.SignedOut, "Sign in to local Core.");
            Notify(nameof(State), nameof(Username), nameof(DisplayName), nameof(StatusText), nameof(ErrorText),
                nameof(IsBusy), nameof(IsSignedIn), nameof(CanSignIn), nameof(CanCreateAdministrator), nameof(RequiresElevation));
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            SignOut();
            _disposed = true;
        }
        try { _authentication.Dispose(); }
        finally { _setup.Dispose(); }
    }

    private void Notify(params string[] properties)
    {
        foreach (var property in properties)
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
    }

    private static bool ValidUsername(string? username) =>
        !string.IsNullOrWhiteSpace(username) && username.Trim().Length <= 256 && !username.Any(char.IsControl);
}
