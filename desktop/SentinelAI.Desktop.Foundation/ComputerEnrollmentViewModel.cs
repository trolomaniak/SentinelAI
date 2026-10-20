using System.ComponentModel;
using System.Globalization;

namespace SentinelAI.Desktop.Foundation;

public sealed record EnrollmentAddressChoice(string Value, string DisplayText);
public sealed record ValidityChoice(int Hours, string DisplayText);
public sealed record IssuedCodeRow(Guid Id, string Code, string ExpiresText)
{
    public override string ToString() => nameof(IssuedCodeRow);
}
public sealed record UnusedCodeRow(Guid Id, string ExpiresText);

// Devices -> "Add computers" (enrollment codes) and "Remove computer". Issued codes stay in memory only until the
// next batch, sign-out or session expiry; Desktop never logs or persists them except where the administrator saves them.
public sealed class ComputerEnrollmentViewModel : INotifyPropertyChanged, IDisposable
{
    public const string SecretNotice = "Each code enrolls one computer and is a secret. Give it only to the person installing SentinelAI Agent on that computer.";
    public const string AddressAdvice = "Agents keep using the address in their code. Prefer the computer name, or give this computer a fixed IP address.";
    public static readonly IReadOnlyList<int> CountChoices = Enumerable.Range(1, 50).ToArray();
    public static readonly IReadOnlyList<ValidityChoice> ValidityChoices =
    [
        new(1, "1 hour"), new(8, "8 hours"), new(24, "24 hours"), new(72, "3 days"), new(168, "7 days")
    ];

    private readonly IComputerEnrollmentClient _client;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private CancellationTokenSource _lifetime = new();
    private long _generation;
    private bool _disposed;
    private bool _busy;
    private bool _available;
    private string _statusText = "";
    private string _errorText = "";
    private IReadOnlyList<EnrollmentAddressChoice> _addresses = [];
    private EnrollmentAddressChoice? _selectedAddress;
    private int _count = 1;
    private ValidityChoice _validity = ValidityChoices[2];
    private IReadOnlyList<IssuedCodeRow> _issued = [];
    private IReadOnlyList<UnusedCodeRow> _unused = [];

    public ComputerEnrollmentViewModel(IComputerEnrollmentClient client, TimeProvider? time = null)
    {
        _client = client;
        _time = time ?? TimeProvider.System;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public bool IsBusy { get { lock (_gate) return _busy; } }
    public bool IsAvailable { get { lock (_gate) return _available; } }
    public bool CanIssue { get { lock (_gate) return _available && !_busy && _selectedAddress is not null; } }
    public string StatusText { get { lock (_gate) return _statusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public IReadOnlyList<EnrollmentAddressChoice> Addresses { get { lock (_gate) return _addresses; } }
    public IReadOnlyList<IssuedCodeRow> IssuedCodes { get { lock (_gate) return _issued; } }
    public IReadOnlyList<UnusedCodeRow> UnusedCodes { get { lock (_gate) return _unused; } }
    public string IssuedCodesText { get { lock (_gate) return string.Join(Environment.NewLine, _issued.Select(row => row.Code)); } }

    public EnrollmentAddressChoice? SelectedAddress
    {
        get { lock (_gate) return _selectedAddress; }
        set { lock (_gate) _selectedAddress = value is not null && _addresses.Contains(value) ? value : _selectedAddress; Notify(); }
    }

    public int Count
    {
        get { lock (_gate) return _count; }
        set { lock (_gate) _count = Math.Clamp(value, 1, 50); Notify(); }
    }

    public ValidityChoice Validity
    {
        get { lock (_gate) return _validity; }
        set { lock (_gate) _validity = ValidityChoices.Contains(value) ? value : _validity; Notify(); }
    }

    public async Task LoadAsync()
    {
        if (!TryBegin(out var generation, out var token)) return;
        try
        {
            var options = await _client.GetEnrollmentOptionsAsync(token).ConfigureAwait(false);
            if (!Settle(generation, options.Outcome)) return;
            var unused = options.Outcome == ComputerEnrollmentOutcome.Success
                ? await _client.GetUnusedCodesAsync(token).ConfigureAwait(false) : null;
            if (unused is not null && !Settle(generation, unused.Outcome)) return;
            lock (_gate)
            {
                if (generation != _generation) return;
                var value = options.Value;
                _available = value is { Available: true } && value.Addresses.Count > 0;
                _addresses = value is null ? [] : value.Addresses.Select(Describe).ToArray();
                _selectedAddress = _addresses.FirstOrDefault(address => address.Value == value?.RecommendedAddress) ?? _addresses.FirstOrDefault();
                _unused = unused?.Value is { } list ? list.Select(code => new UnusedCodeRow(code.Id, ExpiryText(code.ExpiresUtc))).ToArray() : [];
                _statusText = options.Outcome != ComputerEnrollmentOutcome.Success ? "Computer enrollment is unavailable. Try again."
                    : value is not { Available: true } ? "Agents on other computers cannot connect: this installation is local to this computer only."
                    : !value.Listening ? "Core is not listening on the local network right now. Codes work once it listens again."
                    : _unused.Count == 0 ? "No unused codes." : $"{_unused.Count.ToString(CultureInfo.CurrentCulture)} unused codes.";
                _errorText = "";
            }
        }
        finally { End(generation); }
    }

    public async Task IssueAsync()
    {
        string address;
        int count, hours;
        lock (_gate)
        {
            if (_selectedAddress is null || !_available) return;
            (address, count, hours) = (_selectedAddress.Value, _count, _validity.Hours);
        }
        if (!TryBegin(out var generation, out var token)) return;
        try
        {
            var issued = await _client.IssueCodesAsync(count, hours, address, token).ConfigureAwait(false);
            if (!Settle(generation, issued.Outcome)) return;
            lock (_gate)
            {
                if (generation != _generation) return;
                if (issued.Value is { } codes)
                {
                    _issued = codes.Select(code => new IssuedCodeRow(code.Id, code.Code, ExpiryText(code.ExpiresUtc))).ToArray();
                    _errorText = "";
                }
                else _errorText = issued.Outcome == ComputerEnrollmentOutcome.Conflict
                    ? "This installation is local to this computer only, so no codes can be created."
                    : "The codes could not be created. Try again.";
            }
        }
        finally { End(generation); }
        if (IsCurrent(generation)) await LoadUnusedAsync().ConfigureAwait(false);
    }

    public async Task RevokeAsync(Guid id)
    {
        if (!TryBegin(out var generation, out var token)) return;
        try
        {
            var outcome = await _client.RevokeCodeAsync(id, token).ConfigureAwait(false);
            if (!Settle(generation, outcome)) return;
            lock (_gate)
            {
                if (generation != _generation) return;
                _issued = _issued.Where(row => row.Id != id).ToArray();
                _errorText = outcome is ComputerEnrollmentOutcome.Success or ComputerEnrollmentOutcome.NotFound ? "" : "The code could not be revoked. Try again.";
            }
        }
        finally { End(generation); }
        if (IsCurrent(generation)) await LoadUnusedAsync().ConfigureAwait(false);
    }

    // Returns true when Core removed the computer (or it was already gone); the caller then refreshes the device list.
    public async Task<bool> RemoveComputerAsync(Guid endpointId)
    {
        if (!TryBegin(out var generation, out var token)) return false;
        try
        {
            var outcome = await _client.RemoveComputerAsync(endpointId, token).ConfigureAwait(false);
            if (!Settle(generation, outcome)) return false;
            lock (_gate)
            {
                if (generation != _generation) return false;
                var removed = outcome is ComputerEnrollmentOutcome.Success or ComputerEnrollmentOutcome.NotFound;
                _errorText = removed ? "" : "The computer could not be removed. Try again.";
                return removed;
            }
        }
        finally { End(generation); }
    }

    // Sign-out and session expiry: forget the codes and cancel every request in flight.
    public void Clear()
    {
        CancellationTokenSource previous;
        lock (_gate)
        {
            if (_disposed) return;
            _generation++;
            previous = _lifetime;
            _lifetime = new CancellationTokenSource();
            (_busy, _available, _statusText, _errorText) = (false, false, "", "");
            (_addresses, _selectedAddress, _issued, _unused) = ([], null, [], []);
        }
        previous.Cancel();
        previous.Dispose();
        Notify();
    }

    public void Dispose()
    {
        CancellationTokenSource lifetime;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _generation++;
            lifetime = _lifetime;
            _issued = [];
        }
        lifetime.Cancel();
        lifetime.Dispose();
    }

    private async Task LoadUnusedAsync()
    {
        if (!TryBegin(out var generation, out var token)) return;
        try
        {
            var unused = await _client.GetUnusedCodesAsync(token).ConfigureAwait(false);
            if (!Settle(generation, unused.Outcome)) return;
            lock (_gate)
            {
                if (generation != _generation || unused.Value is not { } list) return;
                _unused = list.Select(code => new UnusedCodeRow(code.Id, ExpiryText(code.ExpiresUtc))).ToArray();
                _statusText = _unused.Count == 0 ? "No unused codes." : $"{_unused.Count.ToString(CultureInfo.CurrentCulture)} unused codes.";
            }
        }
        finally { End(generation); }
    }

    private bool TryBegin(out long generation, out CancellationToken token)
    {
        lock (_gate)
        {
            generation = _generation;
            token = _disposed ? default : _lifetime.Token;
            if (_disposed || _busy) return false;
            _busy = true;
        }
        Notify();
        return true;
    }

    private void End(long generation)
    {
        lock (_gate)
        {
            if (generation != _generation) return;
            _busy = false;
        }
        Notify();
    }

    private bool IsCurrent(long generation) { lock (_gate) return generation == _generation && !_disposed; }

    // An expired session clears everything and asks the shell to sign in again.
    private bool Settle(long generation, ComputerEnrollmentOutcome outcome)
    {
        if (outcome is not (ComputerEnrollmentOutcome.Unauthenticated or ComputerEnrollmentOutcome.UntrustedConnection)) return IsCurrent(generation);
        if (!IsCurrent(generation)) return false;
        Clear();
        SessionExpired?.Invoke(this, EventArgs.Empty);
        return false;
    }

    private string ExpiryText(DateTimeOffset expiresUtc) =>
        "Expires " + expiresUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) +
        (expiresUtc - _time.GetUtcNow() < TimeSpan.FromHours(1) ? " (soon)" : "");

    private static EnrollmentAddressChoice Describe(EnrollmentAddressOption option) => new(option.Value,
        option.IsName ? option.Value + (option.Resolves ? " (computer name, recommended)" : " (computer name, does not resolve yet)")
                      : option.Value + " (IP address; keep it fixed)");

    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
}
