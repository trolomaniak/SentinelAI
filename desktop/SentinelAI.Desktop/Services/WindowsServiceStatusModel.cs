using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Threading;

namespace SentinelAI.Desktop.Services;

public enum LocalServiceState { Unknown, NotInstalled, Starting, Running, Stopping, Stopped }

public sealed record LocalServiceStatusSnapshot(LocalServiceState Core, LocalServiceState Agent);

public interface ILocalServiceStatusReader
{
    LocalServiceStatusSnapshot Read();
}

public sealed class LocalServiceStatusChangedEventArgs(
    LocalServiceStatusSnapshot previous, LocalServiceStatusSnapshot current) : EventArgs
{
    public LocalServiceStatusSnapshot Previous { get; } = previous;
    public LocalServiceStatusSnapshot Current { get; } = current;
}

/// <summary>Public SCM observations only; does not start, stop, configure or authenticate either service.</summary>
public sealed class WindowsServiceStatusModel : INotifyPropertyChanged, IDisposable
{
    private readonly ILocalServiceStatusReader _reader;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _timer;
    private readonly CancellationTokenSource _lifetime = new();
    private Task<LocalServiceStatusSnapshot>? _nativeRead;
    private Task? _refresh;
    private bool _disposed;
    private bool _isRefreshing;
    private LocalServiceStatusSnapshot _snapshot = Unknown;
    private string _statusText = "Service status has not been checked.";
    private static readonly LocalServiceStatusSnapshot Unknown = new(LocalServiceState.Unknown, LocalServiceState.Unknown);

    public WindowsServiceStatusModel(ILocalServiceStatusReader? reader = null)
    {
        _reader = reader ?? new WindowsLocalServiceStatusReader();
        _dispatcher = Dispatcher.CurrentDispatcher;
        _timer = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
        {
            Interval = TimeSpan.FromSeconds(10)
        };
        _timer.Tick += OnTimer;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler<LocalServiceStatusChangedEventArgs>? StatusChanged;
    public LocalServiceState CoreState => _snapshot.Core;
    public LocalServiceState AgentState => _snapshot.Agent;
    public string CoreStatusText => Display(CoreState);
    public string AgentStatusText => Display(AgentState);
    public string StatusText => _statusText;
    public bool IsRefreshing => _isRefreshing;

    public void Start()
    {
        _dispatcher.VerifyAccess();
        if (_disposed || _timer.IsEnabled) return;
        _timer.Start();
        _ = RefreshAsync();
    }

    public Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        _dispatcher.VerifyAccess();
        if (_disposed || cancellationToken.IsCancellationRequested) return Task.CompletedTask;
        if (_refresh is { IsCompleted: false }) return _refresh;
        // A local SCM call cannot be interrupted safely. If it outlives our
        // observation deadline, retain it rather than accumulating worker calls.
        if (_nativeRead is { IsCompleted: false }) return Task.CompletedTask;
        _nativeRead = Task.Run(ReadSafely);
        _refresh = ObserveAsync(_nativeRead, cancellationToken);
        return _refresh;
    }

    private LocalServiceStatusSnapshot ReadSafely()
    {
        try { return _reader.Read(); }
        catch { return Unknown; }
    }

    private async Task ObserveAsync(Task<LocalServiceStatusSnapshot> nativeRead, CancellationToken cancellationToken)
    {
        SetRefreshing(true);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        try
        {
            var snapshot = await nativeRead.WaitAsync(TimeSpan.FromSeconds(2), linked.Token);
            if (_disposed || linked.IsCancellationRequested) return;
            Publish(snapshot, snapshot.Core == LocalServiceState.Unknown || snapshot.Agent == LocalServiceState.Unknown
                ? "Some service status is unavailable. Core connection health is checked separately."
                : "Read-only local Windows service status. Core connection health is checked separately.");
        }
        catch (TimeoutException)
        {
            if (!_disposed) Publish(Unknown, "Local service status is unavailable. Try Refresh later.");
        }
        catch (OperationCanceledException) { }
        finally { if (!_disposed) SetRefreshing(false); }
    }

    private void Publish(LocalServiceStatusSnapshot snapshot, string statusText)
    {
        var previous = _snapshot;
        _snapshot = snapshot;
        _statusText = statusText;
        foreach (var property in new[] { nameof(CoreState), nameof(AgentState), nameof(CoreStatusText), nameof(AgentStatusText), nameof(StatusText) })
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
        if (previous != snapshot) StatusChanged?.Invoke(this, new LocalServiceStatusChangedEventArgs(previous, snapshot));
    }

    private void SetRefreshing(bool value)
    {
        if (_isRefreshing == value) return;
        _isRefreshing = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsRefreshing)));
    }

    private void OnTimer(object? sender, EventArgs args) => _ = RefreshAsync();
    private static string Display(LocalServiceState state) => state switch
    {
        LocalServiceState.NotInstalled => "Not installed",
        LocalServiceState.Starting => "Starting",
        LocalServiceState.Running => "Running",
        LocalServiceState.Stopping => "Stopping",
        LocalServiceState.Stopped => "Stopped",
        _ => "Unknown"
    };

    public void Dispose()
    {
        _dispatcher.VerifyAccess();
        if (_disposed) return;
        _disposed = true;
        _timer.Stop();
        _timer.Tick -= OnTimer;
        _lifetime.Cancel();
        _lifetime.Dispose();
        _isRefreshing = false;
        PropertyChanged = null;
        StatusChanged = null;
    }
}

/// <summary>Queries exactly the two installed local services with QUERY_STATUS access only.</summary>
public sealed class WindowsLocalServiceStatusReader : ILocalServiceStatusReader
{
    public LocalServiceStatusSnapshot Read()
    {
        if (!OperatingSystem.IsWindows()) return new(LocalServiceState.Unknown, LocalServiceState.Unknown);
        var manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (manager == IntPtr.Zero) return new(LocalServiceState.Unknown, LocalServiceState.Unknown);
        try { return new(ReadService(manager, "SentinelAICore"), ReadService(manager, "SentinelAIAgent")); }
        finally { CloseServiceHandle(manager); }
    }

    private static LocalServiceState ReadService(IntPtr manager, string name)
    {
        var service = OpenService(manager, name, 0x0004); // SERVICE_QUERY_STATUS
        if (service == IntPtr.Zero)
            return Marshal.GetLastWin32Error() == 1060 ? LocalServiceState.NotInstalled : LocalServiceState.Unknown;
        try
        {
            if (!QueryServiceStatusEx(service, 0, out var status, (uint)Marshal.SizeOf<ServiceStatus>(), out _))
                return LocalServiceState.Unknown;
            return status.State switch
            {
                1 => LocalServiceState.Stopped,
                2 => LocalServiceState.Starting,
                3 => LocalServiceState.Stopping,
                4 => LocalServiceState.Running,
                _ => LocalServiceState.Unknown
            };
        }
        finally { CloseServiceHandle(service); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint Type, State, Controls, ExitCode, SpecificExitCode, Checkpoint, WaitHint, ProcessId, Flags;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, uint size, out uint required);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
