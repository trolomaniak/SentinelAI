using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

/// <summary>Optional native tray actions. Closing the window still exits and clears its session.</summary>
public sealed class WindowsDesktopTray : INotifyPropertyChanged, IDisposable
{
    private const uint IconId = 23;
    private const int CallbackMessage = 0x8000 + 23;
    private readonly Window _window;
    private readonly DesktopIntegrationViewModel _preferences;
    private readonly WindowsServiceStatusModel _services;
    private readonly Action _open;
    private readonly Action _exit;
    private readonly HwndSourceHook _hook;
    private readonly uint _taskbarCreated;
    private HwndSource? _source;
    private bool _registered;
    private bool _disposed;
    private bool _isAvailable = true;
    private string _statusText = "Tray integration is off.";
    private readonly LocalServiceNotificationPolicy _notifications = new();
    private bool _notificationPermission;

    public WindowsDesktopTray(Window window, DesktopIntegrationViewModel preferences,
        WindowsServiceStatusModel services, Action open, Action exit)
    {
        _window = window;
        _preferences = preferences;
        _services = services;
        _open = open;
        _exit = exit;
        _hook = WindowMessage;
        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");
        _preferences.PropertyChanged += OnPreferencesChanged;
        _services.StatusChanged += OnServiceStatusChanged;
        _window.SourceInitialized += OnSourceInitialized;
        _window.Closed += OnWindowClosed;
        AttachSource();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public bool IsAvailable => _isAvailable;
    public string StatusText => _statusText;

    private void OnSourceInitialized(object? sender, EventArgs args) => AttachSource();

    private void AttachSource()
    {
        _window.Dispatcher.VerifyAccess();
        if (_disposed || _source is not null) return;
        var handle = new WindowInteropHelper(_window).Handle;
        if (handle == IntPtr.Zero) return;
        _source = HwndSource.FromHwnd(handle);
        _source?.AddHook(_hook);
        UpdateRegistration();
    }

    private void OnPreferencesChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName is nameof(DesktopIntegrationViewModel.TrayEnabled) or null or "")
            UpdateRegistration();
        if (args.PropertyName is nameof(DesktopIntegrationViewModel.TrayEnabled) or nameof(DesktopIntegrationViewModel.NotificationsEnabled) or null or "")
            UpdateNotificationPermission();
    }

    private void UpdateNotificationPermission()
    {
        var enabled = !_disposed && _registered && _preferences.TrayEnabled && _preferences.NotificationsEnabled;
        if (enabled == _notificationPermission) return;
        _notificationPermission = enabled;
        _notifications.ResetObservedStates(enabled ? new(_services.CoreState, _services.AgentState) : null);
    }

    private void UpdateRegistration()
    {
        _window.Dispatcher.VerifyAccess();
        if (_disposed) return;
        if (!_preferences.TrayEnabled)
        {
            DeleteIcon();
            SetStatus(true, "Tray integration is off. Closing Desktop ends its session.");
            return;
        }
        if (_source is null)
        {
            SetStatus(true, "Tray integration will start with the Desktop window.");
            return;
        }
        if (_registered) return;
        var data = CreateData(0x0001 | 0x0002 | 0x0004); // MESSAGE, ICON, TIP
        data.Icon = LoadIcon(IntPtr.Zero, new IntPtr(32512)); // shared application icon
        data.Tip = "SentinelAI — Open SentinelAI";
        _registered = data.Icon != IntPtr.Zero && ShellNotifyIcon(0, ref data);
        UpdateNotificationPermission();
        SetStatus(_registered, _registered
            ? "Tray is enabled. Open SentinelAI restores the window; Exit Desktop closes its session."
            : "Tray integration is unavailable. Use the normal Desktop window.");
    }

    private void OnServiceStatusChanged(object? sender, LocalServiceStatusChangedEventArgs args)
    {
        if (_disposed || !_registered || !_preferences.TrayEnabled || !_preferences.NotificationsEnabled) return;
        if (!_notifications.TryCreateNotification(args.Current, out var message)) return;
        var data = CreateData(0x0010); // INFO; all text is fixed, without endpoint or alert data
        data.InfoTitle = "SentinelAI local service";
        data.Info = message;
        data.InfoFlags = 2 | 0x80; // WARNING, RESPECT_QUIET_TIME
        data.TimeoutOrVersion = 10000;
        if (!ShellNotifyIcon(1, ref data))
            SetStatus(false, "Tray notifications are unavailable. Service status remains visible in Settings.");
    }

    private IntPtr WindowMessage(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (_disposed) return IntPtr.Zero;
        if (_taskbarCreated != 0 && (uint)message == _taskbarCreated)
        {
            _registered = false;
            UpdateNotificationPermission();
            UpdateRegistration();
            return IntPtr.Zero;
        }
        if (!_registered || !_preferences.TrayEnabled || message != CallbackMessage ||
            unchecked((uint)wParam.ToInt64()) != IconId) return IntPtr.Zero;
        handled = true;
        var notification = unchecked((uint)lParam.ToInt64());
        try
        {
            if (notification is 0x0202 or 0x0203 or 0x0400 or 0x0401 or 0x0405)
                _open();
            else if (notification is 0x0205 or 0x007B)
                ShowMenu(hwnd);
        }
        catch { SetStatus(false, "The tray action is unavailable. Use the normal Desktop window."); }
        return IntPtr.Zero;
    }

    private void ShowMenu(IntPtr hwnd)
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;
        try
        {
            if (!AppendMenu(menu, 0, new UIntPtr(1), "Open SentinelAI") ||
                !AppendMenu(menu, 0, new UIntPtr(2), "Exit Desktop") || !GetCursorPos(out var point)) return;
            SetForegroundWindow(hwnd);
            var choice = TrackPopupMenu(menu, 0x0100 | 0x0080 | 0x0002, point.X, point.Y, 0, hwnd, IntPtr.Zero);
            PostMessage(hwnd, 0, IntPtr.Zero, IntPtr.Zero);
            if (choice == 1) _open();
            else if (choice == 2) _exit();
        }
        finally { DestroyMenu(menu); }
    }

    private NotifyIconData CreateData(uint flags) => new()
    {
        Size = (uint)Marshal.SizeOf<NotifyIconData>(),
        Window = _source?.Handle ?? IntPtr.Zero,
        Id = IconId,
        Flags = flags,
        Callback = CallbackMessage,
        Tip = "",
        Info = "",
        InfoTitle = ""
    };

    private void DeleteIcon()
    {
        if (!_registered) return;
        var data = CreateData(0);
        ShellNotifyIcon(2, ref data);
        _registered = false;
        UpdateNotificationPermission();
    }

    private void SetStatus(bool available, string status)
    {
        _isAvailable = available;
        _statusText = status;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsAvailable)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusText)));
    }

    private void OnWindowClosed(object? sender, EventArgs args) => Dispose();

    public void Dispose()
    {
        _window.Dispatcher.VerifyAccess();
        if (_disposed) return;
        _disposed = true;
        _preferences.PropertyChanged -= OnPreferencesChanged;
        _services.StatusChanged -= OnServiceStatusChanged;
        _window.SourceInitialized -= OnSourceInitialized;
        _window.Closed -= OnWindowClosed;
        DeleteIcon();
        _source?.RemoveHook(_hook);
        _source = null;
        PropertyChanged = null;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size;
        public IntPtr Window;
        public uint Id, Flags, Callback;
        public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint TimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public uint InfoFlags;
        public Guid Guid;
        public IntPtr BalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [DllImport("shell32.dll", EntryPoint = "Shell_NotifyIconW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ShellNotifyIcon(uint action, ref NotifyIconData data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadIcon(IntPtr instance, IntPtr name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessage(string message);
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AppendMenu(IntPtr menu, uint flags, UIntPtr id, string text);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] private static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr window, IntPtr rect);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}

/// <summary>Fixed, nonsecret stopped-service notices, with a monotonic global frequency bound.</summary>
public sealed class LocalServiceNotificationPolicy(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private long? _lastNotification;
    private bool _coreWasRunning;
    private bool _agentWasRunning;

    public void ResetObservedStates(LocalServiceStatusSnapshot? baseline = null)
    {
        _coreWasRunning = baseline?.Core == LocalServiceState.Running;
        _agentWasRunning = baseline?.Agent == LocalServiceState.Running;
    }

    public bool TryCreateNotification(LocalServiceStatusSnapshot current, out string message)
    {
        message = "";
        var coreStopped = Observe(current.Core, ref _coreWasRunning);
        var agentStopped = Observe(current.Agent, ref _agentWasRunning);
        if (!coreStopped && !agentStopped) return false;
        var now = _time.GetTimestamp();
        if (_lastNotification is { } last && _time.GetElapsedTime(last, now) < TimeSpan.FromSeconds(30)) return false;
        _lastNotification = now;
        message = coreStopped && agentStopped ? "The local Core and Agent services stopped. Open SentinelAI to check service status."
            : coreStopped ? "The local Core service stopped. Open SentinelAI to check service status."
            : "The local Agent service stopped. Open SentinelAI to check service status.";
        return true;
    }

    private static bool Observe(LocalServiceState current, ref bool wasRunning)
    {
        if (current == LocalServiceState.Running) { wasRunning = true; return false; }
        if (current == LocalServiceState.Stopped)
        {
            var stopped = wasRunning;
            wasRunning = false;
            return stopped;
        }
        if (current is LocalServiceState.Unknown or LocalServiceState.NotInstalled) wasRunning = false;
        return false;
    }
}
