using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;

internal static partial class Program
{
    private static async Task LocalServiceStatusAsync()
    {
        var actual = await Task.Run(() => new WindowsLocalServiceStatusReader().Read());
        Ensure(Enum.IsDefined(actual.Core) && Enum.IsDefined(actual.Agent), "SCM observation produced an unsupported public state.");

        using (var reader = new NativeServiceStatusReader(new(LocalServiceState.Running, LocalServiceState.Stopped), held: true))
        using (var model = new WindowsServiceStatusModel(reader))
        {
            var notifications = 0;
            model.PropertyChanged += (_, _) => Ensure(Application.Current.Dispatcher.CheckAccess(), "SCM status notified bindings outside the UI thread.");
            model.StatusChanged += (_, _) => notifications++;
            Ensure(model.CoreState == LocalServiceState.Unknown && model.AgentState == LocalServiceState.Unknown,
                "Service status must begin Unknown without an assumed live service.");
            var refresh = model.RefreshAsync();
            await reader.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(model.IsRefreshing && reader.Reads == 1, "The native status read was not performed asynchronously once.");
            Ensure(ReferenceEquals(refresh, model.RefreshAsync()), "Concurrent SCM refresh created a duplicate read.");
            await FlushAsync();
            reader.Release();
            await refresh;
            Ensure(model.CoreStatusText == "Running" && model.AgentStatusText == "Stopped" && !model.IsRefreshing,
                "The service status snapshot did not publish the exact read-only observations.");
            Ensure(notifications == 1, "A service snapshot change must notify once.");
            await model.RefreshAsync();
            Ensure(notifications == 1 && reader.Reads == 2, "An unchanged refresh emitted a repeated service transition.");
            reader.Snapshot = new(LocalServiceState.NotInstalled, LocalServiceState.Unknown);
            await model.RefreshAsync();
            Ensure(model.CoreStatusText == "Not installed" && model.AgentStatusText == "Unknown" && notifications == 2,
                "A missing or inaccessible service was presented as Running or Stopped.");
        }

        using (var reader = new NativeServiceStatusReader(new(LocalServiceState.Running, LocalServiceState.Running), held: true))
        using (var model = new WindowsServiceStatusModel(reader))
        {
            var refresh = model.RefreshAsync();
            await reader.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await refresh.WaitAsync(TimeSpan.FromSeconds(4));
            Ensure(!model.IsRefreshing && model.CoreState == LocalServiceState.Unknown && model.AgentState == LocalServiceState.Unknown,
                "A delayed SCM call retained an unverified live status after its deadline.");
            Ensure(model.StatusText.Contains("unavailable", StringComparison.OrdinalIgnoreCase), "A delayed SCM observation lacks an explicit failure state.");
            await model.RefreshAsync();
            Ensure(reader.Reads == 1, "Deadline expiry accumulated another native SCM worker while the first was still pending.");
            model.Dispose();
            reader.Release();
            await reader.Finished.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await FlushAsync();
            Ensure(model.CoreState == LocalServiceState.Unknown && model.AgentState == LocalServiceState.Unknown,
                "A disposed status model published a late native result.");
            await model.RefreshAsync();
            Ensure(reader.Reads == 1, "A disposed status model accepted another native query.");
        }

        VerifyLocalServiceNotificationPolicy();
        await VerifyNativeDesktopTrayAsync();
    }

    private static void VerifyLocalServiceNotificationPolicy()
    {
        var clock = new NativeServiceNotificationClock();
        var policy = new LocalServiceNotificationPolicy(clock);
        var running = new LocalServiceStatusSnapshot(LocalServiceState.Running, LocalServiceState.Running);
        var coreStopped = new LocalServiceStatusSnapshot(LocalServiceState.Stopped, LocalServiceState.Running);
        var agentStopped = new LocalServiceStatusSnapshot(LocalServiceState.Running, LocalServiceState.Stopped);
        var bothStopped = new LocalServiceStatusSnapshot(LocalServiceState.Stopped, LocalServiceState.Stopped);
        Ensure(!policy.TryCreateNotification(bothStopped, out var empty) && empty == "",
            "Initial or unknown service status generated a stop notification.");
        Ensure(!policy.TryCreateNotification(new(LocalServiceState.Unknown, LocalServiceState.NotInstalled), out _),
            "An uncertain or missing service was reported as a verified stop.");
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(new(LocalServiceState.Stopping, LocalServiceState.Running), out _),
            "A pending stop was reported as an already stopped service.");
        Ensure(policy.TryCreateNotification(coreStopped, out var coreMessage) && coreMessage ==
            "The local Core service stopped. Open SentinelAI to check service status.", "Core service notification text is not fixed and nonsecret.");
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(agentStopped, out _), "Notifications were not throttled globally across both services.");
        clock.Advance(TimeSpan.FromSeconds(29));
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(bothStopped, out _), "The global notification frequency bound ended early.");
        clock.Advance(TimeSpan.FromSeconds(1));
        policy.ResetObservedStates(running);
        Ensure(policy.TryCreateNotification(agentStopped, out var agentMessage) && agentMessage ==
            "The local Agent service stopped. Open SentinelAI to check service status.", "Agent service notification is not fixed or did not resume after the bound.");
        clock.Advance(TimeSpan.FromSeconds(30));
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(new(LocalServiceState.Stopping, LocalServiceState.Stopping), out _),
            "Pending stop transitions emitted a premature combined notification.");
        Ensure(policy.TryCreateNotification(bothStopped, out var bothMessage) && bothMessage ==
            "The local Core and Agent services stopped. Open SentinelAI to check service status.", "Combined service notification is not fixed and nonsecret.");
        Ensure(!policy.TryCreateNotification(bothStopped, out _), "An unchanged stopped snapshot emitted another notification.");
        Ensure(!policy.TryCreateNotification(running, out _), "Normal recovery emitted an unrequested notification.");
        policy.ResetObservedStates();
        clock.Advance(TimeSpan.FromSeconds(30));
        Ensure(!policy.TryCreateNotification(bothStopped, out _), "Clearing notification consent retained a previously armed stop notification.");
        policy.ResetObservedStates(bothStopped);
        Ensure(!policy.TryCreateNotification(bothStopped, out _), "Re-enabling notifications emitted an old stopped-service notice.");
        policy.ResetObservedStates(running);
        Ensure(policy.TryCreateNotification(coreStopped, out _), "Notifications did not resume for a fresh observed service stop.");
        policy.ResetObservedStates();
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(agentStopped, out _), "Toggling consent reset the global monotonic notification frequency bound.");
        clock.Advance(TimeSpan.FromSeconds(30));
        policy.ResetObservedStates(running);
        Ensure(!policy.TryCreateNotification(new(LocalServiceState.Unknown, LocalServiceState.NotInstalled), out _),
            "An unavailable service observation emitted an unverified stop notification.");
        Ensure(!policy.TryCreateNotification(bothStopped, out _), "Uncertain service observations retained obsolete Running evidence.");
    }

    private static async Task VerifyNativeDesktopTrayAsync()
    {
        var dataType = typeof(WindowsDesktopTray).GetNestedType("NotifyIconData", BindingFlags.NonPublic)!;
        Ensure(Marshal.SizeOf(dataType) == 976, "The x64 Unicode Shell_NotifyIcon structure has the wrong native size.");
        Ensure(Marshal.OffsetOf(dataType, "Window").ToInt32() == 8 && Marshal.OffsetOf(dataType, "Info").ToInt32() == 304 &&
            Marshal.OffsetOf(dataType, "BalloonIcon").ToInt32() == 968, "The native notification fields have incorrect x64 alignment.");
        var preferences = new DesktopIntegrationViewModel(new NativeTrayPreferencesStore());
        using var services = new WindowsServiceStatusModel(new NativeServiceStatusReader(new(LocalServiceState.Unknown, LocalServiceState.Unknown)));
        var opened = 0;
        var exited = 0;
        var window = new Window { Title = "SentinelAI tray integration test", Width = 320, Height = 200 };
        using var tray = new WindowsDesktopTray(window, preferences, services, () => opened++, () => exited++);
        try
        {
            window.Show();
            await FlushAsync();
            var handle = new WindowInteropHelper(window).Handle;
            Ensure(!preferences.TrayEnabled && !preferences.NotificationsEnabled && tray.IsAvailable && tray.StatusText.Contains("off", StringComparison.OrdinalIgnoreCase),
                "Tray and notifications must default off without hiding the normal window.");
            SendTrayMessage(handle, 0x0202);
            Ensure(opened == 0 && exited == 0, "A disabled tray processed a native callback.");
            var taskbarMessage = RegisterTrayWindowMessage("TaskbarCreated");
            SendTrayWindowMessage(handle, taskbarMessage, IntPtr.Zero, IntPtr.Zero);
            Ensure(!preferences.TrayEnabled && tray.StatusText.Contains("off", StringComparison.OrdinalIgnoreCase),
                "A Shell restart silently enabled an opted-out tray.");
            preferences.TrayEnabled = true;
            await FlushAsync();
            if (tray.IsAvailable)
            {
                SendTrayMessage(handle, 0x0202);
                Ensure(opened == 1 && exited == 0, "The real native tray callback did not invoke only Open SentinelAI.");
                // Emulate Explorer losing its owned icon before TaskbarCreated;
                // do not stop Explorer or affect other applications' tray icons.
                typeof(WindowsDesktopTray).GetMethod("DeleteIcon", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(tray, null);
                SendTrayWindowMessage(handle, taskbarMessage, IntPtr.Zero, IntPtr.Zero);
                Ensure(tray.IsAvailable, "Tray registration did not recover after the Shell recreated its taskbar.");
                SendTrayMessage(handle, 0x0202);
                Ensure(opened == 2 && exited == 0, "The restored tray lost its native Open SentinelAI callback.");
            }
            else
            {
                Ensure(tray.StatusText.Contains("unavailable", StringComparison.OrdinalIgnoreCase) && window.IsVisible,
                    "A missing system tray prevented the normal Desktop workflow.");
            }
            preferences.TrayEnabled = false;
            var previousOpens = opened;
            SendTrayMessage(handle, 0x0202);
            Ensure(opened == previousOpens && !preferences.NotificationsEnabled && window.IsVisible,
                "Disabling the tray retained callbacks, notifications or a hidden Desktop.");
            window.Close();
            await FlushAsync();
            preferences.TrayEnabled = true;
            Ensure(!window.IsVisible && exited == 0, "Closing the window retained a hidden UI or invoked a service-affecting action.");
        }
        finally { if (window.IsVisible) window.Close(); }
    }

    private static void SendTrayMessage(IntPtr window, uint mouseMessage) =>
        SendTrayWindowMessage(window, 0x8000 + 23, new IntPtr(23), new IntPtr(mouseMessage));

    [DllImport("user32.dll", EntryPoint = "SendMessageW")]
    private static extern IntPtr SendTrayWindowMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", EntryPoint = "RegisterWindowMessageW", CharSet = CharSet.Unicode)]
    private static extern uint RegisterTrayWindowMessage(string message);

    private sealed class NativeServiceStatusReader(LocalServiceStatusSnapshot snapshot, bool held = false) : ILocalServiceStatusReader, IDisposable
    {
        private readonly ManualResetEventSlim _gate = new(!held);
        private int _reads;
        public int Reads => Volatile.Read(ref _reads);
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LocalServiceStatusSnapshot Snapshot { get; set; } = snapshot;
        public LocalServiceStatusSnapshot Read()
        {
            Interlocked.Increment(ref _reads);
            Started.TrySetResult();
            try { _gate.Wait(); return Snapshot; }
            finally { Finished.TrySetResult(); }
        }
        public void Release() => _gate.Set();
        public void Dispose() { _gate.Set(); _gate.Dispose(); }
    }

    private sealed class NativeServiceNotificationClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan period) => _ticks += period.Ticks;
    }

    private sealed class NativeTrayPreferencesStore : IDesktopPreferencesStore
    {
        private DesktopPreferences _preferences = new();
        public DesktopPreferencesResult Read() => new(DesktopPreferenceOutcome.Success, _preferences);
        public DesktopPreferencesResult Save(DesktopPreferences preferences)
        {
            _preferences = preferences;
            return Read();
        }
    }
}
