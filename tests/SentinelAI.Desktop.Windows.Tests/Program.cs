using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;

internal static class Program
{
    private static int _assertions;

    [STAThread]
    private static int Main()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("These tests require an interactive native Windows desktop.");
            return 1;
        }

        var app = new TestApp();
        app.InitializeComponent();
        app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        var dispatcher = Dispatcher.CurrentDispatcher;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
        try
        {
            // TestApp suppresses the startup callback scheduled by Application's
            // constructor, while retaining the production XAML resources.
            var tests = RunAsync(app);
            var frame = new DispatcherFrame();
            _ = tests.ContinueWith(_ => dispatcher.BeginInvoke(() => frame.Continue = false),
                CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);
            Dispatcher.PushFrame(frame);
            tests.GetAwaiter().GetResult();
            Console.WriteLine($"Native Windows desktop tests passed ({_assertions} assertions).");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            app.Shutdown();
        }
    }

    private static async Task RunAsync(App app)
    {
        using var bindings = new BindingTrace();
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(bindings);
        using var client = new FakeCoreClient();
        using var model = new ShellViewModel(client, "1.2.3-test");
        var window = new MainWindow(model);
        try
        {
            Ensure(window.WindowStyle != WindowStyle.None, "The shell must retain native window chrome.");
            Ensure(window.MinWidth > 0 && window.MinHeight > 0, "The responsive shell requires explicit minimum dimensions.");
            window.Show();
            await FlushAsync();
            Ensure(app.Windows.Count == 1 && ReferenceEquals(app.Windows[0], window),
                "The test unexpectedly created another application window.");
            var handle = new WindowInteropHelper(window).Handle;
            Ensure(handle != IntPtr.Zero && NativeMethods.IsWindowVisible(handle), "The WPF shell did not create a visible native HWND.");
            Ensure(NativeMethods.AreDpiAwarenessContextsEqual(NativeMethods.GetWindowDpiAwarenessContext(handle), new IntPtr(-4)),
                "The native window must use PerMonitorV2 DPI awareness.");
            var physicalDpi = NativeMethods.GetDpiForWindow(handle);
            Ensure(physicalDpi > 0, "The actual window DPI was unavailable.");
            var wpfDpi = VisualTreeHelper.GetDpi(window);
            Ensure(Math.Abs(wpfDpi.PixelsPerInchX - physicalDpi) < 1 && Math.Abs(wpfDpi.PixelsPerInchY - physicalDpi) < 1,
                "WPF layout and native window DPI disagree.");
            Console.WriteLine($"Verified real HWND at {physicalDpi} DPI ({wpfDpi.DpiScaleX:P0} scale). Resize checks use layout units; they do not emulate physical monitor DPI.");

            Ensure(window.Title == model.Title, "The native title is not bound to the shell title.");
            Ensure(Descendants<TextBlock>(window).Any(text => text.Text.Contains(model.Version, StringComparison.Ordinal)),
                "The application version is not displayed.");
            foreach (var key in new[] { "WindowBackgroundBrush", "SurfaceBrush", "PrimaryTextBrush", "SecondaryTextBrush", "AccentBrush", "BorderBrush", "NavigationBackgroundBrush", "NavigationForegroundBrush", "NavigationSelectedBrush" })
            {
                Ensure(app.TryFindResource(key) is Brush, $"The semantic theme resource {key} is missing.");
            }

            var navigation = RequireControl<ListBox>(window, "NavigationList");
            var content = RequireControl<ContentControl>(window, "PageContent");
            var refresh = RequireControl<Button>(window, "RefreshCoreButton");
            Ensure(navigation.Items.Count == model.Pages.Count && navigation.Items.Count > 1, "The native navigation is not bound to all placeholder pages.");
            Ensure(Keyboard.Focus(navigation) is not null && navigation.IsKeyboardFocusWithin, "Keyboard users cannot focus navigation.");

            foreach (var size in new[] { new Size(window.MinWidth, window.MinHeight), new Size(window.Width, window.Height), new Size(1480, 960) })
            {
                window.Width = size.Width;
                window.Height = size.Height;
                await FlushAsync();
                Ensure(window.ActualWidth >= window.MinWidth && window.ActualHeight >= window.MinHeight, "Window resizing ignored the minimum layout size.");
                AssertInsideWindow(window, navigation);
                AssertInsideWindow(window, content);
                for (var index = 0; index < model.Pages.Count; index++)
                {
                    navigation.SelectedIndex = index;
                    navigation.ScrollIntoView(model.Pages[index]);
                    await FlushAsync();
                    var item = navigation.ItemContainerGenerator.ContainerFromIndex(index) as ListBoxItem;
                    Ensure(item is not null, "A navigation item did not create a native container.");
                    var itemPeer = UIElementAutomationPeer.CreatePeerForElement(item!);
                    Ensure(itemPeer is not null && itemPeer.GetName() == model.Pages[index].Title,
                        "Assistive technology did not receive the page title as the native navigation label.");
                    Ensure(ReferenceEquals(navigation.SelectedItem, model.CurrentPage), "Navigation did not update the current view model page.");
                    Ensure(ReferenceEquals(content.Content, model.CurrentPage), "The content presenter did not follow current navigation.");
                    Ensure(Descendants<TextBlock>(content).Any(text => text.Text == model.CurrentPage.Title), "A selected placeholder heading was not rendered.");
                    Ensure(Descendants<ScrollViewer>(content).Any(scroll => scroll.ViewportWidth > 0 && scroll.ViewportHeight > 0),
                        "The page has no usable scroll viewport at the tested size.");
                }
            }

            await WaitForAsync(() => !model.IsCheckingCore && client.Calls > 0, "Startup Core check did not complete.");
            Ensure(Descendants<TextBlock>(window).Any(text => text.Text == model.CoreStatusText), "The Core status is not displayed through a binding.");
            client.Health = CoreHealth.Unavailable;
            var previousCalls = client.Calls;
            var refreshPeer = UIElementAutomationPeer.CreatePeerForElement(refresh) ?? new ButtonAutomationPeer(refresh);
            Ensure(refreshPeer.GetPattern(PatternInterface.Invoke) is IInvokeProvider, "The refresh control has no accessible native invoke pattern.");
            ((IInvokeProvider)refreshPeer.GetPattern(PatternInterface.Invoke)).Invoke();
            await WaitForAsync(() => client.Calls > previousCalls && !model.IsCheckingCore, "The native refresh button did not complete a Core check.");
            await FlushAsync();
            Ensure(model.CoreStatusText.Contains("unavailable", StringComparison.OrdinalIgnoreCase), "An unavailable Core did not produce the offline status.");
            Ensure(Descendants<TextBlock>(window).Any(text => text.Text == model.CoreStatusText), "An offline status update did not reach the native view.");

            window.Close();
            await FlushAsync();
            Ensure(!NativeMethods.IsWindow(handle), "Graceful close left the native window alive.");
            Ensure(client.Disposed, "Graceful close did not release the Core client.");
            Ensure(bindings.Messages.Count == 0, $"Native shell binding warnings/errors: {string.Join(Environment.NewLine, bindings.Messages)}");
        }
        finally
        {
            if (window.IsVisible)
            {
                window.Close();
            }
            bindingSource.Listeners.Remove(bindings);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static T RequireControl<T>(Window window, string name) where T : FrameworkElement
    {
        var control = window.FindName(name) as T;
        Ensure(control is not null, $"The native shell control {name} is missing.");
        return control!;
    }

    private static void AssertInsideWindow(Window window, FrameworkElement element)
    {
        Ensure(element.ActualWidth > 0 && element.ActualHeight > 0, "A shell region has no usable layout area.");
        var bounds = element.TransformToAncestor(window).TransformBounds(new Rect(element.RenderSize));
        Ensure(bounds.Left >= -1 && bounds.Top >= -1 && bounds.Right <= window.ActualWidth + 1 && bounds.Bottom <= window.ActualHeight + 1,
            "A shell region extends beyond the window at the tested size.");
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match)
            {
                yield return match;
            }
            foreach (var descendant in Descendants<T>(child))
            {
                yield return descendant;
            }
        }
    }

    private static async Task FlushAsync()
    {
        await Dispatcher.CurrentDispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private static async Task WaitForAsync(Func<bool> predicate, string failure)
    {
        var deadline = Stopwatch.StartNew();
        while (!predicate() && deadline.Elapsed < TimeSpan.FromSeconds(5))
        {
            await Task.Delay(20);
        }
        Ensure(predicate(), failure);
    }

    private static void Ensure(bool condition, string message)
    {
        _assertions++;
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeCoreClient : ICoreClient
    {
        public CoreHealth Health { get; set; } = CoreHealth.Available;
        public int Calls { get; private set; }
        public bool Disposed { get; private set; }
        public Task<CoreHealth> CheckHealthAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(Health);
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class TestApp : App
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Never invoke App.OnStartup: this separate test executable injects
            // its own fake client and creates exactly one tested window.
        }
    }

    private sealed class BindingTrace : TraceListener
    {
        public List<string> Messages { get; } = [];
        public override void Write(string? message)
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                Messages.Add(message);
            }
        }
        public override void WriteLine(string? message) => Write(message);
    }

    private static class NativeMethods
    {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWindowVisible(IntPtr handle);
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWindow(IntPtr handle);
        [DllImport("user32.dll")]
        internal static extern IntPtr GetWindowDpiAwarenessContext(IntPtr handle);
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AreDpiAwarenessContextsEqual(IntPtr first, IntPtr second);
        [DllImport("user32.dll")]
        internal static extern uint GetDpiForWindow(IntPtr handle);
    }
}
