using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using SentinelAI.Contracts.SoftwareCatalog;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task SoftwareCatalogViewsAsync()
    {
        var previous = Localizer.Current;
        try
        {
            foreach (var language in new[] { UiLanguage.English, UiLanguage.Polish })
            {
                Localizer.Use(language);
                await SoftwareCatalogViewAsync(language);
            }
        }
        finally { Localizer.Use(previous); }
    }

    private static async Task SoftwareCatalogViewAsync(UiLanguage language)
    {
        using var shell = new ShellViewModel(new FakeCoreClient(), "software-catalog-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
        var client = new NativeSoftwareCatalogClient();
        using var model = new SoftwareCatalogViewModel(client);
        var window = new MainWindow(shell, auth, null, null, null, null, null, null, null, null, softwareCatalog: model) { Width = 640, Height = 480 };
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "The native catalog fixture did not reach sign-in.");
            var page = shell.Pages.Single(item => item.Id == PageId.SoftwareCatalog);
            shell.CurrentPage = page;
            await FlushAsync();
            Ensure(client.CatalogReads == 0 && !RequireControl<ContentControl>(window, "PageContent").IsVisible,
                "Software was read or shown before sign-in.");

            auth.Username = "native-catalog-admin";
            await auth.SignInAsync("Synthetic-Catalog-Test!".AsMemory());
            await WaitForAsync(() => model.Products.Count == 25, "The native catalog did not load after sign-in.");
            await FlushAsync();
            var view = Descendants<SoftwareCatalogView>(window).Single();
            var heading = SoftwareControl<TextBlock>(view, "PageHeading");
            var title = language == UiLanguage.Polish ? "Katalog oprogramowania" : "Software catalog";
            Ensure(heading.IsVisible && heading.Text == title && page.Title == title && UIElementAutomationPeer.CreatePeerForElement(heading)?.GetName() == title,
                "The software catalog did not expose its localized navigation and heading.");
            var scroll = SoftwareControl<ScrollViewer>(view, "SoftwareCatalogScroll");
            AssertSoftwareViewport(window, scroll, language);
            var next = SoftwareControl<Button>(view, "SoftwareNextProducts");
            next.BringIntoView();
            await FlushAsync();
            AssertInsideWindow(window, next);
            next.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => model.Products.Count == 1 && client.LastCatalog == (string.Empty, 25), "Native product pagination did not advance.");

            var search = SoftwareControl<TextBox>(view, "SoftwareSearch");
            search.BringIntoView();
            await FlushAsync();
            AssertInsideWindow(window, search);
            Ensure(search.MaxLength == SoftwareCatalogContract.MaximumQueryLength &&
                UIElementAutomationPeer.CreatePeerForElement(search)?.GetName() == (language == UiLanguage.Polish ? "Nazwa aplikacji lub wydawca" : "Application name or publisher"),
                "The search field lacked a localized accessible name or bound.");
            search.SetCurrentValue(TextBox.TextProperty, NativeSoftwareCatalogClient.Name);
            search.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            SoftwareControl<Button>(view, "SoftwareSearchButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => client.LastCatalog == (NativeSoftwareCatalogClient.Name, 0) && model.Products.Count == 1,
                "Native search did not apply a literal query and restart paging.");
            await FlushAsync();

            var products = SoftwareControl<ListBox>(view, "SoftwareProducts");
            products.ScrollIntoView(products.Items[0]);
            await FlushAsync();
            var item = (ListBoxItem)products.ItemContainerGenerator.ContainerFromIndex(0);
            Ensure(UIElementAutomationPeer.CreatePeerForElement(item)?.GetName() == NativeSoftwareCatalogClient.Name,
                "The application row lacked a literal accessible name.");
            products.SelectedIndex = 0;
            await WaitForAsync(() => model.HasSelection && model.Installations.Count == 1, "Selecting an application did not load its device and version.");
            await FlushAsync();
            var installations = SoftwareControl<ListBox>(view, "SoftwareInstallations");
            var installed = (SoftwareInstallationRow)installations.Items[0];
            Ensure(installed.Computer == NativeSoftwareCatalogClient.EndpointName && installed.Version == "3.1 (x64)" &&
                installed.Observation.Contains(language == UiLanguage.Polish ? "Niepełny raport" : "Partial report", StringComparison.Ordinal),
                "The version row lost device, architecture or partial report evidence.");

            var history = SoftwareControl<Button>(view, "SoftwareShowProductChanges");
            history.BringIntoView();
            await FlushAsync();
            AssertInsideWindow(window, history);
            history.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => model.SelectedTabIndex == 1 && model.Changes.Count == 1 && client.LastProduct == NativeSoftwareCatalogClient.Id,
                "The application history shortcut did not change view and filter scope.");
            await FlushAsync();
            var tabs = SoftwareControl<TabControl>(view, "SoftwareCatalogTabs");
            Ensure(tabs.SelectedIndex == 1 && Equals(((TabItem)tabs.SelectedItem).Header,
                language == UiLanguage.Polish ? "Zmiany oprogramowania" : "Software changes"), "The changes tab lacked its localized heading.");
            AssertSoftwareViewport(window, SoftwareControl<ScrollViewer>(view, "SoftwareChangesScroll"), language);
            SoftwareControl<Button>(view, "SoftwareShowFleetChanges").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => client.LastProduct is null && model.Changes.Count == 1 && model.Changes[0].Application.Contains("Retired synthetic app", StringComparison.Ordinal),
                "The native history could not return to fleet scope and show the retired application.");
            await FlushAsync();
            var rows = SoftwareControl<ListBox>(view, "SoftwareChanges");
            Ensure(VirtualizingPanel.GetScrollUnit(rows) == ScrollUnit.Pixel && ((SoftwareChangeRow)rows.Items[0]).Observation.Contains(
                language == UiLanguage.Polish ? "Pozycja zniknęła z raportu" : "Disappeared from report", StringComparison.Ordinal),
                "Native history did not preserve the observed wording or readable long-row scrolling.");

            shell.CurrentPage = shell.Pages.Single(item => item.Id == PageId.Devices);
            await FlushAsync();
            Ensure(model.Products.Count == 0 && model.SearchText.Length == 0 && model.Installations.Count == 0 && model.Changes.Count == 0,
                "Navigating away retained catalog data.");
            shell.CurrentPage = page;
            await WaitForAsync(() => model.Products.Count == 25, "Returning to the native catalog did not read a clean product page.");
            await FlushAsync();
            view = Descendants<SoftwareCatalogView>(window).Single();
            tabs = SoftwareControl<TabControl>(view, "SoftwareCatalogTabs");
            tabs.SetCurrentValue(Selector.SelectedIndexProperty, 1);
            tabs.GetBindingExpression(Selector.SelectedIndexProperty)?.UpdateSource();
            await WaitForAsync(() => model.Changes.Count == 1 && client.LastProduct is null, "Opening fleet history directly did not load it.");
            auth.SignOut();
            await FlushAsync();
            Ensure(model.Products.Count == 0 && model.Changes.Count == 0 && !model.HasSelection && model.SelectedTabIndex == 0 &&
                !RequireControl<ContentControl>(window, "PageContent").IsVisible, "Sign-out retained the catalog or its history tab.");
        }
        finally { window.Close(); }
    }

    private static T SoftwareControl<T>(DependencyObject view, string id) where T : FrameworkElement => Descendants<T>(view)
        .Single(control => AutomationProperties.GetAutomationId(control) == id);

    private static void AssertSoftwareViewport(Window window, ScrollViewer scroll, UiLanguage language)
    {
        var viewport = new Size(scroll.ViewportWidth, scroll.ViewportHeight);
        var extent = new Size(scroll.ExtentWidth, scroll.ExtentHeight);
        var id = AutomationProperties.GetAutomationId(scroll);
        var dpi = VisualTreeHelper.GetDpi(scroll).PixelsPerInchX;
        Ensure(viewport.Width > 0 && viewport.Height > 0 && scroll.ScrollableHeight > 0 && scroll.ScrollableWidth == 0,
            $"{id} did not fit or scroll at 640×480 ({language}, {dpi} DPI). Render={scroll.RenderSize}, viewport={viewport}, extent={extent}, scrollable={scroll.ScrollableWidth}×{scroll.ScrollableHeight}.");
        AssertInsideWindow(window, scroll);
    }

    private sealed class NativeSoftwareCatalogClient : ISoftwareCatalogClient
    {
        public const string Name = "Łódź & Editor";
        public const string EndpointName = "Synthetic computer";
        public static readonly string Id = new('a', 64);
        private static readonly Guid Endpoint = Guid.Parse("0bca9248-dfd3-4f20-9bcd-cbbdd414a4b3");
        private static readonly DateTimeOffset Now = new(2026, 11, 25, 16, 45, 0, TimeSpan.Zero);
        private static readonly SoftwareCatalogCoverage Coverage = new(4, 1, 1, 1, 1, 1);
        public int CatalogReads { get; private set; }
        public (string Query, int Offset) LastCatalog { get; private set; }
        public string? LastProduct { get; private set; }

        public Task<DeviceReadResult<SoftwareCatalogPage>> GetSoftwareCatalogAsync(string query, int offset, int limit, CancellationToken cancellationToken)
        {
            CatalogReads++;
            LastCatalog = (query, offset);
            var total = query.Length == 0 ? 26 : 1;
            var items = Enumerable.Range(offset, Math.Min(limit, total - offset)).Select(index => new SoftwareProduct(
                index == 0 ? Id : index.ToString("x64"), index == 0 ? Name : "Synthetic app " + index, null, 1, 1)).ToArray();
            return Task.FromResult(new DeviceReadResult<SoftwareCatalogPage>(DeviceReadOutcome.Success, new(Now, total, offset, limit, Coverage, items)));
        }

        public Task<DeviceReadResult<SoftwareInstallationsPage>> GetSoftwareInstallationsAsync(string productId, int offset, int limit, CancellationToken cancellationToken) =>
            Task.FromResult(new DeviceReadResult<SoftwareInstallationsPage>(DeviceReadOutcome.Success,
                new(productId, Now, 1, offset, limit, [new(Endpoint, EndpointName, "3.1", "x64", Now.AddHours(-7), true, true)])));

        public Task<DeviceReadResult<SoftwareChangesPage>> GetSoftwareChangesAsync(string? productId, int offset, int limit, CancellationToken cancellationToken)
        {
            LastProduct = productId;
            var change = new SoftwareChange(Endpoint, EndpointName, productId ?? new string('b', 64), productId is null ? "Retired synthetic app" : Name,
                null, "disappeared", Now.AddHours(-9), Now.AddHours(-3), 1, 0, [new("2.1", "x86")], []);
            return Task.FromResult(new DeviceReadResult<SoftwareChangesPage>(DeviceReadOutcome.Success, new(productId, Now, 1, offset, limit, [change])));
        }
    }
}
