using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task NotificationsViewsAsync()
    {
        try
        {
            foreach (var language in new[] { UiLanguage.English, UiLanguage.Polish })
            {
                Localizer.Use(language);
                using var health = new FakeCoreClient();
                using var shell = new ShellViewModel(health, "notification-test");
                using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
                var client = new NativeNotificationsClient();
                using var notifications = new NotificationsViewModel(client);
                var source = PresentationTraceSources.DataBindingSource;
                var level = source.Switch.Level;
                using var trace = new BindingTrace();
                source.Switch.Level = SourceLevels.Warning; source.Listeners.Add(trace);
                var window = new MainWindow(shell, auth, null, null, null, null, null, null, null, null, notifications: notifications);
                try
                {
                    window.Show();
                    await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Notification fixture did not reach sign-in.");
                    shell.CurrentPage = shell.Pages.Single(p => p.Id == PageId.Notifications);
                    await FlushAsync();
                    Ensure(client.ListReads == 0 && !RequireControl<ContentControl>(window, "PageContent").IsVisible,
                        "The notification page requested or displayed administrator data before sign-in.");
                    auth.Username = "native-notification-admin";
                    await auth.SignInAsync("Synthetic-Native-Notification!".AsMemory());
                    await WaitForAsync(() => notifications.CanSavePolicy && notifications.Rows.Count > 0, "Signing in did not load the native notification center.");
                    await FlushAsync();
                    var view = Descendants<NotificationsView>(window).Single();
                    Ensure(ReferenceEquals(view.DataContext, notifications) && shell.CurrentPage.Title == (language == UiLanguage.Polish ? "Powiadomienia" : "Notifications"),
                        "The notification page/navigation did not use the real localized view model.");
                    var heading = Descendants<TextBlock>(view).Single(t => AutomationProperties.GetAutomationId(t) == "PageHeading");
                    Ensure(heading.IsVisible && heading.Text == shell.CurrentPage.Title && AutomationProperties.GetName(heading) == shell.CurrentPage.Title,
                        "The notification page did not expose the shared localized navigation heading.");
                    Ensure(Descendants<TextBlock>(view).Any(t => t.Text == "{Binding hostile}<script>literal endpoint</script>") && Descendants<TextBlock>(view).All(t => !t.Inlines.OfType<System.Windows.Documents.Hyperlink>().Any()),
                        "The native page interpreted endpoint text as markup or provided hostile-link navigation.");
                    var url = (PasswordBox)view.FindName("WebhookUrlInput");
                    var secret = (PasswordBox)view.FindName("WebhookSecretInput");
                    var password = (PasswordBox)view.FindName("SmtpPasswordInput");
                    Ensure(url.IsEnabled && secret.IsEnabled && password.IsEnabled && !notifications.WebhookEnabled && !notifications.EmailEnabled,
                        "Protected inputs were not usable or opening the page enabled external channels.");
                    window.Width = window.MinWidth; window.Height = window.MinHeight;
                    await FlushAsync();
                    var scroll = Descendants<ScrollViewer>(view).Single(s => AutomationProperties.GetAutomationId(s) == "NotificationsScroll");
                    Ensure(scroll.ScrollableHeight > 0 && scroll.ScrollableWidth == 0, "The native notification page did not scroll vertically at 640×480.");
                    foreach (var control in new FrameworkElement[] { url, secret, password, NotificationButton(view, "NotificationsSave") })
                    {
                        control.BringIntoView(); await FlushAsync();
                        AssertInsideWindow(window, control);
                        Ensure(control.IsEnabled && control.Focusable, "A protected input or explicit save was unreachable at the minimum viewport.");
                    }
                    var list = Descendants<ListBox>(view).Single(l => AutomationProperties.GetAutomationId(l) == "NotificationsList");
                    list.SelectedIndex = 0;
                    NotificationButton(view, "NotificationsMarkRead").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    await WaitForAsync(() => client.ReadWrites == 1 && !notifications.IsBusy, "Native mark-read did not complete.");
                    Ensure(!notifications.CanMarkRead, "The native read action kept an already-read notification enabled.");
                    url.Password = "https://public.example/hook?token=synthetic";
                    secret.Password = "Synthetic-Native-Webhook-Secret";
                    password.Password = "Synthetic-Native-Smtp-Password";
                    var controlsWereCleared = false;
                    client.OnSave = () => controlsWereCleared = url.Password.Length == 0 && secret.Password.Length == 0 && password.Password.Length == 0;
                    client.PendingWrite = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    NotificationButton(view, "NotificationsSave").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    Ensure(controlsWereCleared, "Native secret controls retained plaintext during submission.");
                    Ensure(client.PolicyWrites == 1 && client.InputLengths.SequenceEqual([43, 31, 30]), "Native protected input buffers lost their exact values before submission.");
                    Ensure(client.Inputs.All(memory => memory.Span.IndexOfAnyExcept('\0') < 0), "Plaintext input buffers survived serialization while HTTP was pending.");
                    client.PendingWrite.SetResult(new(NotificationRequestOutcome.Success, NativeNotificationsClient.Policy()));
                    await WaitForAsync(() => !notifications.IsBusy, "Native notification save did not settle.");
                    url.Password = "https://public.example/unsaved?token=synthetic"; secret.Password = "Synthetic-Unsubmitted-Secret"; password.Password = "Synthetic-Unsubmitted-Password";
                    shell.CurrentPage = shell.Pages.Single(p => p.Id == PageId.Overview);
                    await FlushAsync();
                    Ensure(url.Password.Length == 0 && secret.Password.Length == 0 && password.Password.Length == 0 && notifications.Rows.Count == 0 && notifications.Policy is null,
                        "Leaving Notifications retained secrets, data or an editable policy version.");
                    shell.CurrentPage = shell.Pages.Single(p => p.Id == PageId.Notifications);
                    await WaitForAsync(() => notifications.CanSavePolicy, "Returning to Notifications did not refresh its policy version.");
                    await FlushAsync();
                    view = Descendants<NotificationsView>(window).Single();
                    url = (PasswordBox)view.FindName("WebhookUrlInput"); url.Password = "https://public.example/unsaved";
                    auth.SignOut(); await FlushAsync();
                    Ensure(url.Password.Length == 0 && notifications.Rows.Count == 0 && notifications.Policy is null && !notifications.CanSavePolicy,
                        "Signing out retained notification data or a protected destination input.");
                    Ensure(trace.Messages.Count == 0, "Native notification bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
                }
                finally
                {
                    if (window.IsVisible) window.Close();
                    source.Listeners.Remove(trace); source.Switch.Level = level;
                }
            }
        }
        finally { Localizer.Use(UiLanguage.English); }
    }

    private static Button NotificationButton(DependencyObject parent, string id) => Descendants<Button>(parent).Single(b => AutomationProperties.GetAutomationId(b) == id);
    private sealed class NativeNotificationsClient : INotificationsClient
    {
        private static readonly Guid Id = Guid.Parse("93e95651-1930-4e2e-88e7-e5bc6e57d381");
        internal int ListReads, ReadWrites, PolicyWrites;
        internal Action? OnSave;
        internal int[] InputLengths = [];
        internal ReadOnlyMemory<char>[] Inputs = [];
        internal TaskCompletionSource<NotificationResult<NotificationPolicy>>? PendingWrite;
        internal static NotificationPolicy Policy() => new(4, true, true, 15, 5, false, null, false, false, false, null, 587, null, false, null, null, "available");
        public Task<NotificationResult<NotificationPage>> GetNotificationsAsync(int offset, int limit, bool unread, CancellationToken token)
        {
            ListReads++;
            var now = DateTimeOffset.UtcNow;
            var item = new NotificationSummary(Id, "criticalAlertNew", Guid.NewGuid(), "{Binding hostile}<script>literal endpoint</script>", Guid.NewGuid(), "rule.synthetic", "critical", 3, now, now, ReadWrites > 0 ? now : null);
            return Task.FromResult(new NotificationResult<NotificationPage>(NotificationRequestOutcome.Success, new(1, ReadWrites > 0 ? 0 : 1, offset, limit, [item])));
        }
        public Task<NotificationResult<bool>> MarkNotificationReadAsync(Guid id, CancellationToken token)
        { ReadWrites++; return Task.FromResult(new NotificationResult<bool>(NotificationRequestOutcome.Success, true)); }
        public Task<NotificationResult<NotificationDeliveryPage>> GetNotificationDeliveriesAsync(int offset, int limit, Guid? id, CancellationToken token) =>
            Task.FromResult(new NotificationResult<NotificationDeliveryPage>(NotificationRequestOutcome.Success, new(0, offset, limit, [])));
        public Task<NotificationResult<NotificationPolicy>> GetNotificationPolicyAsync(CancellationToken token) => Task.FromResult(new NotificationResult<NotificationPolicy>(NotificationRequestOutcome.Success, Policy()));
        public Task<NotificationResult<NotificationPolicy>> SetNotificationPolicyAsync(NotificationPolicyWrite policy, ReadOnlyMemory<char> url, ReadOnlyMemory<char> secret, ReadOnlyMemory<char> password, CancellationToken token)
        {
            PolicyWrites++; InputLengths = [url.Length, secret.Length, password.Length]; Inputs = [url, secret, password]; OnSave?.Invoke();
            return PendingWrite?.Task ?? Task.FromResult(new NotificationResult<NotificationPolicy>(NotificationRequestOutcome.Success, Policy()));
        }
    }
}
