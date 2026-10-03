using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

namespace SentinelAI.Desktop;

/// <summary>The separately elevated setup window owns no bearer session and never controls Core lifetime.</summary>
public sealed class SetupWindow : Window
{
    private readonly AuthenticationViewModel _model;
    public SetupWindow(IAdministratorSetupClient setup)
    {
        Title = "SentinelAI — initial administrator setup";
        Width = 620; Height = 650; MinWidth = 480; MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI"); FontSize = 14;
        _model = new AuthenticationViewModel(new SetupOnlyAuthenticationClient(), setup);
        var layout = new DockPanel { Margin = new Thickness(24) };
        var close = new Button { Content = "Close", Margin = new Thickness(0, 16, 0, 0) };
        close.Click += (_, _) => Close();
        DockPanel.SetDock(close, Dock.Bottom);
        layout.Children.Add(close);
        layout.Children.Add(new AuthenticationView { DataContext = _model, SetupOnly = true });
        Content = layout;
        Loaded += OnLoaded;
    }
    private async void OnLoaded(object sender, RoutedEventArgs e) => await _model.InitializeAsync();
    protected override void OnClosed(EventArgs e) { Loaded -= OnLoaded; _model.Dispose(); base.OnClosed(e); }
    private sealed class SetupOnlyAuthenticationClient : IAuthenticationClient
    {
        public Task<AuthenticationResult> SignInAsync(string username, ReadOnlyMemory<char> password, CancellationToken token) => Task.FromResult(new AuthenticationResult(AuthenticationOutcome.Unavailable));
        public Task<SessionResult> ValidateSessionAsync(CancellationToken token) => Task.FromResult(new SessionResult(SessionStatus.SignedOut));
        public void SignOut() { }
        public void Dispose() { }
    }
}
