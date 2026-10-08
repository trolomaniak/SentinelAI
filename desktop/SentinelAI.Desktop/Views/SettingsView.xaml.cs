using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class SettingsView : UserControl
{
    public SettingsView() => InitializeComponent();
    private LicenseViewModel? Model => DataContext as LicenseViewModel;

    private async void OnRefreshLicense(object sender, RoutedEventArgs e)
    {
        if (Model is { CanRefresh: true } model) await model.RefreshAsync();
    }

    private async void OnRenewLicense(object sender, RoutedEventArgs e)
    {
        if (Model is { CanRenew: true } model) await model.RenewAsync();
    }

    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e) =>
        SettingsActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
}
