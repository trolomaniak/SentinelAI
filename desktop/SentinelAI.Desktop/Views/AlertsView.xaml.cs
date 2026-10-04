using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class AlertsView : UserControl
{
    public AlertsView() => InitializeComponent();

    private AlertsViewModel? Model => DataContext as AlertsViewModel;

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshAsync();
        PageScroller.ScrollToTop();
    }

    private async void OnApplyFilters(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.ApplyFiltersAsync();
        PageScroller.ScrollToTop();
    }

    private async void OnPreviousPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanPreviousPage: true } model) await model.PreviousPageAsync();
        PageScroller.ScrollToTop();
    }

    private async void OnNextPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanNextPage: true } model) await model.NextPageAsync();
        PageScroller.ScrollToTop();
    }

    private async void OnOpenDetail(object sender, RoutedEventArgs e)
    {
        if (Model is { SelectedAlert: { } alert } model) await OpenAlertAsync(model, alert);
    }

    private async void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left && e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(AlertsGrid, source) is DataGridRow { Item: AlertRow alert } && Model is { } model)
            await OpenAlertAsync(model, alert);
    }

    private Task OpenAlertAsync(AlertsViewModel model, AlertRow alert)
    {
        var operation = model.OpenDetailAsync(alert.AlertId);
        PageScroller.ScrollToTop();
        DetailActionsScroller.ScrollToTop();
        return operation;
    }

    private async void OnRefreshDetail(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshDetailAsync();
        PageScroller.ScrollToTop();
    }

    private async void OnSaveStatus(object sender, RoutedEventArgs e)
    {
        if (Model is { ProposedStatus: { } status, CanSaveStatus: true } model)
            await model.SaveStatusAsync(status);
        PageScroller.ScrollToTop();
    }

    private void OnBack(object sender, RoutedEventArgs e)
    {
        Model?.CloseDetail();
        PageScroller.ScrollToTop();
    }

    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e)
    {
        AlertsGrid.Height = Math.Max(160, e.NewSize.Height - PageHeader.ActualHeight - ListToolbar.ActualHeight - ListPaging.ActualHeight - 24);
        // Keep Back/Refresh above long detail content without consuming the
        // entire detail viewport at the minimum supported window dimensions.
        DetailActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
    }
}
