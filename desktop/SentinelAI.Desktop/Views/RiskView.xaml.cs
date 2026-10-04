using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class RiskView : UserControl
{
    public RiskView() => InitializeComponent();
    private RiskViewModel? Model => DataContext as RiskViewModel;

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshAsync();
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
    private async void OnOpenEndpoint(object sender, RoutedEventArgs e)
    {
        if (Model is { SelectedEndpoint: { } endpoint } model) await OpenEndpointAsync(model, endpoint);
    }
    private async void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left && e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(RiskGrid, source) is DataGridRow { Item: EndpointRiskRow endpoint } && Model is { } model)
            await OpenEndpointAsync(model, endpoint);
    }
    private Task OpenEndpointAsync(RiskViewModel model, EndpointRiskRow endpoint)
    {
        var operation = model.OpenEndpointAsync(endpoint.EndpointId);
        PageScroller.ScrollToTop();
        DetailActionsScroller.ScrollToTop();
        return operation;
    }
    private async void OnRefreshDetail(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshDetailAsync();
        PageScroller.ScrollToTop();
    }
    private void OnBack(object sender, RoutedEventArgs e)
    {
        Model?.CloseDetail();
        PageScroller.ScrollToTop();
    }
    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e)
    {
        RiskGrid.Height = Math.Max(160, e.NewSize.Height - PageHeader.ActualHeight - ListToolbar.ActualHeight - ListPaging.ActualHeight - 24);
        DetailActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
    }
}
