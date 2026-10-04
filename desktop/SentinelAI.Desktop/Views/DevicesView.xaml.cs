using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class DevicesView : UserControl
{
    public DevicesView() => InitializeComponent();

    private DevicesViewModel? Model => DataContext as DevicesViewModel;

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshAsync();
    }

    private void OnClearFilters(object sender, RoutedEventArgs e)
    {
        if (Model is not { } model) return;
        model.SearchText = string.Empty;
        model.HealthFilter = DeviceHealthFilter.All;
    }

    private async void OnOpenDetail(object sender, RoutedEventArgs e) => await OpenSelectedDeviceAsync();

    private async void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Double-clicking a header or empty space must not open a stale selection.
        if (e.ChangedButton == MouseButton.Left && e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(DevicesGrid, source) is DataGridRow { Item: DeviceRow device } && Model is { } model)
            await OpenDeviceAsync(model, device);
    }

    private Task OpenSelectedDeviceAsync() => Model is { SelectedDevice: { } selected } model
        ? OpenDeviceAsync(model, selected)
        : Task.CompletedTask;

    private Task OpenDeviceAsync(DevicesViewModel model, DeviceRow device)
    {
        var operation = model.OpenDetailAsync(device.EndpointId);
        PageScroller.ScrollToTop();
        return operation;
    }

    private void OnBack(object sender, RoutedEventArgs e)
    {
        Model?.CloseDetail();
        PageScroller.ScrollToTop();
    }

    private void OnPreviousPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanPreviousPage: true } model) model.PageIndex--;
    }

    private void OnNextPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanNextPage: true } model) model.PageIndex++;
    }

    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e)
    {
        // An outer page scroll remains usable in short windows while the finite
        // DataGrid viewport preserves native recycling row virtualization.
        DevicesGrid.Height = Math.Max(160, e.NewSize.Height - PageHeader.ActualHeight - ListToolbar.ActualHeight - ListPaging.ActualHeight - 24);
    }
}
