using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class DevicesView : UserControl
{
    public DevicesView() => InitializeComponent();

    private DevicesViewModel? Model => DataContext as DevicesViewModel;
    private ComputerEnrollmentViewModel? Enrollment => (Window.GetWindow(this) as MainWindow)?.ComputerEnrollment;

    private async void OnAddComputersExpanded(object sender, RoutedEventArgs e)
    {
        if (Enrollment is { } enrollment) await enrollment.LoadAsync();
    }

    private async void OnCreateCodes(object sender, RoutedEventArgs e)
    {
        if (Enrollment is { } enrollment) await enrollment.IssueAsync();
    }

    private void OnCopyCodes(object sender, RoutedEventArgs e)
    {
        if (Enrollment is { IssuedCodesText.Length: > 0 } enrollment) Clipboard.SetText(enrollment.IssuedCodesText);
    }

    // One small ".sentinelai-enroll" file per code in a folder the administrator chooses.
    private void OnSaveCodes(object sender, RoutedEventArgs e)
    {
        if (Enrollment is not { IssuedCodes.Count: > 0 } enrollment) return;
        var dialog = new OpenFolderDialog { Title = "Choose a folder for the enrollment code files" };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        try
        {
            EnrollmentCodeFiles.Write(dialog.FolderName, enrollment.IssuedCodes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(Window.GetWindow(this), "The code files could not be saved there. Choose another folder.", "SentinelAI",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnRevokeCode(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid id } && Enrollment is { } enrollment) await enrollment.RevokeAsync(id);
    }

    private void OnRemoveComputer(object sender, RoutedEventArgs e) => RemoveComputerConfirmation.Visibility = Visibility.Visible;

    private void OnCancelRemoveComputer(object sender, RoutedEventArgs e) => RemoveComputerConfirmation.Visibility = Visibility.Collapsed;

    private async void OnConfirmRemoveComputer(object sender, RoutedEventArgs e)
    {
        RemoveComputerConfirmation.Visibility = Visibility.Collapsed;
        if (Model is not { Detail: { } detail } model || Enrollment is not { } enrollment) return;
        if (!await enrollment.RemoveComputerAsync(detail.EndpointId)) return;
        model.CloseDetail();
        PageScroller.ScrollToTop();
        await model.RefreshAsync();
    }

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
        RemoveComputerConfirmation.Visibility = Visibility.Collapsed;
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
