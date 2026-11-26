using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class SoftwareCatalogView : UserControl
{
    public SoftwareCatalogView() => InitializeComponent();

    private SoftwareCatalogViewModel? Model => DataContext as SoftwareCatalogViewModel;

    private async void OnProductSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Model is { } model && sender is ListBox list)
            await model.SelectProductAsync(list.SelectedItem as SoftwareProductRow);
    }

    private async void OnSearchKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || Model is not { } model) return;
        e.Handled = true;
        await model.SearchAsync();
    }

    private async void OnSearch(object sender, RoutedEventArgs e) { if (Model is { } model) await model.SearchAsync(); }
    private async void OnClearSearch(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ClearSearchAsync(); }
    private async void OnRefreshProducts(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshAsync(); }
    private async void OnPreviousProducts(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousProductsAsync(); }
    private async void OnNextProducts(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextProductsAsync(); }
    private async void OnRefreshInstallations(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshInstallationsAsync(); }
    private async void OnPreviousInstallations(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousInstallationsAsync(); }
    private async void OnNextInstallations(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextInstallationsAsync(); }
    private async void OnShowProductChanges(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ShowProductChangesAsync(); }
    private async void OnShowFleetChanges(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ShowFleetChangesAsync(); }
    private async void OnRefreshChanges(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshChangesAsync(); }
    private async void OnPreviousChanges(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousChangesAsync(); }
    private async void OnNextChanges(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextChangesAsync(); }
}
