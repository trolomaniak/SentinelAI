using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class MonitoringCoverageView : UserControl
{
    public MonitoringCoverageView() => InitializeComponent();

    private MonitoringCoverageViewModel? Model => DataContext as MonitoringCoverageViewModel;

    private async void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    { if (Model is { } model && sender is ListBox list) await model.SelectEndpointAsync(list.SelectedItem as MonitoringEndpointRow); }

    private async void OnRefresh(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshAsync(); }
    private async void OnPrevious(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousPageAsync(); }
    private async void OnNext(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextPageAsync(); }
    private async void OnRefreshDetail(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshDetailAsync(); }
    private async void OnRefreshGaps(object sender, RoutedEventArgs e) { if (Model is { } model) await model.RefreshGapsAsync(); }
    private async void OnPreviousGap(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousGapPageAsync(); }
    private async void OnNextGap(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextGapPageAsync(); }
}
