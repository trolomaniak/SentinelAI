using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class OverviewView : UserControl
{
    public OverviewView() => InitializeComponent();

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        if (IsVisible && sender is FrameworkElement { DataContext: OperationsOverviewViewModel model })
            await model.RefreshAsync();
    }
}
