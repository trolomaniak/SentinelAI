using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class ReportsView : UserControl
{
    public ReportsView() => InitializeComponent();
    private ReportsViewModel? Model => DataContext as ReportsViewModel;
    private async void OnGenerate(object sender, RoutedEventArgs e)
    {
        if (Model is { CanGenerate: true } model) await model.GenerateAsync();
    }
    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (Model is { CanSave: true } model) await model.SaveAsync();
    }
    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e) =>
        ReportActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
}
