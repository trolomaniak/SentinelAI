using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class AiExplanationView : UserControl
{
    public AiExplanationView() => InitializeComponent();
    private AiExplanationViewModel? Model => DataContext as AiExplanationViewModel;

    private async void OnExplain(object sender, RoutedEventArgs e)
    {
        if (Model is { CanExplain: true } model) await model.ExplainAsync();
    }

    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e) =>
        AiActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
}
