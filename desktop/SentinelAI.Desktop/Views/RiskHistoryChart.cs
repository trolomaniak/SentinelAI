using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Media;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public sealed class RiskHistoryChart : FrameworkElement
{
    public static readonly DependencyProperty HistoryProperty = DependencyProperty.Register(nameof(History), typeof(RiskHistoryPresentation),
        typeof(RiskHistoryChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public RiskHistoryPresentation? History
    {
        get => (RiskHistoryPresentation?)GetValue(HistoryProperty);
        set => SetValue(HistoryProperty, value);
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new FrameworkElementAutomationPeer(this);

    protected override void OnRender(DrawingContext drawingContext)
    {
        base.OnRender(drawingContext);
        const double padding = 6;
        var width = RenderSize.Width - 2 * padding;
        var height = RenderSize.Height - 2 * padding;
        if (History is not { } history || width <= 0 || height <= 0) return;

        var grid = new Pen(TryFindResource("BorderBrush") as Brush ?? Brushes.Gray, 1);
        for (var tick = 0; tick <= 2; tick++)
        {
            var y = padding + height * tick / 2;
            drawingContext.DrawLine(grid, new Point(padding, y), new Point(padding + width, y));
        }

        var pointBrush = TryFindResource("AccentBrush") as Brush ?? Brushes.Navy;
        var duration = (history.GeneratedUtc - history.StartUtc).TotalSeconds;
        foreach (var point in history.Points)
        {
            var x = padding + width * (duration > 0 ? (point.CapturedUtc - history.StartUtc).TotalSeconds / duration : 0);
            var y = padding + height * (100 - point.Score) / 100;
            drawingContext.DrawEllipse(pointBrush, null, new Point(x, y), 3, 3);
        }
    }
}
