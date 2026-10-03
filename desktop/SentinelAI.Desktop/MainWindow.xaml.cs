using System.Windows;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop;

public partial class MainWindow : Window
{
    private readonly ShellViewModel _viewModel;

    public MainWindow(ShellViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Core availability never delays the native window opening.
        await _viewModel.InitializeAsync();
    }

    protected override void OnClosed(EventArgs e)
    {
        Loaded -= OnLoaded;
        _viewModel.Dispose();
        base.OnClosed(e);
    }
}
