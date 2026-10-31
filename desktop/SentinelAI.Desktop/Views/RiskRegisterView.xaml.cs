using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

/// <summary>TASK-032: the Risk Register page; every value and rule comes from the view model and Core.</summary>
public partial class RiskRegisterView : UserControl
{
    public RiskRegisterView() => InitializeComponent();
    private RiskRegisterViewModel? Model => DataContext as RiskRegisterViewModel;

    private async void OnApplyFilters(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.ApplyFiltersAsync();
    }

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        if (Model is { } model) await model.RefreshAsync();
    }

    private async void OnNewRisk(object sender, RoutedEventArgs e)
    {
        if (Model is not { } model) return;
        var operation = model.NewRiskAsync();
        Editor.BringIntoView();
        await operation;
    }

    private async void OnPreviousPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanPreviousPage: true } model) await model.PreviousPageAsync();
    }

    private async void OnNextPage(object sender, RoutedEventArgs e)
    {
        if (Model is { CanNextPage: true } model) await model.NextPageAsync();
    }

    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (Model is { CanSave: true } model) await model.SaveAsync();
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Model?.CancelEdit();

    private async void OnLoadAlerts(object sender, RoutedEventArgs e)
    {
        if (Model is { CanEdit: true } model) await model.LoadAlertChoicesAsync();
    }

    private async void OnReview(object sender, RoutedEventArgs e)
    {
        if (Model is { CanReview: true } model) await model.RecordReviewAsync();
    }
}
