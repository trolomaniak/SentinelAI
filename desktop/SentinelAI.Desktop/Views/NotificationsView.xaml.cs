using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class NotificationsView : UserControl
{
    public NotificationsView()
    {
        InitializeComponent();
        DataContextChanged += OnContextChanged;
        Unloaded += OnUnloaded;
        Loaded += OnLoaded;
    }
    private NotificationsViewModel? Model => DataContext as NotificationsViewModel;
    private void OnLoaded(object sender, RoutedEventArgs e)
    { if (Model is { } model) { model.PropertyChanged -= OnModelChanged; model.PropertyChanged += OnModelChanged; } }
    private void OnUnloaded(object sender, RoutedEventArgs e)
    { if (Model is { } model) model.PropertyChanged -= OnModelChanged; ClearInputs(); }
    private void OnContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is NotificationsViewModel old) old.PropertyChanged -= OnModelChanged;
        if (e.NewValue is NotificationsViewModel current) current.PropertyChanged += OnModelChanged;
        ClearInputs();
    }
    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        void ClearWhenInactive() { if (Model is null || Model.Policy is null || Model.IsBusy) ClearInputs(); }
        if (Dispatcher.CheckAccess()) ClearWhenInactive(); else Dispatcher.InvokeAsync(ClearWhenInactive);
    }
    private void ClearInputs() { WebhookUrlInput.Clear(); WebhookSecretInput.Clear(); SmtpPasswordInput.Clear(); }
    private async void OnRefresh(object sender, RoutedEventArgs e) { ClearInputs(); if (Model is { } model) await model.RefreshAsync(); }
    private async void OnApplyFilter(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ApplyFilterAsync(); }
    private async void OnPrevious(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousPageAsync(); }
    private async void OnNext(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextPageAsync(); }
    private async void OnMarkRead(object sender, RoutedEventArgs e) { if (Model is { } model) await model.MarkSelectedReadAsync(); }
    private async void OnSelectedDeliveries(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ShowSelectedDeliveriesAsync(); }
    private async void OnAllDeliveries(object sender, RoutedEventArgs e) { if (Model is { } model) await model.ShowAllDeliveriesAsync(); }
    private async void OnPreviousDelivery(object sender, RoutedEventArgs e) { if (Model is { } model) await model.PreviousDeliveryPageAsync(); }
    private async void OnNextDelivery(object sender, RoutedEventArgs e) { if (Model is { } model) await model.NextDeliveryPageAsync(); }
    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (Model is not { CanSavePolicy: true } model) { ClearInputs(); return; }
        char[] url = [], secret = [], password = [];
        Task? save = null;
        try
        {
            url = Consume(WebhookUrlInput); secret = Consume(WebhookSecretInput); password = Consume(SmtpPasswordInput);
            // The client serializes the buffers synchronously before returning its pending HTTP operation.
            save = model.SavePolicyAsync(url, secret, password);
        }
        finally { Array.Clear(url); Array.Clear(secret); Array.Clear(password); ClearInputs(); }
        if (save is not null) await save;
    }
    private static char[] Consume(PasswordBox input)
    {
        using var value = input.SecurePassword;
        var pointer = IntPtr.Zero;
        try
        {
            var result = new char[value.Length];
            pointer = Marshal.SecureStringToGlobalAllocUnicode(value);
            Marshal.Copy(pointer, result, 0, result.Length);
            return result;
        }
        finally { if (pointer != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pointer); input.Clear(); }
    }
}
