using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;

namespace SentinelAI.Desktop.Views;

public partial class AuthenticationView : UserControl
{
    public static readonly DependencyProperty SetupOnlyProperty = DependencyProperty.Register(nameof(SetupOnly), typeof(bool), typeof(AuthenticationView), new PropertyMetadata(false));
    public bool SetupOnly { get => (bool)GetValue(SetupOnlyProperty); set => SetValue(SetupOnlyProperty, value); }
    private AuthenticationViewModel? _model;

    public AuthenticationView()
    {
        InitializeComponent();
        DataContextChanged += OnContextChanged;
        Unloaded += (_, _) => PasswordInput.Clear();
    }

    private void OnContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_model is not null) _model.PropertyChanged -= OnModelChanged;
        _model = e.NewValue as AuthenticationViewModel;
        if (_model is not null) _model.PropertyChanged += OnModelChanged;
        PasswordInput.Clear();
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AuthenticationViewModel.State))
        {
            // Clear once per state notification, before the next input opportunity.
            // The same update also notifies IsSignedIn, after fresh input may arrive.
            if (Dispatcher.CheckAccess()) PasswordInput.Clear();
            else Dispatcher.InvokeAsync(() => PasswordInput.Clear());
        }
    }

    private async void OnSignIn(object sender, RoutedEventArgs e) => await SubmitAsync(create: false);
    private async void OnCreateAdministrator(object sender, RoutedEventArgs e) => await SubmitAsync(create: true);

    private async Task SubmitAsync(bool create)
    {
        if (_model is null) return;
        using var secret = PasswordInput.SecurePassword;
        PasswordInput.Clear();
        var characters = new char[secret.Length];
        var pointer = Marshal.SecureStringToGlobalAllocUnicode(secret);
        try
        {
            for (var index = 0; index < characters.Length; index++) characters[index] = (char)Marshal.ReadInt16(pointer, index * 2);
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
        try
        {
            if (create) await _model.CreateAdministratorAsync(characters);
            else await _model.SignInAsync(characters);
        }
        finally { Array.Clear(characters); }
    }

    private void OnSignOut(object sender, RoutedEventArgs e) { PasswordInput.Clear(); _model?.SignOut(); }
    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        PasswordInput.Clear();
        if (_model is not null) await _model.InitializeAsync();
    }
    private void OnElevatedSetup(object sender, RoutedEventArgs e)
    {
        PasswordInput.Clear();
        if (!WindowsCoreServices.OpenElevatedSetup())
            MessageBox.Show("Initial setup needs administrator permission. You can try again when ready.", "SentinelAI", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
