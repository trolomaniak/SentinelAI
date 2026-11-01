using System.Windows.Controls;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    // The Polish version: views created after Desktop chose Polish show the catalog's texts.
    private static async Task PolishViewsAsync()
    {
        Localizer.Use(UiLanguage.Polish);
        try
        {
            using var health = new FakeCoreClient();
            using var shell = new ShellViewModel(health, "polish-test");
            using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
            using var license = new LicenseViewModel(new NativeLicenseClient());
            using var register = new RiskRegisterViewModel(new NativeRiskRegisterClient());
            var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, riskRegister: register);
            try
            {
                window.Show();
                await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Polish fixture did not reach sign-in.");
                auth.Username = "native-polish-admin";
                await auth.SignInAsync("Synthetic-Polish-Admin!".AsMemory());
                shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.RiskRegister);
                await WaitForAsync(() => register.ListState == RiskRegisterListState.Ready, "The Polish Risk Register page did not read Core's records.");
                await FlushAsync();
                var view = Descendants<RiskRegisterView>(window).Single();
                Ensure(RegisterText(view, "PageHeading") == "Rejestr ryzyk" && Descendants<Button>(view).Any(button => button.Content as string == "Nowe ryzyko") &&
                       shell.Pages.Select(page => page.Title).Contains("Ustawienia"), "Views and navigation were not shown in Polish.");
            }
            finally
            {
                if (window.IsVisible) window.Close();
            }
        }
        finally
        {
            Localizer.Use(UiLanguage.English);
        }
    }
}
