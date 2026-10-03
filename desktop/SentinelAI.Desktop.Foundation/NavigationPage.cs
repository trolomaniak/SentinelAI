namespace SentinelAI.Desktop.Foundation;

public enum PageId
{
    Overview,
    Devices,
    Alerts,
    Risk,
    Reports,
    Settings
}

public sealed record NavigationPage(PageId Id, string Title, string Description);
