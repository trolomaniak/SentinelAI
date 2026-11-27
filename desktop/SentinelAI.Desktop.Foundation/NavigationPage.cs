namespace SentinelAI.Desktop.Foundation;

public enum PageId
{
    Overview,
    Devices,
    Alerts,
    Risk,
    RiskRegister,
    Reports,
    Notifications,
    MonitoringCoverage,
    Settings,
    SoftwareCatalog,
    VulnerabilityCenter
}

public sealed record NavigationPage(PageId Id, string Title, string Description);
