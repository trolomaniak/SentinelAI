namespace SentinelAI.Core;

internal sealed record CoreHostingMode(bool IsWindowsService);

internal static class CoreServiceHosting
{
    internal const string ServiceName = "SentinelAICore";
    internal static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(15);

    internal static void ValidateStartup(bool isWindowsService, bool hasProtectedConfiguration,
        string? bootstrapUsername, string? bootstrapPassword)
    {
        if (!isWindowsService)
            return;
        if (!hasProtectedConfiguration)
            throw new InvalidOperationException("The Core Windows Service requires an explicit protected --config file.");
        if (!string.IsNullOrEmpty(bootstrapUsername) || !string.IsNullOrEmpty(bootstrapPassword))
            throw new InvalidOperationException("Administrator bootstrap is unavailable in the Core Windows Service. Complete local setup before starting the service.");
    }
}
