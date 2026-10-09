namespace SentinelAI.Setup.Foundation;

/// <summary>Prevents installer child processes from honoring inherited code-loading overrides.</summary>
public static class SetupEnvironmentRules
{
    private static readonly string[] Prefixes = ["CORECLR_", "COMPLUS_", "COR_", "DOTNET_", "APPDOMAIN_MANAGER", "__COMPAT_"];
    private static readonly string[] Names =
    [
        "COR_ENABLE_PROFILING", "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE",
        "DOTNET_BUNDLE_EXTRACT_BASE_DIR", "DOTNET_ROLL_FORWARD", "DOTNET_MULTILEVEL_LOOKUP",
        "DEVPATH", "SENTINELAI_BOOTSTRAP_USERNAME", "SENTINELAI_BOOTSTRAP_PASSWORD"
    ];

    public static bool IsExecutionOverride(string name) => Prefixes.Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
        Names.Contains(name, StringComparer.OrdinalIgnoreCase);
}
