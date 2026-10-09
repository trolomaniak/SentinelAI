using System.Collections;
using System.Diagnostics;
using System.IO;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

internal static class ChildProcessEnvironment
{
    // Only this process's child inheritance changes. Windows execution/language
    // policies, registry, network settings and unrelated credentials are untouched.
    public static void SanitizeParent()
    {
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            if (entry.Key is string name && SetupEnvironmentRules.IsExecutionOverride(name)) Environment.SetEnvironmentVariable(name, null);
    }

    public static void ConfigurePowerShell(ProcessStartInfo start)
    {
        foreach (var name in start.Environment.Keys.ToArray()) if (SetupEnvironmentRules.IsExecutionOverride(name)) start.Environment.Remove(name);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system = Path.Combine(windows, "System32"); var powershell = Path.Combine(system, "WindowsPowerShell", "v1.0");
        start.Environment["PSModulePath"] = Path.Combine(powershell, "Modules");
        start.Environment["PATH"] = string.Join(Path.PathSeparator, system, windows, powershell);
    }
}
