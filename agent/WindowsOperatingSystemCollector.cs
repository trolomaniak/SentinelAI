using System.Runtime.Versioning;
using Microsoft.Win32;

namespace SentinelAI.Agent;

public sealed record WindowsOperatingSystemMetadata(
    string Name,
    string Version,
    string? DisplayVersion,
    string? InstallationType);

/// <summary>Collects bounded Windows release metadata without WMI or external processes.</summary>
public static class WindowsOperatingSystemCollector
{
    private const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    [SupportedOSPlatform("windows")]
    public static WindowsOperatingSystemMetadata Collect() =>
        Collect(ReadLocalMachineValue, Environment.OSVersion.Version);

    // An absent value returns null; inaccessible metadata remains unknown. This
    // overload allows deterministic tests without reading or changing a registry.
    public static WindowsOperatingSystemMetadata Collect(
        Func<string, string, object?> readValue, Version nativeVersion)
    {
        ArgumentNullException.ThrowIfNull(readValue);
        ArgumentNullException.ThrowIfNull(nativeVersion);

        var productName = ReadText(readValue, "ProductName", 128);
        var installationType = ReadText(readValue, "InstallationType", 32);
        var displayVersion = ReadText(readValue, "DisplayVersion", 32);
        var releaseId = ReadText(readValue, "ReleaseId", 16);
        var updateBuildRevision = Read(readValue, "UBR");

        var name = SelectName(productName, installationType, nativeVersion);
        // ReleaseId is retained as 2009 on newer Windows releases. Only use it
        // for legacy Windows 10 versions before the DisplayVersion convention.
        if (displayVersion is null && name == "Windows 10" && nativeVersion.Build is >= 0 and < 19042 &&
            releaseId is { Length: 4 } && releaseId.All(char.IsAsciiDigit) &&
            int.TryParse(releaseId, out var releaseNumber) && releaseNumber is >= 1507 and <= 2004)
        {
            displayVersion = releaseId;
        }

        var version = nativeVersion.ToString();
        // Registry DWORDs are returned as Int32. Reject other types and values
        // that cannot be represented as a nonnegative System.Version revision.
        if (updateBuildRevision is int revision && revision >= 0 && nativeVersion.Build >= 0)
        {
            version = new Version(nativeVersion.Major, nativeVersion.Minor, nativeVersion.Build, revision)
                .ToString();
        }

        return new WindowsOperatingSystemMetadata(name, version, displayVersion, installationType);
    }

    private static string SelectName(string? productName, string? installationType, Version nativeVersion)
    {
        var isServer = productName?.Contains("Server", StringComparison.OrdinalIgnoreCase) == true ||
                       installationType?.StartsWith("Server", StringComparison.OrdinalIgnoreCase) == true;
        var isClient = string.Equals(installationType, "Client", StringComparison.OrdinalIgnoreCase) ||
                       productName == "Windows 10" || productName == "Windows 11" ||
                       productName?.StartsWith("Windows 10 ", StringComparison.OrdinalIgnoreCase) == true ||
                       productName?.StartsWith("Windows 11 ", StringComparison.OrdinalIgnoreCase) == true;

        if (!isServer && isClient && nativeVersion.Major == 10 && nativeVersion.Build >= 10240)
        {
            // ProductName can still say Windows 10 after a Windows 11 upgrade.
            return nativeVersion.Build >= 22000 ? "Windows 11" : "Windows 10";
        }

        return productName?.StartsWith("Windows", StringComparison.OrdinalIgnoreCase) == true
            ? productName
            : "Windows";
    }

    private static string? ReadText(Func<string, string, object?> readValue, string name, int maximumLength)
    {
        if (Read(readValue, name) is not string text)
        {
            return null;
        }

        text = text.Trim();
        return text.Length is > 0 && text.Length <= maximumLength && !text.Any(char.IsControl)
            ? text
            : null;
    }

    private static object? Read(Func<string, string, object?> readValue, string name)
    {
        try
        {
            return readValue(CurrentVersion, name);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           System.Security.SecurityException or PlatformNotSupportedException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static object? ReadLocalMachineValue(string keyPath, string valueName)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath);
        return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }
}
