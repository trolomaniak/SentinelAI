using SentinelAI.Agent;

internal static class WindowsOperatingSystemTests
{
    private const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    public static void Run()
    {
        VerifyBoundedAndMissingMetadata();
        VerifyClientNamesAndReleases();
        VerifyServerNames();
        VerifyLegacyReleaseFallback();
        VerifyNativeBuildRevision();
        VerifyMalformedAndUnavailableMetadata();
    }

    private static void VerifyBoundedAndMissingMetadata()
    {
        var calls = new HashSet<(string Key, string Name)>();
        var nativeVersion = new Version(10, 0, 26200, 1234);
        var result = WindowsOperatingSystemCollector.Collect((key, name) =>
        {
            Ensure(calls.Add((key, name)), "OS metadata collector repeated a registry probe.");
            return null;
        }, nativeVersion);

        Ensure(result == new WindowsOperatingSystemMetadata("Windows", "10.0.26200.1234", null, null),
            "Absent OS metadata invented a release, installation type, or product name.");
        Ensure(calls.SetEquals(new[] { "ProductName", "DisplayVersion", "ReleaseId", "InstallationType", "UBR" }
                .Select(name => (CurrentVersion, name))),
            "OS metadata collection read outside its bounded registry allowlist.");
    }

    private static void VerifyClientNamesAndReleases()
    {
        var modern = Collect(new Version(10, 0, 26200, 0), new()
        {
            ["ProductName"] = "Windows 10 Pro",
            ["DisplayVersion"] = "26H2",
            ["ReleaseId"] = "2009",
            ["InstallationType"] = "Client",
            ["UBR"] = 0
        });
        Ensure(modern == new WindowsOperatingSystemMetadata("Windows 11", "10.0.26200.0", "26H2", "Client"),
            "Windows 11 did not normalize stale ProductName or preserve its explicit release/build.");

        var windows10 = Collect(new Version(10, 0, 19045, 6000), new()
        {
            ["ProductName"] = "Windows 10 Enterprise",
            ["DisplayVersion"] = "22H2",
            ["InstallationType"] = "Client"
        });
        Ensure(windows10.Name == "Windows 10" && windows10.DisplayVersion == "22H2",
            "Windows 10 client metadata was mislabeled as Windows 11.");

        Ensure(Collect(new Version(10, 0, 22000, 0), new() { ["InstallationType"] = "Client" }).Name == "Windows 11",
            "An explicit Windows 11 client installation was not recognized at its first build.");
        Ensure(Collect(new Version(10, 0, 21999, 0), new() { ["InstallationType"] = "Client" }).Name == "Windows 10",
            "A pre-Windows 11 client build was incorrectly labeled Windows 11.");
        Ensure(Collect(new Version(10, 0, 26200, 0), new() { ["ProductName"] = "Windows 10 Pro" }).Name == "Windows 11",
            "A recognizable client product required an otherwise optional InstallationType.");
        Ensure(Collect(new Version(10, 0, 26200, 0), new()
            { ["ProductName"] = "Windows 10 Pro", ["InstallationType"] = "Client", ["ReleaseId"] = "2009" })
            .DisplayVersion is null,
            "A missing Windows 11 release was replaced with stale ReleaseId 2009.");
    }

    private static void VerifyServerNames()
    {
        foreach (var installationType in new[] { "Server", "Server Core" })
        {
            var server = Collect(new Version(10, 0, 26100, 1234), new()
            {
                ["ProductName"] = "Windows Server 2025 Standard",
                ["DisplayVersion"] = "24H2",
                ["InstallationType"] = installationType
            });
            Ensure(server.Name == "Windows Server 2025 Standard" && server.InstallationType == installationType,
                "A Windows Server build was mislabeled as a Windows desktop client.");
        }

        Ensure(Collect(new Version(10, 0, 26100, 0), new()
            { ["ProductName"] = "Windows Server 2025 Datacenter" }).Name == "Windows Server 2025 Datacenter",
            "A server product without InstallationType was mislabeled Windows 11.");
        Ensure(Collect(new Version(10, 0, 26100, 0), new() { ["InstallationType"] = "Server Core" }).Name == "Windows",
            "A missing server product name was invented from a desktop build threshold.");
        Ensure(Collect(new Version(6, 3, 9600, 0), new()
            { ["ProductName"] = "Windows 8.1 Pro", ["InstallationType"] = "Client" }).Name == "Windows 8.1 Pro",
            "An older Windows product name was overwritten by modern Windows branding.");
    }

    private static void VerifyLegacyReleaseFallback()
    {
        var legacy = Collect(new Version(10, 0, 18363, 0), new()
            { ["ProductName"] = "Windows 10 Pro", ["ReleaseId"] = "1909", ["InstallationType"] = "Client" });
        Ensure(legacy.DisplayVersion == "1909", "A valid legacy Windows 10 ReleaseId was not preserved.");

        foreach (var releaseId in new[] { "2009", "9999", "1909 trailing", "26H2", "1500" })
        {
            Ensure(Collect(new Version(10, 0, 18363, 0), new()
                { ["ProductName"] = "Windows 10 Pro", ["ReleaseId"] = releaseId }).DisplayVersion is null,
                "An invalid or stale ReleaseId became a displayed Windows release.");
        }

        Ensure(Collect(new Version(10, 0, 19045, 0), new()
            { ["ProductName"] = "Windows 10 Pro", ["ReleaseId"] = "1909" }).DisplayVersion is null,
            "A current Windows 10 build displayed a stale legacy release fallback.");
    }

    private static void VerifyNativeBuildRevision()
    {
        var nativeVersion = new Version(10, 0, 26200, 1234);
        Ensure(Collect(nativeVersion, new() { ["UBR"] = 6899 }).Version == "10.0.26200.6899",
            "Windows UBR was not applied to the native operating system build.");
        Ensure(Collect(nativeVersion, new() { ["UBR"] = 0 }).Version == "10.0.26200.0",
            "A valid zero UBR was treated as absent.");
        Ensure(Collect(nativeVersion, new() { ["UBR"] = int.MaxValue }).Version == $"10.0.26200.{int.MaxValue}",
            "A nonnegative DWORD revision within System.Version bounds was rejected.");
        foreach (var invalid in new object[] { -1, uint.MaxValue, 6899L, "6899", true, 1.5 })
        {
            Ensure(Collect(nativeVersion, new() { ["UBR"] = invalid }).Version == nativeVersion.ToString(),
                "An invalid registry UBR changed the native Windows version.");
        }
        Ensure(Collect(new Version(10, 0), new() { ["UBR"] = 1 }).Version == "10.0",
            "Missing native build metadata was invented to apply a registry revision.");
    }

    private static void VerifyMalformedAndUnavailableMetadata()
    {
        var malformed = Collect(new Version(10, 0, 26200, 0), new()
        {
            ["ProductName"] = "not a Windows product",
            ["DisplayVersion"] = "26H2\nInjected",
            ["InstallationType"] = new string('s', 33),
            ["ReleaseId"] = 1909
        });
        Ensure(malformed == new WindowsOperatingSystemMetadata("Windows", "10.0.26200.0", null, null),
            "Malformed OS metadata was returned as reliable product/release information.");

        var trimmed = Collect(new Version(10, 0, 26200, 0), new()
        {
            ["ProductName"] = " Windows 10 Pro ", ["DisplayVersion"] = " 26H2 ", ["InstallationType"] = " Client "
        });
        Ensure(trimmed.Name == "Windows 11" && trimmed.DisplayVersion == "26H2" && trimmed.InstallationType == "Client",
            "Valid OS registry strings were not trimmed.");
        Ensure(Collect(new Version(10, 0, 26200, 0), new()
            { ["ProductName"] = new string('p', 129), ["DisplayVersion"] = new string('v', 33) })
            .DisplayVersion is null,
            "OS registry string length limits were not enforced.");

        foreach (var unavailable in new Exception[]
        {
            new IOException(), new UnauthorizedAccessException(), new System.Security.SecurityException(),
            new PlatformNotSupportedException()
        })
        {
            var result = WindowsOperatingSystemCollector.Collect((_, _) => throw unavailable,
                new Version(10, 0, 26200, 1234));
            Ensure(result == new WindowsOperatingSystemMetadata("Windows", "10.0.26200.1234", null, null),
                "Unavailable registry metadata failed collection or invented operating system details.");
        }

        var partial = WindowsOperatingSystemCollector.Collect((_, name) => name switch
        {
            "ProductName" => "Windows 10 Pro",
            "InstallationType" => "Client",
            "DisplayVersion" => throw new UnauthorizedAccessException(),
            "UBR" => 1234,
            _ => null
        }, new Version(10, 0, 26200, 0));
        Ensure(partial.Name == "Windows 11" && partial.Version == "10.0.26200.1234" && partial.DisplayVersion is null,
            "One inaccessible value prevented collecting other available Windows metadata.");
    }

    private static WindowsOperatingSystemMetadata Collect(Version nativeVersion, Dictionary<string, object> metadata) =>
        WindowsOperatingSystemCollector.Collect((key, name) =>
        {
            Ensure(key == CurrentVersion, "OS metadata collector read an unexpected registry key.");
            return metadata.GetValueOrDefault(name);
        }, nativeVersion);

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }
}
