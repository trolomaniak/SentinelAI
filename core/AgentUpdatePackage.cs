namespace SentinelAI.Core;

/// <summary>
/// MVP-7: this release's signed Agent package, built into the deployment next to Core as
/// <c>agent-update/agent.manifest.json</c> and <c>agent-update/agent.zip</c>, so it is upgraded and rolled back with Core.
/// Enrolled Agents fetch it over their authenticated routes, and each Agent computer's SYSTEM updater verifies the
/// signature before installing it; Core only serves the files. A build without them offers no Agent update.
/// <c>SentinelAI:AgentUpdate:Directory</c> exists for tests.
/// </summary>
public sealed class AgentUpdatePackage
{
    /// <summary>The signed update envelope's own limit.</summary>
    public const int MaximumManifestBytes = 8 * 1024;
    public const string ManifestFileName = "agent.manifest.json";
    public const string PackageFileName = "agent.zip";

    private AgentUpdatePackage(string directory) => Directory = directory;

    public string Directory { get; }

    public static AgentUpdatePackage Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:AgentUpdate");
        if (section.GetChildren().Any(child => !string.Equals(child.Key, "Directory", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Unknown SentinelAI:AgentUpdate setting.");
        var directory = section["Directory"] ?? Path.Combine(AppContext.BaseDirectory, "agent-update");
        if (!Path.IsPathFullyQualified(directory)) throw new InvalidOperationException("The Agent update directory must be an absolute path.");
        return new AgentUpdatePackage(directory);
    }

    /// <summary>The signed manifest bytes, or null when this build has no Agent package.</summary>
    public async Task<byte[]?> ReadManifestAsync(CancellationToken cancellationToken)
    {
        var path = Path.Combine(Directory, ManifestFileName);
        if (!File.Exists(path) || !File.Exists(Path.Combine(Directory, PackageFileName))) return null;
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > MaximumManifestBytes) return null;
        var bytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken);
        return bytes;
    }

    /// <summary>The package path, or null when this build has no Agent package.</summary>
    public string? PackagePath
    {
        get
        {
            var path = Path.Combine(Directory, PackageFileName);
            return File.Exists(path) && File.Exists(Path.Combine(Directory, ManifestFileName)) ? path : null;
        }
    }
}
