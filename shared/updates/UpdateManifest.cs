namespace SentinelAI.Updates;

/// <summary>All metadata is authenticated; the URL is descriptive and is never fetched by this library.</summary>
public sealed record UpdateManifest(
    string Version,
    string ArtifactId,
    string ArtifactUrl,
    string Sha256,
    long SizeBytes,
    string Channel,
    string Environment);

/// <summary>Only successful signature and policy verification can create this capability.</summary>
public sealed class VerifiedUpdateManifest
{
    internal VerifiedUpdateManifest(UpdateManifest manifest, string keyId)
    {
        Manifest = manifest;
        KeyId = keyId;
    }

    public UpdateManifest Manifest { get; }
    public string KeyId { get; }
}

/// <summary>A generic rejection which never includes manifest contents, paths or secrets.</summary>
public sealed class UpdateValidationException : Exception
{
    public UpdateValidationException() : base("Update validation failed.") { }
}
