using SentinelAI.Licensing;

namespace SentinelAI.Setup.Foundation;

public interface ISetupPilotLicenseClient
{
    Task ApplyAsync(string username, ReadOnlyMemory<char> password, string key, CancellationToken token);
}

/// <summary>
/// MVP-3: the pilot public keys built into this Setup (<c>setup/pilot-license/trust/&lt;key ID&gt;.pem</c> in the
/// hash-verified payload; the same keys Core is deployed with). A build without them asks for no key.
/// </summary>
public sealed class SetupPilotLicense
{
    public const int MaximumKeys = 32;
    public const int MaximumPublicKeyBytes = 4096;
    private readonly PilotLicenseVerifier _verifier;
    private SetupPilotLicense(PilotLicenseVerifier verifier) => _verifier = verifier;

    public static SetupPilotLicense? Load(string workDirectory)
    {
        var trust = Path.Combine(workDirectory, "setup", "pilot-license", "trust");
        if (!Directory.Exists(trust)) return null;
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        var entries = Directory.GetFileSystemEntries(trust);
        if (entries.Length is 0 or > MaximumKeys) throw new InvalidDataException("Invalid pilot license trust.");
        foreach (var entry in entries)
        {
            var file = new FileInfo(entry);
            if (!file.Exists || file.Extension != ".pem" || file.Length is <= 0 or > MaximumPublicKeyBytes)
                throw new InvalidDataException("Invalid pilot license trust.");
            keys.Add(Path.GetFileNameWithoutExtension(file.Name), File.ReadAllText(file.FullName));
        }
        try { return new(new PilotLicenseVerifier(keys)); }
        catch (ArgumentException) { throw new InvalidDataException("Invalid pilot license trust."); }
    }

    /// <summary>A key valid now or starting later is accepted, as in Core; the result carries the signed claims.</summary>
    public PilotLicenseResult Verify(string? key, DateTimeOffset now) => _verifier.Verify(key, now);

    public static bool Accepted(PilotLicenseResult result) => result.Status is PilotLicenseStatus.Valid or PilotLicenseStatus.NotYetValid;

    public static string Normalize(string? key) => key?.Trim(' ', '\t', '\r', '\n') ?? string.Empty;

    /// <summary>Bounded base64url text with two separators: the only text Setup hands to Core.</summary>
    public static bool IsKeyText(string? key) => key is { Length: > 0 and <= PilotLicenseFormat.MaxKeyLength } &&
        key.Count(character => character == '.') == 2 &&
        key.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.');
}
