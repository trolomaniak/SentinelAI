using System.Text.Json;
using SentinelAI.Licensing;

namespace SentinelAI.Core;

/// <summary>The company's contact details shown when the pilot ends; build-time settings of the Setup bundle.</summary>
public sealed record PilotContact(string Company, string Email, string Phone, string Website);

/// <summary>
/// MVP-3 pilot licensing trust, read from the signed deployment next to Core: <c>pilot-license/trust/&lt;key ID&gt;.pem</c>
/// (public keys only, separate from update and lease keys) and <c>pilot-license/contact.json</c>. A build without them
/// has no pilot licensing. <c>SentinelAI:PilotLicense:Directory</c> exists for tests.
/// </summary>
public sealed class PilotLicenseOptions
{
    public const int MaximumContactLength = 128;
    private PilotLicenseOptions(PilotLicenseVerifier verifier, PilotContact? contact) { Verifier = verifier; Contact = contact; }

    public PilotLicenseVerifier Verifier { get; }
    public PilotContact? Contact { get; }
    public bool Configured => Verifier.Configured;

    public static PilotLicenseOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:PilotLicense");
        if (section.GetChildren().Any(child => !string.Equals(child.Key, "Directory", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Unknown SentinelAI:PilotLicense setting.");
        var directory = section["Directory"] ?? Path.Combine(AppContext.BaseDirectory, "pilot-license");
        if (!Path.IsPathFullyQualified(directory)) throw new InvalidOperationException("The pilot license directory must be an absolute path.");
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        PilotContact? contact = null;
        try
        {
            var trust = Path.Combine(directory, "trust");
            if (Directory.Exists(trust))
            {
                var entries = Directory.GetFileSystemEntries(trust);
                if (entries.Length > 32) throw new InvalidOperationException("At most 32 pilot public keys may be supplied.");
                foreach (var entry in entries)
                {
                    var file = new FileInfo(entry);
                    if (!file.Exists || !string.Equals(file.Extension, ".pem", StringComparison.Ordinal) || file.Length is <= 0 or > 4096)
                        throw new InvalidOperationException("Pilot trust holds only public PEM files of at most 4096 bytes.");
                    keys.Add(Path.GetFileNameWithoutExtension(file.Name), File.ReadAllText(file.FullName));
                }
            }
            var contactPath = Path.Combine(directory, "contact.json");
            if (File.Exists(contactPath)) contact = ParseContact(File.ReadAllBytes(contactPath));
            return new PilotLicenseOptions(new PilotLicenseVerifier(keys), contact);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or JsonException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException("Pilot license trust must be named P-256 public PEM keys and a valid contact file.");
        }
    }

    /// <summary>Exactly company, email, phone and website: strings of at most 128 characters without control characters.</summary>
    public static PilotContact ParseContact(ReadOnlySpan<byte> json)
    {
        if (json.Length is 0 or > 4096) throw new JsonException("Invalid pilot contact.");
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 2 });
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("Invalid pilot contact.");
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Name is not ("company" or "email" or "phone" or "website") || property.Value.ValueKind != JsonValueKind.String ||
                property.Value.GetString() is not { Length: <= MaximumContactLength } value || value.Any(char.IsControl) || !values.TryAdd(property.Name, value))
                throw new JsonException("Invalid pilot contact.");
        }
        if (values.Count != 4 || values["company"].Length == 0) throw new JsonException("Invalid pilot contact.");
        return new(values["company"], values["email"], values["phone"], values["website"]);
    }
}
