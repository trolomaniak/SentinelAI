using System.Globalization;
using System.Text.Json;

namespace SentinelAI.Updates;

/// <summary>Exact, bounded JSON and an ES256 signing domain distinct from licensing tokens.</summary>
public static class UpdateManifestFormat
{
    public const string Format = "sentinelai-update-v1";
    public const int MaximumDocumentBytes = 8_192;
    public const long MaximumArtifactBytes = 512L * 1024 * 1024;
    internal const int SignatureBytes = 64;

    /// <summary>Canonical UTF-8 JSON covering format, key ID and every manifest field.</summary>
    public static byte[] CreateSigningData(UpdateManifest manifest, string keyId)
    {
        ValidateForWriting(manifest, keyId);
        return Write(manifest, keyId, null);
    }

    /// <summary>Assembles an externally created P-256/SHA-256 P1363 signature; never imports a private key.</summary>
    public static byte[] SerializeSigned(UpdateManifest manifest, string keyId, ReadOnlySpan<byte> signature)
    {
        ValidateForWriting(manifest, keyId);
        if (signature.Length != SignatureBytes) throw new ArgumentException("A fixed-size ES256 signature is required.", nameof(signature));
        return Write(manifest, keyId, Encode(signature));
    }

    internal static bool TryRead(ReadOnlySpan<byte> document, out UpdateManifest? manifest, out string? keyId, out byte[] signature)
    {
        manifest = null;
        keyId = null;
        signature = [];
        if (document.Length is < 1 or > MaximumDocumentBytes) return false;
        try
        {
            using var json = JsonDocument.Parse(document.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 3
            });
            if (!TryProperties(json.RootElement, ["format", "keyId", "manifest", "signature"], out var envelope) ||
                !TryString(envelope["format"], out var format) || format != Format ||
                !TryString(envelope["keyId"], out keyId) || !IsIdentifier(keyId) ||
                !TryString(envelope["signature"], out var encodedSignature) || encodedSignature is null ||
                !TryDecodeSignature(encodedSignature, out signature) ||
                !TryProperties(envelope["manifest"], ["version", "artifactId", "artifactUrl", "sha256", "sizeBytes", "channel", "environment"], out var fields) ||
                !TryString(fields["version"], out var version) ||
                !TryString(fields["artifactId"], out var artifactId) ||
                !TryString(fields["artifactUrl"], out var url) ||
                !TryString(fields["sha256"], out var sha256) ||
                fields["sizeBytes"].ValueKind != JsonValueKind.Number || !fields["sizeBytes"].TryGetInt64(out var sizeBytes) ||
                !TryString(fields["channel"], out var channel) ||
                !TryString(fields["environment"], out var environment)) return false;
            var candidate = new UpdateManifest(version!, artifactId!, url!, sha256!, sizeBytes, channel!, environment!);
            if (!ValidateManifest(candidate)) return false;
            manifest = candidate;
            return true;
        }
        // JsonDocument defers some string/property-name decoding: unpaired surrogate escapes
        // can therefore throw here rather than at Parse. They are malformed input as well.
        catch (Exception exception) when (exception is JsonException or InvalidOperationException) { return false; }
    }

    internal static bool ValidateManifest(UpdateManifest? manifest) => manifest is not null &&
        TryVersion(manifest.Version, out _) && IsIdentifier(manifest.ArtifactId) &&
        IsArtifactUrl(manifest.ArtifactUrl) && IsHash(manifest.Sha256) &&
        manifest.SizeBytes is > 0 and <= MaximumArtifactBytes && IsChannel(manifest.Channel) && IsEnvironment(manifest.Environment);

    internal static bool IsIdentifier(string? value) => value is { Length: > 0 and <= 64 } &&
        value.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

    internal static bool IsChannel(string? channel) => channel is "stable" or "pilot" or "beta";
    internal static bool IsEnvironment(string? environment) => environment is "development" or "production";

    internal static bool TryVersion(string? text, out Version version)
    {
        version = new Version(0, 0, 0);
        if (text is not { Length: >= 5 and <= 17 }) return false;
        var parts = text.Split('.');
        if (parts.Length != 3) return false;
        var numbers = new int[3];
        for (var index = 0; index < parts.Length; index++)
        {
            var part = parts[index];
            if (part.Length is < 1 or > 5 || part.Length > 1 && part[0] == '0' ||
                !part.All(character => character is >= '0' and <= '9') ||
                !int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out numbers[index]) || numbers[index] > 65_535)
                return false;
        }
        version = new Version(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    private static bool IsHash(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsArtifactUrl(string? value) => value is { Length: > 0 and <= 2_048 } &&
        !value.Any(character => char.IsControl(character) || char.IsWhiteSpace(character)) &&
        !value.Contains('?') && !value.Contains('#') &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length > 0 && uri.UserInfo.Length == 0;

    private static void ValidateForWriting(UpdateManifest manifest, string keyId)
    {
        if (!ValidateManifest(manifest) || !IsIdentifier(keyId))
            throw new ArgumentException("Valid bounded update metadata and a key identifier are required.");
    }

    private static byte[] Write(UpdateManifest manifest, string keyId, string? signature)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("format", Format);
            writer.WriteString("keyId", keyId);
            writer.WriteStartObject("manifest");
            writer.WriteString("version", manifest.Version);
            writer.WriteString("artifactId", manifest.ArtifactId);
            writer.WriteString("artifactUrl", manifest.ArtifactUrl);
            writer.WriteString("sha256", manifest.Sha256);
            writer.WriteNumber("sizeBytes", manifest.SizeBytes);
            writer.WriteString("channel", manifest.Channel);
            writer.WriteString("environment", manifest.Environment);
            writer.WriteEndObject();
            if (signature is not null) writer.WriteString("signature", signature);
            writer.WriteEndObject();
        }
        var bytes = stream.ToArray();
        if (bytes.Length > MaximumDocumentBytes) throw new ArgumentException("Update manifest exceeds the size limit.");
        return bytes;
    }

    private static bool TryProperties(JsonElement root, string[] required, out Dictionary<string, JsonElement> properties)
    {
        properties = new(StringComparer.Ordinal);
        if (root.ValueKind != JsonValueKind.Object) return false;
        foreach (var property in root.EnumerateObject())
            if (!required.Contains(property.Name, StringComparer.Ordinal) || !properties.TryAdd(property.Name, property.Value)) return false;
        return properties.Count == required.Length;
    }

    private static bool TryString(JsonElement value, out string? text)
    {
        text = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        return text is not null;
    }

    private static bool TryDecodeSignature(string encoded, out byte[] signature)
    {
        signature = [];
        if (encoded.Length != 86 || !encoded.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) return false;
        try
        {
            signature = Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + "==");
            return signature.Length == SignatureBytes && Encode(signature) == encoded;
        }
        catch (FormatException) { return false; }
    }

    private static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
