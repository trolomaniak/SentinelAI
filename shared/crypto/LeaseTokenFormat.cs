using System.Text.Json;
using SentinelAI.Contracts.Licensing;

namespace SentinelAI.Licensing;

/// <summary>Strict, bounded JWS wire format. This library never accepts or uses a private key.</summary>
public static class LeaseTokenFormat
{
    public const int MaxTokenLength = 16_384;
    public const int MaxEndpointLimit = 1_000_000;
    public const int MaxFeatureCount = 64;
    public const int MaxIdentifierLength = 64;
    public static readonly TimeSpan MaximumLeaseDuration = TimeSpan.FromDays(7);

    internal const int MaxHeaderLength = 1_024;
    internal const int SignatureLength = 64;
    internal const string Algorithm = "ES256";
    internal const string TokenType = "sentinelai-lease-v1";

    public static string CreateSigningInput(LeaseClaims claims, string keyId)
    {
        ArgumentNullException.ThrowIfNull(claims);
        if (!IsIdentifier(keyId)) throw new ArgumentException("A bounded lease key identifier is required.", nameof(keyId));
        var snapshot = claims with { EnabledFeatures = claims.EnabledFeatures?.ToArray()! };
        if (!ValidateClaims(snapshot)) throw new ArgumentException("Lease claims are invalid.", nameof(claims));

        using var header = new MemoryStream();
        using (var writer = new Utf8JsonWriter(header))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", Algorithm);
            writer.WriteString("typ", TokenType);
            writer.WriteString("kid", keyId);
            writer.WriteEndObject();
        }
        using var payload = new MemoryStream();
        using (var writer = new Utf8JsonWriter(payload))
        {
            writer.WriteStartObject();
            writer.WriteString("organization_id", snapshot.OrganizationId);
            writer.WriteString("installation_id", snapshot.InstallationId);
            writer.WriteString("plan", snapshot.Plan);
            writer.WriteNumber("endpoint_limit", snapshot.EndpointLimit);
            writer.WriteStartArray("enabled_features");
            foreach (var feature in snapshot.EnabledFeatures) writer.WriteStringValue(feature);
            writer.WriteEndArray();
            writer.WriteString("issued_at", snapshot.IssuedAt);
            writer.WriteString("full_mode_until", snapshot.FullModeUntil);
            writer.WriteEndObject();
        }
        return Encode(header.ToArray()) + "." + Encode(payload.ToArray());
    }

    public static string Assemble(string signingInput, ReadOnlySpan<byte> signature)
    {
        if (!TryReadSigningInput(signingInput, out _, out var payload) || !TryReadClaims(payload, out _) ||
            signature.Length != SignatureLength)
            throw new ArgumentException("The signing input and fixed-size ES256 signature must be valid.");
        var token = signingInput + "." + Encode(signature);
        if (token.Length > MaxTokenLength) throw new ArgumentException("Lease exceeds the token limit.");
        return token;
    }

    public static bool ValidateClaims(LeaseClaims? claims)
    {
        if (claims is null || claims.OrganizationId == Guid.Empty || claims.InstallationId == Guid.Empty ||
            !IsIdentifier(claims.Plan) || claims.EndpointLimit is < 1 or > MaxEndpointLimit ||
            claims.EnabledFeatures is null || claims.EnabledFeatures.Count > MaxFeatureCount ||
            claims.IssuedAt.Offset != TimeSpan.Zero || claims.FullModeUntil.Offset != TimeSpan.Zero ||
            claims.FullModeUntil <= claims.IssuedAt ||
            claims.FullModeUntil - claims.IssuedAt > MaximumLeaseDuration)
            return false;
        var features = new HashSet<string>(StringComparer.Ordinal);
        foreach (var feature in claims.EnabledFeatures)
            if (!IsIdentifier(feature) || !features.Add(feature)) return false;
        return true;
    }

    internal static bool IsIdentifier(string? value) => value is { Length: > 0 and <= MaxIdentifierLength } &&
        value.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

    internal static bool TryReadSigningInput(string? input, out string? keyId, out byte[] payload)
    {
        keyId = null;
        payload = [];
        if (string.IsNullOrEmpty(input) || input.Length > MaxTokenLength - 87) return false;
        var separator = input.IndexOf('.');
        if (separator < 1 || separator > MaxHeaderLength || input.IndexOf('.', separator + 1) != -1 ||
            !TryDecode(input.AsSpan(0, separator), out var header) ||
            !TryDecode(input.AsSpan(separator + 1), out payload)) return false;
        try
        {
            using var document = JsonDocument.Parse(header, DocumentOptions);
            if (!TryProperties(document.RootElement, ["alg", "typ", "kid"], out var properties) ||
                !TryString(properties["alg"], out var algorithm) || algorithm != Algorithm ||
                !TryString(properties["typ"], out var type) || type != TokenType ||
                !TryString(properties["kid"], out keyId) || !IsIdentifier(keyId)) return false;
            return true;
        }
        catch (JsonException) { return false; }
    }

    internal static bool TryReadClaims(byte[] payload, out LeaseClaims? claims)
    {
        claims = null;
        try
        {
            using var document = JsonDocument.Parse(payload, DocumentOptions);
            if (!TryProperties(document.RootElement,
                ["organization_id", "installation_id", "plan", "endpoint_limit", "enabled_features", "issued_at", "full_mode_until"],
                out var properties) ||
                !TryGuid(properties["organization_id"], out var organization) ||
                !TryGuid(properties["installation_id"], out var installation) ||
                !TryString(properties["plan"], out var plan) ||
                properties["endpoint_limit"].ValueKind != JsonValueKind.Number ||
                !properties["endpoint_limit"].TryGetInt32(out var limit) ||
                !TryDate(properties["issued_at"], out var issuedAt) ||
                !TryDate(properties["full_mode_until"], out var fullModeUntil) ||
                properties["enabled_features"].ValueKind != JsonValueKind.Array ||
                properties["enabled_features"].GetArrayLength() > MaxFeatureCount) return false;
            var features = new List<string>();
            foreach (var item in properties["enabled_features"].EnumerateArray())
            {
                if (!TryString(item, out var feature) || feature is null) return false;
                features.Add(feature);
            }
            var result = new LeaseClaims(organization, installation, plan!, limit, features.AsReadOnly(), issuedAt, fullModeUntil);
            if (!ValidateClaims(result)) return false;
            claims = result;
            return true;
        }
        catch (JsonException) { return false; }
    }

    internal static bool TryDecode(ReadOnlySpan<char> encoded, out byte[] bytes)
    {
        bytes = [];
        if (encoded.Length == 0 || encoded.Length > MaxTokenLength || encoded.Length % 4 == 1) return false;
        foreach (var character in encoded)
            if (character is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) return false;
        var text = encoded.ToString();
        var padded = text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4);
        try
        {
            bytes = Convert.FromBase64String(padded);
            return Encode(bytes) == text;
        }
        catch (FormatException) { return false; }
    }

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 4
    };

    private static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryProperties(JsonElement root, string[] required, out Dictionary<string, JsonElement> properties)
    {
        properties = new(StringComparer.Ordinal);
        if (root.ValueKind != JsonValueKind.Object) return false;
        foreach (var property in root.EnumerateObject())
            if (!required.Contains(property.Name, StringComparer.Ordinal) || !properties.TryAdd(property.Name, property.Value)) return false;
        return properties.Count == required.Length;
    }

    private static bool TryString(JsonElement element, out string? value)
    {
        value = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
        return value is not null;
    }

    private static bool TryGuid(JsonElement element, out Guid value)
    {
        value = Guid.Empty;
        return element.ValueKind == JsonValueKind.String && element.TryGetGuid(out value);
    }

    private static bool TryDate(JsonElement element, out DateTimeOffset value)
    {
        value = default;
        if (!TryString(element, out var text) || text is null || text.Length < 20 || text[10] != 'T' ||
            !(text.EndsWith('Z') || text.EndsWith("+00:00", StringComparison.Ordinal))) return false;
        return element.TryGetDateTimeOffset(out value);
    }
}
