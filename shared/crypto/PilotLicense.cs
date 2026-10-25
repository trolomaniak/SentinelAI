using System.Text.Json;

namespace SentinelAI.Licensing;

/// <summary>
/// MVP-3 pilot license: a free, time-limited key with no endpoint limit and no installation binding, so it can be
/// sent before Setup runs. It grants no cloud permission and never gates the local security baseline.
/// </summary>
public sealed record PilotLicenseClaims(string Customer, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

public enum PilotLicenseStatus { Valid, Expired, NotYetValid, Invalid }

/// <summary>Only a trusted signature returns claims; <see cref="PilotLicenseStatus.Invalid"/> never carries any.</summary>
public sealed record PilotLicenseResult(PilotLicenseStatus Status, PilotLicenseClaims? Claims = null, string? KeyId = null);

/// <summary>
/// Compact JWS like the lease: base64url(header).base64url(payload).base64url(signature), ES256 with a fixed 64-byte
/// P1363 signature. Header: exactly alg ES256, typ sentinelai-pilot-v1 and kid. Payload: exactly version 1, plan
/// "pilot", customer (1–64 characters), issued_at and expires_at (explicit UTC, at most 365 days apart).
/// This library never accepts or uses a private key; the issuer tool signs.
/// </summary>
public static class PilotLicenseFormat
{
    public const int Version = 1;
    public const string Plan = "pilot";
    public const int MaxKeyLength = 1024;
    public const int MaxCustomerLength = 64;
    public static readonly TimeSpan MaximumDuration = TimeSpan.FromDays(365);
    internal const string TokenType = "sentinelai-pilot-v1";

    public static string CreateSigningInput(PilotLicenseClaims claims, string keyId)
    {
        ArgumentNullException.ThrowIfNull(claims);
        if (!LeaseTokenFormat.IsIdentifier(keyId)) throw new ArgumentException("A bounded pilot key identifier is required.", nameof(keyId));
        if (!ValidateClaims(claims)) throw new ArgumentException("Pilot license claims are invalid.", nameof(claims));
        using var header = new MemoryStream();
        using (var writer = new Utf8JsonWriter(header))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", "ES256");
            writer.WriteString("typ", TokenType);
            writer.WriteString("kid", keyId);
            writer.WriteEndObject();
        }
        using var payload = new MemoryStream();
        using (var writer = new Utf8JsonWriter(payload))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", Version);
            writer.WriteString("plan", Plan);
            writer.WriteString("customer", claims.Customer);
            writer.WriteString("issued_at", claims.IssuedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
            writer.WriteString("expires_at", claims.ExpiresAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }
        return LeaseTokenFormat.Encode(header.ToArray()) + "." + LeaseTokenFormat.Encode(payload.ToArray());
    }

    public static string Assemble(string signingInput, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != LeaseTokenFormat.SignatureLength || !TryReadSigningInput(signingInput, out _, out var payload) ||
            !TryReadClaims(payload, out _)) throw new ArgumentException("The signing input and fixed-size ES256 signature must be valid.");
        var key = signingInput + "." + LeaseTokenFormat.Encode(signature);
        if (key.Length > MaxKeyLength) throw new ArgumentException("The pilot key exceeds its length limit.");
        return key;
    }

    /// <summary>Whole seconds in UTC, issued before it expires, at most 365 days, for a bounded printable customer.</summary>
    public static bool ValidateClaims(PilotLicenseClaims? claims) =>
        claims is not null && IsCustomer(claims.Customer) &&
        claims.IssuedAt.Offset == TimeSpan.Zero && claims.ExpiresAt.Offset == TimeSpan.Zero &&
        claims.IssuedAt.Ticks % TimeSpan.TicksPerSecond == 0 && claims.ExpiresAt.Ticks % TimeSpan.TicksPerSecond == 0 &&
        claims.ExpiresAt > claims.IssuedAt && claims.ExpiresAt - claims.IssuedAt <= MaximumDuration;

    /// <summary>The company name: 1–64 characters, no surrounding spaces, no control characters, well-formed Unicode.</summary>
    public static bool IsCustomer(string? value)
    {
        if (value is not { Length: > 0 and <= MaxCustomerLength } || value != value.Trim()) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsControl(character) || char.IsLowSurrogate(character)) return false;
            if (char.IsHighSurrogate(character) && (index + 1 == value.Length || !char.IsLowSurrogate(value[++index]))) return false;
        }
        return true;
    }

    internal static bool TryRead(string key, out string signingInput, out string? keyId, out byte[] payload, out byte[] signature)
    {
        signingInput = string.Empty;
        keyId = null;
        payload = [];
        signature = [];
        if (key.Length is 0 or > MaxKeyLength) return false;
        var separator = key.LastIndexOf('.');
        if (separator < 1) return false;
        signingInput = key[..separator];
        return TryReadSigningInput(signingInput, out keyId, out payload) &&
               LeaseTokenFormat.TryDecode(key.AsSpan(separator + 1), out signature) && signature.Length == LeaseTokenFormat.SignatureLength;
    }

    private static bool TryReadSigningInput(string input, out string? keyId, out byte[] payload)
    {
        keyId = null;
        payload = [];
        var separator = input.IndexOf('.');
        if (separator < 1 || input.IndexOf('.', separator + 1) != -1 ||
            !LeaseTokenFormat.TryDecode(input.AsSpan(0, separator), out var header) ||
            !LeaseTokenFormat.TryDecode(input.AsSpan(separator + 1), out payload)) return false;
        try
        {
            using var document = JsonDocument.Parse(header, LeaseTokenFormat.DocumentOptions);
            return LeaseTokenFormat.TryProperties(document.RootElement, ["alg", "typ", "kid"], out var properties) &&
                   LeaseTokenFormat.TryString(properties["alg"], out var algorithm) && algorithm == "ES256" &&
                   LeaseTokenFormat.TryString(properties["typ"], out var type) && type == TokenType &&
                   LeaseTokenFormat.TryString(properties["kid"], out keyId) && LeaseTokenFormat.IsIdentifier(keyId);
        }
        catch (JsonException) { return false; }
    }

    internal static bool TryReadClaims(byte[] payload, out PilotLicenseClaims? claims)
    {
        claims = null;
        try
        {
            using var document = JsonDocument.Parse(payload, LeaseTokenFormat.DocumentOptions);
            if (!LeaseTokenFormat.TryProperties(document.RootElement, ["version", "plan", "customer", "issued_at", "expires_at"], out var properties) ||
                properties["version"].ValueKind != JsonValueKind.Number || !properties["version"].TryGetInt32(out var version) || version != Version ||
                !LeaseTokenFormat.TryString(properties["plan"], out var plan) || plan != Plan ||
                !LeaseTokenFormat.TryString(properties["customer"], out var customer) ||
                !LeaseTokenFormat.TryDate(properties["issued_at"], out var issuedAt) ||
                !LeaseTokenFormat.TryDate(properties["expires_at"], out var expiresAt)) return false;
            var result = new PilotLicenseClaims(customer!, issuedAt.ToUniversalTime(), expiresAt.ToUniversalTime());
            if (!ValidateClaims(result)) return false;
            claims = result;
            return true;
        }
        catch (JsonException) { return false; }
    }
}

/// <summary>Offline verification against the pilot public keys supplied with the Setup bundle, by key ID.</summary>
public sealed class PilotLicenseVerifier
{
    private readonly Dictionary<string, byte[]> _publicKeys;

    public PilotLicenseVerifier(IReadOnlyDictionary<string, string> publicKeyPems) => _publicKeys = TrustAnchors.Load(publicKeyPems);

    /// <summary>False when the build carries no pilot public key: no pilot key can then be valid.</summary>
    public bool Configured => _publicKeys.Count != 0;

    /// <summary>
    /// Fails closed: malformed text, an unknown key ID, a wrong signature or invalid claims are <see cref="PilotLicenseStatus.Invalid"/>.
    /// Surrounding whitespace from pasting is ignored. <c>now &lt; issued_at</c> is NotYetValid; <c>now &gt;= expires_at</c> is Expired.
    /// </summary>
    public PilotLicenseResult Verify(string? key, DateTimeOffset now)
    {
        var text = key?.Trim(' ', '\t', '\r', '\n');
        if (string.IsNullOrEmpty(text) ||
            !PilotLicenseFormat.TryRead(text, out var signingInput, out var keyId, out var payload, out var signature) ||
            keyId is null || !_publicKeys.TryGetValue(keyId, out var publicKey) ||
            !TrustAnchors.VerifySignature(publicKey, signingInput, signature) ||
            !PilotLicenseFormat.TryReadClaims(payload, out var claims) || claims is null)
            return new(PilotLicenseStatus.Invalid);
        var status = now < claims.IssuedAt ? PilotLicenseStatus.NotYetValid
            : now >= claims.ExpiresAt ? PilotLicenseStatus.Expired : PilotLicenseStatus.Valid;
        return new(status, claims, keyId);
    }
}
