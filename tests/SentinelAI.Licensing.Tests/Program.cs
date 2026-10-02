using System.Security.Cryptography;
using System.Text;
using SentinelAI.Contracts.Licensing;
using SentinelAI.Licensing;

var assertions = 0;
var now = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
var organizationId = Guid.Parse("11111111-1111-1111-1111-111111111111");
var installationId = Guid.Parse("22222222-2222-2222-2222-222222222222");
var claims = new LeaseClaims(organizationId, installationId, "BUSINESS", 25, ["cloud_ai", "pdf_reports", "api"], now, now.AddDays(7));
using var firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var publicKeys = new Dictionary<string, string> { ["dev-key-1"] = firstKey.ExportSubjectPublicKeyInfoPem() };
var verifier = new LeaseTokenVerifier(publicKeys);
var signingInput = LeaseTokenFormat.CreateSigningInput(claims, "dev-key-1");
var validToken = Sign(signingInput, firstKey);
var valid = Verify(validToken);
Ensure(valid.Status == LeaseVerificationStatus.Valid && valid.KeyId == "dev-key-1" &&
       valid.Claims is { Plan: "BUSINESS", EndpointLimit: 25 } && valid.Claims.EnabledFeatures.SequenceEqual(claims.EnabledFeatures) &&
       valid.Claims.OrganizationId == organizationId && valid.Claims.InstallationId == installationId &&
       valid.Claims.IssuedAt == now && valid.Claims.FullModeUntil == now.AddDays(7),
    "Generated development keys verify all lease claims locally.");
Ensure(validToken.Length < LeaseTokenFormat.MaxTokenLength && validToken.Split('.').Length == 3 &&
       validToken.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'),
    "Wire token is compact, bounded unpadded base64url.");
Ensure(Verify(validToken, at: now.AddDays(7).AddTicks(-1)).Status == LeaseVerificationStatus.Valid,
    "The lease is valid immediately before its full-mode expiration.");
var expired = Verify(validToken, at: now.AddDays(7));
Ensure(expired.Status == LeaseVerificationStatus.Expired && expired.Claims is not null && expired.KeyId == "dev-key-1",
    "The exact expiration boundary is expired but authenticated claims remain available.");
Ensure(Verify(validToken, at: now.AddDays(10)).Status == LeaseVerificationStatus.Expired,
    "Offline verification detects a past expiration without calling an external service.");
var future = Verify(validToken, at: now.AddTicks(-1));
Ensure(future.Status == LeaseVerificationStatus.NotYetValid && future.Claims is null,
    "Future issuance is rejected with no usable claims and no clock-skew grace.");
Ensure(Verify(validToken, organization: Guid.NewGuid()) is { Status: LeaseVerificationStatus.IdentityMismatch, Claims: null } &&
       Verify(validToken, installation: Guid.NewGuid()) is { Status: LeaseVerificationStatus.IdentityMismatch, Claims: null },
    "Trusted claims cannot be replayed into another organization or installation.");
Ensure(Verify(validToken, organization: Guid.Empty).Status == LeaseVerificationStatus.Invalid &&
       Verify(validToken, installation: Guid.Empty).Status == LeaseVerificationStatus.Invalid,
    "An absent expected identity cannot disable the identity binding.");
Ensure(Verify(validToken, at: now.ToOffset(TimeSpan.FromHours(2))).Status == LeaseVerificationStatus.Valid,
    "Evaluation time compares absolute instants even when the caller supplies a local offset.");

// Snapshot public configuration and support an explicit overlap period for rotation.
publicKeys["dev-key-1"] = secondKey.ExportSubjectPublicKeyInfoPem();
publicKeys.Clear();
Ensure(Verify(validToken).Status == LeaseVerificationStatus.Valid,
    "Later dictionary mutations cannot change the verifier's trusted-key snapshot.");
var overlap = new LeaseTokenVerifier(new Dictionary<string, string>
{
    ["dev-key-1"] = firstKey.ExportSubjectPublicKeyInfoPem(),
    ["dev-key-2"] = secondKey.ExportSubjectPublicKeyInfoPem()
});
var rotatedToken = Sign(LeaseTokenFormat.CreateSigningInput(claims, "dev-key-2"), secondKey);
Ensure(overlap.Verify(validToken, organizationId, installationId, now).Status == LeaseVerificationStatus.Valid &&
       overlap.Verify(rotatedToken, organizationId, installationId, now).Status == LeaseVerificationStatus.Valid,
    "Two explicitly trusted public keys verify during a rotation overlap.");
Ensure(Verify(rotatedToken).Status == LeaseVerificationStatus.Invalid &&
       new LeaseTokenVerifier(new Dictionary<string, string>()).Verify(validToken, organizationId, installationId, now).Status == LeaseVerificationStatus.Invalid,
    "Unknown signing keys and an empty trust set fail closed.");
Ensure(new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = secondKey.ExportSubjectPublicKeyInfoPem() })
        .Verify(validToken, organizationId, installationId, now) is { Status: LeaseVerificationStatus.Invalid, Claims: null, KeyId: null },
    "A matching key identifier does not compensate for a different public key.");

var parts = validToken.Split('.');
var headerJson = Decode(parts[0]);
var payloadJson = Decode(parts[1]);
Ensure(Verify(parts[0] + "." + Encode(payloadJson.Replace("BUSINESS", "ENTERPRISE")) + "." + parts[2]) is
       { Status: LeaseVerificationStatus.Invalid, Claims: null }, "Modified entitlements fail signature verification.");
Ensure(Verify(Encode(headerJson.Replace("dev-key-1", "dev-key-2")) + "." + parts[1] + "." + parts[2]).Status == LeaseVerificationStatus.Invalid,
    "Modified protected key identifiers fail verification.");
var corruptSignature = Convert.FromBase64String(Pad(parts[2]));
corruptSignature[0] ^= 1;
Ensure(Verify(parts[0] + "." + parts[1] + "." + EncodeBytes(corruptSignature)).Status == LeaseVerificationStatus.Invalid,
    "A changed signature is invalid.");
var derSignature = firstKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256,
    DSASignatureFormat.Rfc3279DerSequence);
Ensure(Verify(signingInput + "." + EncodeBytes(derSignature)).Status == LeaseVerificationStatus.Invalid,
    "DER signatures cannot be confused with the fixed 64-byte P1363 wire signature.");

var malformedHeaders = new[]
{
    headerJson.Replace("ES256", "none"),
    headerJson.Replace("ES256", "HS256"),
    headerJson.Replace("sentinelai-lease-v1", "JWT"),
    headerJson.Replace("\"kid\":\"dev-key-1\"", "\"kid\":\"missing-key\""),
    headerJson.Replace("\"alg\":\"ES256\"", "\"alg\":\"ES256\",\"alg\":\"ES256\""),
    headerJson.Replace("\"alg\":\"ES256\"", "\"alg\":\"ES256\",\"\\u0061lg\":\"ES256\""),
    headerJson[..^1] + ",\"jku\":\"https://example.invalid/key\"}",
    headerJson[..^1] + ",\"crit\":[\"custom\"]}",
    "{\"alg\":\"ES256\",\"kid\":\"dev-key-1\"}",
    "{\"alg\":\"ES256\",\"typ\":\"sentinelai-lease-v1\",\"kid\":null}",
    headerJson[..^1] + ",}",
    "[" + headerJson + "]"
};
foreach (var header in malformedHeaders)
    Ensure(Verify(SignRaw(header, payloadJson)).Status == LeaseVerificationStatus.Invalid,
        "Unsupported, unknown, duplicated, escaped-duplicate or malformed protected headers fail even when signed.");

var invalidPayloads = new[]
{
    payloadJson.Replace("\"endpoint_limit\":25", "\"endpoint_limit\":25,\"endpoint_limit\":25"),
    payloadJson[..^1] + ",\"unrecognized_entitlement\":true}",
    payloadJson.Replace("\"endpoint_limit\":25", "\"endpoint_limit\":0"),
    payloadJson.Replace("\"endpoint_limit\":25", "\"endpoint_limit\":1000001"),
    payloadJson.Replace("\"endpoint_limit\":25", "\"endpoint_limit\":25.0"),
    payloadJson.Replace("\"endpoint_limit\":25", "\"endpoint_limit\":\"25\""),
    payloadJson.Replace(organizationId.ToString(), Guid.Empty.ToString()),
    payloadJson.Replace(installationId.ToString(), "not-a-guid"),
    payloadJson.Replace("BUSINESS", "BUSINESS plan"),
    payloadJson.Replace("\"cloud_ai\",\"pdf_reports\",\"api\"", "\"cloud_ai\",\"cloud_ai\""),
    payloadJson.Replace("\"cloud_ai\",\"pdf_reports\",\"api\"", "null"),
    payloadJson.Replace("2026-10-09", "2026-10-10"),
    payloadJson.Replace("2026-10-09", "2026-10-02"),
    payloadJson.Replace("2026-10-09", "2026-10-01"),
    payloadJson.Replace("+00:00", "+01:00"),
    payloadJson.Replace("+00:00", ""),
    payloadJson.Replace("\"issued_at\":", "\"ISSUED_AT\":"),
    payloadJson[..^1] + ",}",
    "null"
};
foreach (var payload in invalidPayloads)
    Ensure(Verify(SignRaw(headerJson, payload)) is { Status: LeaseVerificationStatus.Invalid, Claims: null },
        "Signed malformed or semantically invalid claims cannot create usable entitlements.");

var invalidTokens = new string?[]
{
    null, "", " ", new('a', LeaseTokenFormat.MaxTokenLength + 1), validToken + ".extra", "." + validToken,
    parts[0] + "." + parts[1], parts[0] + "." + parts[1] + ".", validToken + "=", validToken + "\n",
    parts[0] + "=." + parts[1] + "." + parts[2],
    parts[0] + "." + parts[1] + "=." + parts[2],
    parts[0] + "." + parts[1] + ".!", "é." + parts[1] + "." + parts[2],
    new string('a', 1_025) + "." + parts[1] + "." + parts[2]
};
foreach (var token in invalidTokens)
    Ensure(Verify(token) is { Status: LeaseVerificationStatus.Invalid, Claims: null, KeyId: null },
        "Malformed, unbounded, non-base64url and unpadded-format violations fail closed.");
// The final signature character has only two meaningful bits; nonzero discarded bits are forbidden.
var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var alternateLast = alphabet[alphabet.IndexOf(parts[2][^1]) + 1];
Ensure(Verify(signingInput + "." + parts[2][..^1] + alternateLast).Status == LeaseVerificationStatus.Invalid,
    "Noncanonical base64url encodings of otherwise identical signature bytes are rejected.");
var signatureBytes = Convert.FromBase64String(Pad(parts[2]));
Ensure(Verify(signingInput + "." + EncodeBytes(signatureBytes[..63])).Status == LeaseVerificationStatus.Invalid &&
       Verify(signingInput + "." + EncodeBytes([.. signatureBytes, 0])).Status == LeaseVerificationStatus.Invalid,
    "A signature must have exactly 64 bytes.");

Ensure(LeaseTokenFormat.ValidateClaims(claims with { EnabledFeatures = [] }) &&
       LeaseTokenFormat.ValidateClaims(claims with { EndpointLimit = LeaseTokenFormat.MaxEndpointLimit }),
    "A plan may enable no optional features and accepts the explicit upper endpoint boundary.");
Ensure(!LeaseTokenFormat.ValidateClaims(claims with { EnabledFeatures = Enumerable.Range(0, 65).Select(index => "feature" + index).ToArray() }) &&
       !LeaseTokenFormat.ValidateClaims(claims with { Plan = new string('a', 65) }) &&
       !LeaseTokenFormat.ValidateClaims(claims with { EnabledFeatures = ["non_ascii_é"] }),
    "Feature counts and identifiers are strictly bounded ASCII values.");
Throws<ArgumentException>(() => LeaseTokenFormat.CreateSigningInput(claims with { OrganizationId = Guid.Empty }, "dev-key-1"),
    "Signing input construction rejects invalid claims before the server signs.");
Throws<ArgumentException>(() => LeaseTokenFormat.CreateSigningInput(claims, "not a key"),
    "Key identifiers cannot include spaces or control characters.");
Throws<ArgumentException>(() => LeaseTokenFormat.Assemble(signingInput, new byte[63]),
    "Assembly rejects a short signature.");
Throws<ArgumentException>(() => LeaseTokenFormat.Assemble(Encode(headerJson) + "." + Encode(invalidPayloads[0]), new byte[64]),
    "Assembly rejects duplicate claims, rather than normalizing them silently.");
Ensure(new SignedLease(validToken).ToString() == nameof(SignedLease) &&
       new VerifyLeaseRequest(validToken).ToString() == nameof(VerifyLeaseRequest),
    "Logging bearer-token DTOs through ToString does not disclose a signed lease.");
Ensure(valid.Claims!.EnabledFeatures is not string[], "Verified features are returned as a read-only collection.");
Throws<NotSupportedException>(() => ((IList<string>)valid.Claims!.EnabledFeatures)[0] = "unexpected",
    "A caller cannot modify verified feature claims in place.");

Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = firstKey.ExportPkcs8PrivateKeyPem() }),
    "PKCS8 private material is rejected by the public verification configuration.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = firstKey.ExportECPrivateKeyPem() }),
    "EC private material is rejected by the public verification configuration.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = firstKey.ExportSubjectPublicKeyInfoPem() + firstKey.ExportPkcs8PrivateKeyPem() }),
    "Appending private material to a public PEM is rejected.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = firstKey.ExportSubjectPublicKeyInfoPem() + secondKey.ExportSubjectPublicKeyInfoPem() }),
    "Ambiguous multiple public PEM blocks are rejected.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = "not a PEM" }),
    "Malformed verification keys fail configuration validation.");
using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = p384.ExportSubjectPublicKeyInfoPem() }),
    "A different elliptic curve cannot be used under ES256.");
using var rsa = RSA.Create(2048);
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-key-1"] = rsa.ExportSubjectPublicKeyInfoPem() }),
    "RSA public keys cannot be confused with the ECDSA algorithm.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(Enumerable.Range(0, 33).ToDictionary(index => "key" + index, _ => firstKey.ExportSubjectPublicKeyInfoPem())),
    "An unbounded verification key ring is rejected.");
Throws<ArgumentException>(() => new LeaseTokenVerifier(new Dictionary<string, string> { ["invalid id"] = firstKey.ExportSubjectPublicKeyInfoPem() }),
    "Verification key identifiers use the same bounded contract as protected headers.");

Parallel.For(0, 32, _ =>
{
    if (Verify(validToken).Status != LeaseVerificationStatus.Valid) throw new InvalidOperationException("Concurrent verification failed.");
});
Ensure(true, "Parallel reads create independent public verification instances and remain valid.");
Console.WriteLine($"Licensing crypto tests passed ({assertions} assertions, generated development keys only).");

LeaseVerificationResult Verify(string? token, Guid? organization = null, Guid? installation = null, DateTimeOffset? at = null) =>
    verifier.Verify(token, organization ?? organizationId, installation ?? installationId, at ?? now);
string Sign(string input, ECDsa key) => LeaseTokenFormat.Assemble(input,
    key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
string SignRaw(string header, string payload)
{
    var input = Encode(header) + "." + Encode(payload);
    // Raw test signing deliberately bypasses construction so parser tests cannot mirror the implementation.
    return input + "." + EncodeBytes(firstKey.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
}
static string Encode(string value) => EncodeBytes(Encoding.UTF8.GetBytes(value));
static string EncodeBytes(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static string Pad(string value) => value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);
static string Decode(string value) => Encoding.UTF8.GetString(Convert.FromBase64String(Pad(value)));
void Ensure(bool condition, string message)
{
    assertions++;
    if (!condition) throw new InvalidOperationException(message);
}
void Throws<TException>(Action action, string message) where TException : Exception
{
    assertions++;
    try { action(); }
    catch (TException) { return; }
    throw new InvalidOperationException(message);
}
