using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace SentinelAI.Updates.Tests;

public static class ManifestTests
{
    private static int _assertions;
    private const string KeyId = "dev-update-1";
    private const string ArtifactId = "sentinelai-agent-win-x64";

    public static async Task RunAsync()
    {
        _assertions = 0;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var package = Enumerable.Range(0, 131_173).Select(index => (byte)(index % 251)).ToArray();
        var manifest = new UpdateManifest("1.2.3", ArtifactId, "https://updates.example.invalid/agent-1.2.3.zip",
            Convert.ToHexStringLower(SHA256.HashData(package)), package.LongLength, "stable", "development");
        var keys = new Dictionary<string, string> { [KeyId] = key.ExportSubjectPublicKeyInfoPem() };
        var policy = Policy(keys);
        var signed = Sign(manifest, key);
        var verified = UpdateManifestVerifier.Verify(signed, policy);
        Check(verified.Manifest == manifest && verified.KeyId == KeyId, "The signed test manifest verifies every claim locally.");
        Check(signed.Length < UpdateManifestFormat.MaximumDocumentBytes, "The signed manifest is bounded.");
        var reordered = JsonNode.Parse(signed)!.AsObject();
        var reorderedEnvelope = new JsonObject
        {
            ["signature"] = reordered["signature"]!.DeepClone(),
            ["manifest"] = reordered["manifest"]!.DeepClone(),
            ["keyId"] = reordered["keyId"]!.DeepClone(),
            ["format"] = reordered["format"]!.DeepClone()
        };
        Check(UpdateManifestVerifier.Verify(Encoding.UTF8.GetBytes(reorderedEnvelope.ToJsonString()), policy).Manifest == manifest,
            "JSON ordering and whitespace do not alter the canonical authenticated claims.");
        Check(Encoding.UTF8.GetString(UpdateManifestFormat.CreateSigningData(manifest, KeyId)).Contains("\"format\":\"sentinelai-update-v1\"", StringComparison.Ordinal),
            "Signing is domain-separated from licensing tokens.");

        // The trust set is a snapshot, never an alias to caller configuration.
        keys[KeyId] = secondKey.ExportSubjectPublicKeyInfoPem();
        keys.Clear();
        Check(UpdateManifestVerifier.Verify(signed, policy).Manifest == manifest, "Later dictionary mutations cannot replace trust anchors.");
        Reject(signed, Policy(new Dictionary<string, string> { [KeyId] = secondKey.ExportSubjectPublicKeyInfoPem() }));
        Reject(Sign(manifest, key, "unknown-update-key"), policy);
        var overlap = new Dictionary<string, string>
        {
            [KeyId] = key.ExportSubjectPublicKeyInfoPem(),
            ["dev-update-2"] = secondKey.ExportSubjectPublicKeyInfoPem()
        };
        Check(UpdateManifestVerifier.Verify(Sign(manifest, secondKey, "dev-update-2"), Policy(overlap)).KeyId == "dev-update-2",
            "Explicit overlapping public anchors support rotation.");

        // Every signed metadata field, including the key ID and URL, changes the signature domain.
        var altered = new[]
        {
            manifest with { Version = "1.2.4" }, manifest with { ArtifactId = "sentinelai-core-win-x64" },
            manifest with { ArtifactUrl = "https://updates.example.invalid/other.zip" },
            manifest with { Sha256 = new string('a', 64) }, manifest with { SizeBytes = manifest.SizeBytes + 1 },
            manifest with { Channel = "pilot" }, manifest with { Environment = "production" }
        };
        var originalSignature = key.SignData(UpdateManifestFormat.CreateSigningData(manifest, KeyId), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        foreach (var changed in altered)
        {
            var changedPolicy = Policy(new Dictionary<string, string> { [KeyId] = key.ExportSubjectPublicKeyInfoPem() },
                changed.Environment, changed.Channel, changed.ArtifactId);
            Reject(UpdateManifestFormat.SerializeSigned(changed, KeyId, originalSignature), changedPolicy);
        }
        var corrupted = originalSignature.ToArray();
        corrupted[0] ^= 1;
        Reject(UpdateManifestFormat.SerializeSigned(manifest, KeyId, corrupted), policy);
        Reject(UpdateManifestFormat.SerializeSigned(manifest, "dev-update-2", originalSignature), Policy(overlap));
        Reject(Modify(signed, body => body["signature"] = Base64Url(key.SignData(UpdateManifestFormat.CreateSigningData(manifest, KeyId),
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))), policy);

        // An accidentally configured development public key cannot make a development envelope production-valid.
        var trusted = new Dictionary<string, string> { [KeyId] = key.ExportSubjectPublicKeyInfoPem() };
        Reject(signed, Policy(trusted, environment: "production"));
        Reject(Sign(manifest with { Environment = "production" }, key), policy);
        foreach (var channel in new[] { "pilot", "beta" })
        {
            var channelManifest = manifest with { Channel = channel };
            Reject(Sign(channelManifest, key), policy);
            Check(UpdateManifestVerifier.Verify(Sign(channelManifest, key), Policy(trusted, channel: channel)).Manifest.Channel == channel,
                "Each prerelease channel requires explicit opt-in.");
        }
        Reject(Sign(manifest with { ArtifactId = "sentinelai-core-win-x64" }, key), policy);
        foreach (var staleVersion in new[] { "1.0.0", "1.2.2", "1.2.3", "0.65535.65535" })
            Reject(Sign(manifest with { Version = staleVersion }, key), Policy(trusted, installedVersion: "1.2.3"));
        Check(UpdateManifestVerifier.Verify(Sign(manifest with { Version = "1.10.0" }, key), Policy(trusted, installedVersion: "1.9.9")).Manifest.Version == "1.10.0",
            "Version ordering is numeric, never lexicographic.");

        ValidateMalformed(signed, policy);
        ValidateInvalidMetadata(manifest);
        ValidateKeys(key, trusted);
        await ValidateArtifactAsync(package, verified, manifest, key, policy);
        Console.WriteLine($"Update manifest/hash tests passed ({_assertions} assertions).");
    }

    private static void ValidateMalformed(byte[] signed, UpdateVerificationPolicy policy)
    {
        var text = Encoding.UTF8.GetString(signed);
        var malformed = new[]
        {
            "", "null", "[]", "{}", "[" + text + "]", text[..^1] + ",}", "/*comment*/" + text,
            text[..^1] + ",\"algorithm\":\"none\"}", text[..^1] + ",\"keyUrl\":\"https://example.invalid/key\"}",
            text.Replace("\"format\":", "\"format\":\"sentinelai-update-v1\",\"format\":", StringComparison.Ordinal),
            text.Replace("\"keyId\":", "\"keyId\":\"dev-update-1\",\"\\u006beyId\":", StringComparison.Ordinal),
            text.Replace("\"version\":", "\"version\":\"1.2.3\",\"version\":", StringComparison.Ordinal),
            text.Replace("\"version\":", "\"version\":\"1.2.3\",\"\\u0076ersion\":", StringComparison.Ordinal),
            text.Replace("\"version\":", "\"extra\":true,\"version\":", StringComparison.Ordinal),
            new string(' ', UpdateManifestFormat.MaximumDocumentBytes + 1)
        };
        foreach (var input in malformed) Reject(Encoding.UTF8.GetBytes(input), policy);
        Reject([0xff, 0xfe, 0xfd], policy);
        foreach (var surrogate in new[] { "\\uD800", "\\uDC00" })
        {
            Reject(Encoding.UTF8.GetBytes(text.Replace("\"format\":\"sentinelai-update-v1\"", "\"format\":\"" + surrogate + "\"", StringComparison.Ordinal)), policy);
            Reject(Encoding.UTF8.GetBytes(text.Replace("\"format\":", "\"" + surrogate + "\":", StringComparison.Ordinal)), policy);
            Reject(Encoding.UTF8.GetBytes(text.Replace("\"version\":\"1.2.3\"", "\"version\":\"" + surrogate + "\"", StringComparison.Ordinal)), policy);
            Reject(Encoding.UTF8.GetBytes(text.Replace("\"version\":", "\"" + surrogate + "\":", StringComparison.Ordinal)), policy);
        }
        var invalidUtf8 = Encoding.UTF8.GetBytes(text);
        invalidUtf8[Array.IndexOf(invalidUtf8, (byte)'s')] = 0xff;
        Reject(invalidUtf8, policy);
        foreach (var property in new[] { "format", "keyId", "manifest", "signature" })
        {
            Reject(Modify(signed, root => root.Remove(property)), policy);
            Reject(Modify(signed, root => root[property] = null), policy);
            Reject(Modify(signed, root => root[property] = 7), policy);
        }
        foreach (var property in new[] { "version", "artifactId", "artifactUrl", "sha256", "sizeBytes", "channel", "environment" })
        {
            Reject(Modify(signed, root => root["manifest"]!.AsObject().Remove(property)), policy);
            Reject(Modify(signed, root => root["manifest"]![property] = null), policy);
            Reject(Modify(signed, root => root["manifest"]![property] = property == "sizeBytes" ? "123" : JsonValue.Create(123)), policy);
        }
        foreach (var signature in new[] { "", "none", new string('a', 85), new string('a', 87), new string('a', 85) + "+", new string('a', 86) + "==" })
            Reject(Modify(signed, root => root["signature"] = signature), policy);
        // Base64url's unused trailing bits must be zero, even if they decode to the original signature bytes.
        Reject(Modify(signed, root =>
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            var signature = root["signature"]!.GetValue<string>();
            var last = alphabet.IndexOf(signature[^1]);
            root["signature"] = signature[..^1] + alphabet[last | 1];
        }), policy);
        foreach (var size in new JsonNode?[] { JsonValue.Create(0L), JsonValue.Create(-1L), JsonValue.Create(UpdateManifestFormat.MaximumArtifactBytes + 1), JsonValue.Create(1.5), JsonValue.Create(ulong.MaxValue) })
            Reject(Modify(signed, root => root["manifest"]!["sizeBytes"] = size?.DeepClone()), policy);
        foreach (var field in new[] { "version", "artifactId", "artifactUrl", "sha256", "channel", "environment" })
            Reject(Modify(signed, root => root["manifest"]![field] = "bad\u0001value"), policy);
        // A bounded raw UTF-8 document can expand beyond the canonical JSON limit; it still yields a generic rejection.
        var expanding = JsonNode.Parse(signed)!.AsObject();
        expanding["manifest"]!["artifactUrl"] = "https://example.invalid/" + new string('\u00fc', 1_500);
        var raw = expanding.ToJsonString(new System.Text.Json.JsonSerializerOptions
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        Check(Encoding.UTF8.GetByteCount(raw) < UpdateManifestFormat.MaximumDocumentBytes, "The expanded-canonical test input is bounded on the wire.");
        Reject(Encoding.UTF8.GetBytes(raw), policy);
    }

    private static void ValidateInvalidMetadata(UpdateManifest manifest)
    {
        foreach (var version in new[] { "", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.3-beta", "-1.2.3", "+1.2.3", "1.2.65536", "1.2.3 ", "١.2.3" })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { Version = version }, KeyId));
        foreach (var url in new[] { "http://updates.example.invalid/package.zip", "file:///tmp/package.zip", "https://user:secret@example.invalid/package.zip", "https://example.invalid/package.zip?token=secret", "https://example.invalid/package.zip#part", "/package.zip", " https://example.invalid/package.zip", "https://example.invalid/a b.zip", new string('a', 2_049) })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { ArtifactUrl = url }, KeyId));
        foreach (var hash in new[] { "", new string('a', 63), new string('a', 65), new string('A', 64), new string('g', 64) })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { Sha256 = hash }, KeyId));
        foreach (var size in new[] { 0L, -1, UpdateManifestFormat.MaximumArtifactBytes + 1 })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { SizeBytes = size }, KeyId));
        foreach (var channel in new[] { "", "Stable", "canary", "pilot/beta" })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { Channel = channel }, KeyId));
        foreach (var environment in new[] { "", "test", "Production", "production\n" })
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { Environment = environment }, KeyId));
        foreach (var identifier in new[] { "", "key name", "x.y", new string('a', 65), "key\n" })
        {
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest, identifier));
            Throws<ArgumentException>(() => UpdateManifestFormat.CreateSigningData(manifest with { ArtifactId = identifier }, KeyId));
        }
        Throws<ArgumentException>(() => UpdateManifestFormat.SerializeSigned(manifest, KeyId, new byte[63]));
        Throws<ArgumentException>(() => UpdateManifestFormat.SerializeSigned(manifest, KeyId, new byte[65]));
    }

    private static void ValidateKeys(ECDsa key, Dictionary<string, string> trusted)
    {
        using var rsa = RSA.Create(2048);
        using var otherCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        foreach (var pem in new[] { key.ExportPkcs8PrivateKeyPem(), key.ExportECPrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem(), otherCurve.ExportSubjectPublicKeyInfoPem(),
            "not a PEM", key.ExportSubjectPublicKeyInfoPem() + "\n" + key.ExportSubjectPublicKeyInfoPem(), "unknown\n" + key.ExportSubjectPublicKeyInfoPem(), new string(' ', 4_097) })
            Throws<ArgumentException>(() => Policy(new Dictionary<string, string> { [KeyId] = pem }));
        Throws<ArgumentException>(() => Policy(new Dictionary<string, string>()));
        Throws<ArgumentException>(() => Policy(Enumerable.Range(0, 33).ToDictionary(index => "key-" + index, _ => key.ExportSubjectPublicKeyInfoPem())));
        Throws<ArgumentException>(() => Policy(new Dictionary<string, string> { ["bad key"] = key.ExportSubjectPublicKeyInfoPem() }));
        Throws<ArgumentException>(() => Policy(trusted, environment: "test"));
        Throws<ArgumentException>(() => Policy(trusted, channel: "Stable"));
        Throws<ArgumentException>(() => Policy(trusted, artifactId: "../agent"));
        Throws<ArgumentException>(() => Policy(trusted, installedVersion: "1.2"));
    }

    private static async Task ValidateArtifactAsync(byte[] package, VerifiedUpdateManifest verified, UpdateManifest manifest, ECDsa key, UpdateVerificationPolicy policy)
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-update-hash-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var original = Path.Combine(directory, "source.zip");
            var staging = Path.Combine(directory, "verified.zip");
            await File.WriteAllBytesAsync(original, package);
            await UpdateArtifactVerifier.CopyAndVerifyAsync(original, staging, verified);
            Check((await File.ReadAllBytesAsync(staging)).SequenceEqual(package), "Hash verification stages the exact authenticated package bytes.");
            Check((await File.ReadAllBytesAsync(original)).SequenceEqual(package), "Verification never modifies the source artifact.");
            if (!OperatingSystem.IsWindows())
                Check(File.GetUnixFileMode(staging) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "Verified staging files are private on Unix.");
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, staging, verified));
            Check((await File.ReadAllBytesAsync(staging)).SequenceEqual(package), "An existing destination cannot be overwritten or removed.");

            var tampered = package.ToArray();
            tampered[100] ^= 1;
            await File.WriteAllBytesAsync(original, tampered);
            var failedStaging = Path.Combine(directory, "failed.zip");
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, failedStaging, verified));
            Check(!File.Exists(failedStaging), "An equal-size tampered package is rejected and its partial staging file is removed.");
            Check((await File.ReadAllBytesAsync(staging)).SequenceEqual(package), "Changing the original after verification does not change the private copy.");

            await File.WriteAllBytesAsync(original, package[..^1]);
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, failedStaging, verified));
            Check(!File.Exists(failedStaging), "A truncated package leaves no installation candidate.");
            await File.WriteAllBytesAsync(original, package.Concat(new byte[] { 0 }).ToArray());
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, failedStaging, verified));
            Check(!File.Exists(failedStaging), "An oversized package leaves no installation candidate.");

            await File.WriteAllBytesAsync(original, package);
            var wrongHash = UpdateManifestVerifier.Verify(Sign(manifest with { Sha256 = new string('0', 64) }, key), policy);
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, failedStaging, wrongHash));
            Check(!File.Exists(failedStaging), "A correctly signed manifest still requires a matching package hash.");
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await ThrowsAsync<OperationCanceledException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(original, failedStaging, verified, cancellation.Token));
            Check(!File.Exists(failedStaging), "Cancellation removes any partial staging copy.");
            await ThrowsAsync<UpdateValidationException>(() => UpdateArtifactVerifier.CopyAndVerifyAsync(Path.Combine(directory, "missing.zip"), failedStaging, verified));
            Check(!File.Exists(failedStaging), "An unavailable source fails closed without staging a file.");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static UpdateVerificationPolicy Policy(IReadOnlyDictionary<string, string> keys, string environment = "development", string channel = "stable",
        string artifactId = ArtifactId, string installedVersion = "1.0.0") => new(environment, channel, artifactId, installedVersion, keys);

    private static byte[] Sign(UpdateManifest manifest, ECDsa key, string keyId = KeyId) => UpdateManifestFormat.SerializeSigned(manifest, keyId,
        key.SignData(UpdateManifestFormat.CreateSigningData(manifest, keyId), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    private static byte[] Modify(byte[] document, Action<JsonObject> change)
    {
        var root = JsonNode.Parse(document)!.AsObject();
        change(root);
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Reject(byte[] document, UpdateVerificationPolicy policy)
    {
        try { UpdateManifestVerifier.Verify(document, policy); }
        catch (UpdateValidationException exception)
        {
            Check(exception.Message == "Update validation failed." && exception.InnerException is null, "Rejections never disclose untrusted body data or key material.");
            return;
        }
        throw new InvalidOperationException("An invalid or unauthorized update was accepted.");
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { _assertions++; return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T) { _assertions++; return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void Check(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }
}
