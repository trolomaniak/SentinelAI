using System.Security.Cryptography;
using System.Text;
using SentinelAI.Licensing;
using SentinelAI.PilotLicense;

// MVP-3: the pilot license key format, its offline verifier and the owner's issuer tool. Generated keys only.
internal static class PilotLicenseTests
{
    private static readonly DateTimeOffset Issued = new(2026, 11, 2, 0, 0, 0, TimeSpan.Zero);

    public static async Task<int> RunAsync()
    {
        var checks = 0;
        void Ensure(bool condition, string message) { checks++; if (!condition) throw new InvalidOperationException("Pilot license: " + message); }
        void Throws(Action action, string message)
        {
            checks++;
            try { action(); } catch (ArgumentException) { return; }
            throw new InvalidOperationException("Pilot license: " + message);
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new PilotLicenseVerifier(new Dictionary<string, string> { ["dev-pilot-1"] = key.ExportSubjectPublicKeyInfoPem() });
        string Sign(PilotLicenseClaims claims, string keyId = "dev-pilot-1", ECDsa? signer = null)
        {
            var input = PilotLicenseFormat.CreateSigningInput(claims, keyId);
            return PilotLicenseFormat.Assemble(input, (signer ?? key).SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        // Raw signing bypasses construction, so the parser is not checked against its own writer only.
        string SignRaw(string header, string payload)
        {
            var input = Encode(Encoding.UTF8.GetBytes(header)) + "." + Encode(Encoding.UTF8.GetBytes(payload));
            return input + "." + Encode(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        const string Header = "{\"alg\":\"ES256\",\"typ\":\"sentinelai-pilot-v1\",\"kid\":\"dev-pilot-1\"}";
        string Payload(string customer = "Synthetic Pilot Company", string issued = "2026-11-02T00:00:00Z", string expires = "2026-12-02T00:00:00Z",
            string plan = "\"pilot\"", string version = "1", string extra = "") =>
            "{\"version\":" + version + ",\"plan\":" + plan + ",\"customer\":" + System.Text.Json.JsonSerializer.Serialize(customer) +
            ",\"issued_at\":\"" + issued + "\",\"expires_at\":\"" + expires + "\"" + extra + "}";

        // Round trip, including a company name with national letters.
        var claims = new PilotLicenseClaims("Zakład Ślusarski Łódź Sp. z o.o.", Issued, Issued.AddDays(30));
        var text = Sign(claims);
        var valid = verifier.Verify(text, Issued.AddDays(1));
        Ensure(valid.Status == PilotLicenseStatus.Valid && valid.Claims == claims && valid.KeyId == "dev-pilot-1", "round trip");
        Ensure(text.Split('.').Length == 3 && text.Length <= PilotLicenseFormat.MaxKeyLength &&
               text.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'), "compact, bounded base64url text");
        Ensure(verifier.Verify("  " + text + "\r\n", Issued.AddDays(1)).Status == PilotLicenseStatus.Valid, "pasted text with surrounding whitespace");
        Ensure(verifier.Verify(SignRaw(Header, Payload()), Issued.AddDays(1)).Status == PilotLicenseStatus.Valid, "independently encoded key");
        Ensure(new PilotLicenseVerifier(new Dictionary<string, string>()).Verify(text, Issued.AddDays(1)) is { Status: PilotLicenseStatus.Invalid, Claims: null } &&
               !new PilotLicenseVerifier(new Dictionary<string, string>()).Configured && verifier.Configured, "a build without pilot keys accepts none");

        // Time: not yet valid before issue, valid until the exact expiry instant, then expired.
        Ensure(verifier.Verify(text, Issued.AddTicks(-1)) is { Status: PilotLicenseStatus.NotYetValid, Claims: not null }, "not yet valid");
        Ensure(verifier.Verify(text, Issued).Status == PilotLicenseStatus.Valid, "valid from issue");
        Ensure(verifier.Verify(text, claims.ExpiresAt.AddTicks(-1)).Status == PilotLicenseStatus.Valid, "valid just before expiry");
        Ensure(verifier.Verify(text, claims.ExpiresAt) is { Status: PilotLicenseStatus.Expired, Claims: not null }, "expired at the expiry instant");

        // Tampering, an unknown key ID and a wrong signature fail closed, without claims.
        var segments = text.Split('.');
        for (var index = 0; index < segments[1].Length; index++)
        {
            var changed = segments[1].ToCharArray();
            changed[index] = changed[index] == 'A' ? 'B' : 'A';
            Ensure(verifier.Verify(segments[0] + "." + new string(changed) + "." + segments[2], Issued.AddDays(1)) is { Status: PilotLicenseStatus.Invalid, Claims: null },
                "payload change at " + index);
        }
        var signature = segments[2].ToCharArray();
        signature[10] = signature[10] == 'A' ? 'B' : 'A';
        Ensure(verifier.Verify(segments[0] + "." + segments[1] + "." + new string(signature), Issued.AddDays(1)).Status == PilotLicenseStatus.Invalid, "signature change");
        Ensure(verifier.Verify(Sign(claims, "dev-pilot-unknown"), Issued.AddDays(1)).Status == PilotLicenseStatus.Invalid, "unknown key ID");
        Ensure(verifier.Verify(Sign(claims, signer: otherKey), Issued.AddDays(1)).Status == PilotLicenseStatus.Invalid, "wrong signature for the key ID");
        foreach (var invalid in new[]
        {
            null, "", "a.b", text + ".extra", text.Replace('.', ','), text + "=", new string('A', PilotLicenseFormat.MaxKeyLength + 1),
            SignRaw(Header.Replace("sentinelai-pilot-v1", "sentinelai-lease-v1"), Payload()),
            SignRaw(Header.Replace("ES256", "ES384"), Payload()),
            SignRaw(Header.Replace("}", ",\"x5u\":\"https://example.invalid\"}"), Payload()),
            SignRaw(Header, Payload(plan: "\"business\"")), SignRaw(Header, Payload(version: "2")), SignRaw(Header, Payload(version: "\"1\"")),
            SignRaw(Header, Payload(extra: ",\"endpoint_limit\":5")), SignRaw(Header, Payload(issued: "2026-11-02T00:00:00+01:00")),
            SignRaw(Header, Payload(issued: "2026-11-02T00:00:00.5Z")), SignRaw(Header, Payload(expires: "2026-11-02T00:00:00Z")),
            SignRaw(Header, Payload(expires: "2027-11-03T00:00:01Z")), SignRaw(Header, Payload(customer: "")),
            SignRaw(Header, Payload(customer: " Padded")), SignRaw(Header, Payload(customer: "Line\nbreak")),
            SignRaw(Header, Payload(customer: new string('x', PilotLicenseFormat.MaxCustomerLength + 1))),
            SignRaw(Header, Payload().Replace("\"plan\":\"pilot\",", "\"plan\":\"pilot\",\"plan\":\"pilot\","))
        })
            Ensure(verifier.Verify(invalid, Issued.AddDays(1)) is { Status: PilotLicenseStatus.Invalid, Claims: null }, "rejects " + (invalid?.Length > 40 ? invalid[..40] : invalid));
        Ensure(verifier.Verify(SignRaw(Header, Payload(customer: new string('x', PilotLicenseFormat.MaxCustomerLength), expires: "2027-11-02T00:00:00Z")), Issued.AddDays(1)).Status ==
               PilotLicenseStatus.Valid, "64 characters and 365 days are the limits");

        // Length and range limits when issuing; a pilot key is never a lease and the reverse.
        Throws(() => Sign(claims with { Customer = new string('x', 65) }), "customer over 64 characters");
        Throws(() => Sign(claims with { ExpiresAt = Issued.AddDays(366) }), "more than 365 days");
        Throws(() => Sign(claims with { ExpiresAt = Issued }), "expiry not after issue");
        Throws(() => Sign(claims with { IssuedAt = Issued.ToOffset(TimeSpan.FromHours(1)) }), "non-UTC dates");
        Throws(() => Sign(claims, "bad key id"), "key ID characters");
        Throws(() => _ = new PilotLicenseVerifier(new Dictionary<string, string> { ["dev-pilot-1"] = key.ExportPkcs8PrivateKeyPem() }), "a private key is never a trust anchor");
        Ensure(new LeaseTokenVerifier(new Dictionary<string, string> { ["dev-pilot-1"] = key.ExportSubjectPublicKeyInfoPem() })
            .Verify(text, Guid.NewGuid(), Guid.NewGuid(), Issued.AddDays(1)).Status == LeaseVerificationStatus.Invalid, "a pilot key is not a lease");

        checks += await RunToolAsync(verifier);
        return checks;
    }

    private static async Task<int> RunToolAsync(PilotLicenseVerifier unrelated)
    {
        var checks = 0;
        void Ensure(bool condition, string message) { checks++; if (!condition) throw new InvalidOperationException("pilot-license tool: " + message); }
        var time = new FixedTime(new DateTimeOffset(2026, 11, 2, 15, 30, 0, TimeSpan.Zero));
        async Task<(int Exit, string Output, string Error)> Run(params string[] args)
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var exit = await PilotLicenseCommand.RunAsync(args, output, error, time);
            return (exit, output.ToString(), error.ToString());
        }
        var root = Path.Combine(Path.GetTempPath(), "sentinelai-pilot-tool-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var keys = Path.Combine(root, "keys");
            var generated = await Run("keygen", "--directory", keys, "--key-id", "dev-pilot-tool");
            var privatePath = Path.Combine(keys, "dev-pilot-tool.private.pem");
            var publicPath = Path.Combine(keys, "dev-pilot-tool.public.pem");
            Ensure(generated.Exit == 0 && generated.Output == privatePath + Environment.NewLine + publicPath + Environment.NewLine && generated.Error.Length == 0,
                "keygen prints the two paths only");
            Ensure(File.ReadAllText(privatePath).Contains("PRIVATE KEY", StringComparison.Ordinal) && File.ReadAllText(publicPath).StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal),
                "keygen writes a PKCS#8 private key and an SPKI public key");
            if (!OperatingSystem.IsWindows())
                Ensure(File.GetUnixFileMode(keys) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute) &&
                       File.GetUnixFileMode(privatePath) == (UnixFileMode.UserRead | UnixFileMode.UserWrite) &&
                       File.GetUnixFileMode(publicPath) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "owner-only folder and files");
            var before = File.ReadAllText(privatePath);
            var again = await Run("keygen", "--directory", keys, "--key-id", "dev-pilot-tool");
            Ensure(again.Exit == 1 && again.Output.Length == 0 && File.ReadAllText(privatePath) == before && Directory.GetFiles(keys).Length == 2,
                "keygen refuses an existing folder and overwrites nothing");
            var repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.."));
            Ensure((await Run("keygen", "--directory", Path.Combine(repository, "pilot-keys-" + Guid.NewGuid().ToString("N")), "--key-id", "dev-pilot-tool")).Exit == 1,
                "keygen refuses a folder inside a repository");
            Ensure((await Run("keygen", "--directory", "relative-keys", "--key-id", "dev-pilot-tool")).Exit == 1, "keygen requires an absolute path");

            var verifier = new PilotLicenseVerifier(new Dictionary<string, string> { ["dev-pilot-tool"] = File.ReadAllText(publicPath) });
            var issued = await Run("issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic Pilot Company", "--days", "30");
            var key = issued.Output.TrimEnd('\r', '\n');
            var result = verifier.Verify(key, time.GetUtcNow());
            Ensure(issued.Exit == 0 && issued.Output == key + Environment.NewLine && !key.Contains('\n') && !issued.Output.Contains("PRIVATE", StringComparison.Ordinal) &&
                   result.Status == PilotLicenseStatus.Valid && result.Claims == new PilotLicenseClaims("Synthetic Pilot Company",
                       new DateTimeOffset(2026, 11, 2, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 12, 2, 0, 0, 0, TimeSpan.Zero)),
                "issue prints one key for today's UTC date and the requested days");
            Ensure(unrelated.Verify(key, time.GetUtcNow()).Status == PilotLicenseStatus.Invalid, "another pilot key pair does not verify it");
            var scheduled = await Run("issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic Pilot Company", "--days", "90", "--start", "2027-01-15");
            Ensure(scheduled.Exit == 0 && verifier.Verify(scheduled.Output, time.GetUtcNow()) is { Status: PilotLicenseStatus.NotYetValid } scheduledResult &&
                   scheduledResult.Claims!.IssuedAt == new DateTimeOffset(2027, 1, 15, 0, 0, 0, TimeSpan.Zero) &&
                   scheduledResult.Claims.ExpiresAt == new DateTimeOffset(2027, 4, 15, 0, 0, 0, TimeSpan.Zero), "issue honours --start");
            foreach (var invalid in new[]
            {
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "0" },
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "366" },
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", new string('x', 65), "--days", "30" },
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "30", "--start", "15.01.2027" },
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "30", "--unknown", "x" },
                new[] { "issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic" },
                new[] { "issue", "--private-key", publicPath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "30" },
                new[] { "sign" }, Array.Empty<string>()
            })
            {
                var refused = await Run(invalid);
                Ensure(refused.Exit == 1 && refused.Output.Length == 0 && refused.Error.StartsWith("pilot-license: ", StringComparison.Ordinal), "refuses " + string.Join(' ', invalid.Take(1).Concat(invalid.Skip(7))));
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
                Ensure((await Run("issue", "--private-key", privatePath, "--key-id", "dev-pilot-tool", "--customer", "Synthetic", "--days", "30")).Exit == 1,
                    "issue refuses a private key others can read");
            }
            Ensure((await Run("--help")) is { Exit: 0 } help && help.Output.Contains("keygen", StringComparison.Ordinal), "help");
        }
        finally { Directory.Delete(root, recursive: true); }
        return checks;
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
