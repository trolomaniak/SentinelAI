using System.Net;
using System.Security.Cryptography;
using System.Text;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Licensing;
using SentinelAI.Setup.Foundation;

// MVP-3: a fresh central Setup built with pilot public keys verifies the pilot key offline before installing and
// hands it to Core once Core runs. Development keys are generated per run; no private key is stored anywhere.
internal static class PilotSetupTests
{
    private const string Password = "synthetic-password";

    public static async Task<int> RunAsync()
    {
        var checks = 0;
        void Ensure(bool value, string context) { checks++; if (!value) throw new InvalidOperationException("Setup pilot license: " + context); }
        async Task Reject(Func<Task> action, string context)
        {
            try { await action(); }
            catch (InvalidDataException) { checks++; return; }
            throw new InvalidOperationException("Setup pilot license accepted: " + context);
        }

        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var work = Path.Combine(Path.GetTempPath(), $"sentinelai-setup-pilot-{Guid.NewGuid():N}");
        var trust = Path.Combine(work, "setup", "pilot-license", "trust");
        try
        {
            Directory.CreateDirectory(work);
            Ensure(SetupPilotLicense.Load(work) is null, "a build without pilot keys asks for no key");
            Directory.CreateDirectory(trust);
            await Reject(() => Task.FromResult(SetupPilotLicense.Load(work)), "empty pilot trust");
            File.WriteAllText(Path.Combine(trust, "dev-pilot.pem"), signer.ExportSubjectPublicKeyInfoPem());
            var pilot = SetupPilotLicense.Load(work) ?? throw new InvalidOperationException("Pilot trust did not load.");
            Ensure(SetupPilotLicense.Accepted(pilot.Verify(Issue(signer, "dev-pilot", now.AddDays(-1), now.AddDays(30)), now)), "a current key is accepted");
            Ensure(SetupPilotLicense.Accepted(pilot.Verify(Issue(signer, "dev-pilot", now.AddDays(2), now.AddDays(30)), now)), "a key starting later is accepted as in Core");
            Ensure(pilot.Verify(Issue(signer, "dev-pilot", now.AddDays(-30), now.AddDays(-1)), now).Status == PilotLicenseStatus.Expired, "an expired key is refused");
            Ensure(pilot.Verify(Issue(stranger, "dev-pilot", now, now.AddDays(30)), now).Status == PilotLicenseStatus.Invalid, "a key from another signer is refused");
            Ensure(pilot.Verify(Issue(signer, "other-pilot", now, now.AddDays(30)), now).Status == PilotLicenseStatus.Invalid, "an unknown key ID is refused");
            Ensure(SetupPilotLicense.Normalize("  a.b.c\r\n") == "a.b.c" && SetupPilotLicense.Normalize(null) == "", "pasted whitespace is ignored");
            foreach (var text in new[] { "", "a.b", "a.b.c.d", "a.b.c ", "a.b.ć", "a.b.c/", new string('a', PilotLicenseFormat.MaxKeyLength - 3) + ".b.c" })
                Ensure(!SetupPilotLicense.IsKeyText(text), "only bounded base64url key text is handed to Core");
            File.WriteAllText(Path.Combine(trust, "private.pem"), signer.ExportPkcs8PrivateKeyPem());
            await Reject(() => Task.FromResult(SetupPilotLicense.Load(work)), "a private key in Setup's pilot trust");
            File.Delete(Path.Combine(trust, "private.pem"));
            File.WriteAllText(Path.Combine(trust, "notes.txt"), "synthetic");
            await Reject(() => Task.FromResult(SetupPilotLicense.Load(work)), "a non-PEM file in Setup's pilot trust");
        }
        finally { if (Directory.Exists(work)) Directory.Delete(work, recursive: true); }

        // The key reaches Core after the administrator exists and Core runs, and before the Agent enrolls.
        var key = Issue(signer, "dev-pilot", now, now.AddDays(30));
        var sequence = new List<string>();
        var client = new FakePilotClient(sequence);
        await SetupWorkflow.InstallAsync(new FakeWorker(sequence), new FakeAdministrator(sequence), new FakeIssuer(sequence), null,
            " operator ", Password.AsMemory(), new SilentProgress(), CancellationToken.None, client, key);
        Ensure(sequence.SequenceEqual(new[] { "prepare", "state", "initialize:operator", "start", "pilot:operator", "issue:operator", "complete" }) && client.Key == key,
            "the pilot key is applied once Core runs and before the Agent enrolls");
        sequence.Clear();
        await SetupWorkflow.InstallAsync(new FakeWorker(sequence), new FakeAdministrator(sequence), new FakeIssuer(sequence), null,
            "operator", Password.AsMemory(), new SilentProgress(), CancellationToken.None, client);
        Ensure(!sequence.Contains("pilot:operator"), "a build without pilot keys sends none");
        foreach (var (pilotClient, pilotKey, reason) in new (ISetupPilotLicenseClient?, string, string)[] { (null, key, "no client"), (client, "not a key", "invalid key text") })
        {
            sequence.Clear();
            await Reject(() => SetupWorkflow.InstallAsync(new FakeWorker(sequence), new FakeAdministrator(sequence), new FakeIssuer(sequence), null,
                "operator", Password.AsMemory(), new SilentProgress(), CancellationToken.None, pilotClient, pilotKey), reason);
            Ensure(sequence.Count == 0, "an unusable pilot key stops Setup before any change: " + reason);
        }
        sequence.Clear();
        await Reject(() => SetupWorkflow.InstallAsync(new FakeWorker(sequence), new FakeAdministrator(sequence), new FakeIssuer(sequence), null,
            "operator", Password.AsMemory(), new SilentProgress(), CancellationToken.None, new FakePilotClient(sequence) { Fail = true }, key), "Core refusal");
        Ensure(!sequence.Contains("complete") && !sequence.Any(step => step.StartsWith("issue:", StringComparison.Ordinal)), "a refused pilot key does not complete installation");

        // The real client: one login, then one POST with only the key, over a trusted loopback Core.
        var handler = new PilotHandler();
        using (var issuer = new HttpSetupEnrollmentIssuer(new Trust(true), handler))
            await issuer.ApplyAsync(" setup-test ", Password.AsMemory(), key, CancellationToken.None);
        Ensure(handler.Paths.SequenceEqual(new[] { "/api/auth/login", "/api/admin/license/pilot" }) && handler.PilotBody == "{\"key\":\"" + key + "\"}" &&
               handler.Authorization == "Bearer synthetic.jwt-token", "Setup sent anything but the key to Core's pilot route");
        foreach (var status in new[] { HttpStatusCode.BadRequest, HttpStatusCode.NotFound, HttpStatusCode.Conflict, HttpStatusCode.TooManyRequests })
        {
            using var refused = new HttpSetupEnrollmentIssuer(new Trust(true), new PilotHandler { PilotStatus = status });
            await Reject(() => refused.ApplyAsync("setup-test", Password.AsMemory(), key, CancellationToken.None), "Core status " + status);
        }
        var untrusted = new PilotHandler();
        using (var refused = new HttpSetupEnrollmentIssuer(new Trust(false), untrusted))
            await Reject(() => refused.ApplyAsync("setup-test", Password.AsMemory(), key, CancellationToken.None), "untrusted Core");
        Ensure(untrusted.Paths.Count == 0, "an untrusted Core received credentials or a pilot key");
        return checks;
    }

    private static string Issue(ECDsa key, string keyId, DateTimeOffset issued, DateTimeOffset expires)
    {
        var input = PilotLicenseFormat.CreateSigningInput(new PilotLicenseClaims("Example Company", issued, expires), keyId);
        return PilotLicenseFormat.Assemble(input, key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private sealed class FakePilotClient(List<string> sequence) : ISetupPilotLicenseClient
    {
        public bool Fail { get; init; }
        public string? Key { get; private set; }
        public Task ApplyAsync(string username, ReadOnlyMemory<char> password, string key, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); sequence.Add("pilot:" + username); Key = key;
            return Fail ? Task.FromException(new InvalidDataException("Synthetic refusal.")) : Task.CompletedTask;
        }
    }

    private sealed class Trust(bool trusted) : ICoreEndpointTrust
    {
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken token) => Task.FromResult(trusted && origin.AbsoluteUri == "http://127.0.0.1:5000/");
    }

    private sealed class PilotHandler : HttpMessageHandler
    {
        public HttpStatusCode PilotStatus { get; init; } = HttpStatusCode.OK;
        public List<string> Paths { get; } = [];
        public string? PilotBody { get; private set; }
        public string? Authorization { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            if (request.RequestUri.AbsolutePath == "/api/auth/login")
                return Json(HttpStatusCode.OK, "{\"tokenType\":\"Bearer\",\"accessToken\":\"synthetic.jwt-token\",\"expiresIn\":900}");
            PilotBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            Authorization = request.Headers.Authorization?.ToString();
            return Json(PilotStatus, "{\"state\":\"active\"}");
        }
        private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
}
