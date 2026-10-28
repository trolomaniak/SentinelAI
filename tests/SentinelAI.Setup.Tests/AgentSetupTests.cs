using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SentinelAI.Enrollment;
using SentinelAI.Setup.Foundation;

// MVP-2: SentinelAI-Agent-Setup.exe. Synthetic codes, tokens and certificates only.
internal static class AgentSetupTests
{
    private static readonly string Token = new('C', 64);
    private static readonly string Pin = new('A', 64);

    public static async Task<int> RunAsync()
    {
        var checks = 0;
        void Ensure(bool value, string context) { checks++; if (!value) throw new InvalidOperationException("Agent Setup: " + context); }
        void Reject(Action action, string context)
        {
            checks++;
            try { action(); } catch (InvalidDataException) { return; }
            throw new InvalidOperationException("Agent Setup: " + context);
        }

        // The host accepts only the wrapper's canonical command line, always with its image handle first.
        var root = OperatingSystem.IsWindows() ? @"C:\codes\pc-01.sentinelai-enroll" : "/codes/pc-01.sentinelai-enroll";
        Ensure(SetupArguments.TryParse(["--image", "1234"], out var parsed) && parsed == new SetupArguments(SetupMode.Interactive, 1234), "interactive");
        Ensure(SetupArguments.TryParse(["--image", "8", "--uninstall"], out parsed) && parsed!.Mode == SetupMode.Uninstall, "uninstall");
        Ensure(SetupArguments.TryParse(["--image", "8", "--uninstall", "--quiet"], out parsed) && parsed!.Mode == SetupMode.QuietUninstall, "quiet uninstall");
        Ensure(SetupArguments.TryParse(["--image", "8", "--quiet", "--codefile", root], out parsed) &&
               parsed == new SetupArguments(SetupMode.QuietInstall, 8, root), "quiet install with a code file");
        Ensure(SetupArguments.TryParse(["--image", "8", "--upgrade", "--quiet"], out parsed) && parsed!.Mode == SetupMode.QuietUpgrade, "quiet upgrade");
        foreach (var invalid in new string[][]
        {
            [], ["--uninstall"], ["--image"], ["--image", "0"], ["--image", "08"], ["--image", "-8"], ["--image", "x"], ["--image", "99999999999999999999"],
            ["--image", "8", "--quiet"], ["--image", "8", "--codefile", root], ["--image", "8", "--quiet", "--codefile"],
            ["--image", "8", "--quiet", "--codefile", "relative.sentinelai-enroll"], ["--image", "8", "--quiet", "--uninstall"],
            ["--image", "8", "--UNINSTALL"], ["--image", "8", "/uninstall"], ["--image", "8", "--uninstall", "--quiet", "--quiet"],
            ["--image", "8", "--quiet", "--codefile", root, "--uninstall"], ["--image", "8", "--image", "9"],
            ["--image", "8", "--upgrade"], ["--image", "8", "--quiet", "--upgrade"], ["--image", "8", "--upgrade", "--uninstall"], ["--image", "8", "--upgrade", "--quiet", "--quiet"],
            ["--image", "8", "--UPGRADE"], ["--image", "8", "/upgrade"], ["--image", "8", "--upgrade", "--quiet", "--codefile", root]
        })
            Ensure(!SetupArguments.TryParse(invalid, out parsed) && parsed is null, "rejects " + string.Join(' ', invalid));

        // The worker request carries the code's Core, pin and token only for the install action.
        var metadata = new SetupMetadata("dev-agent-tests", "1.0.0", "pilot", new string('0', 64), 1, SetupMetadata.AgentProduct);
        var code = new EnrollmentCode("central-pc.example.test", 5443, Pin, Token);
        var buffer = new byte[8192];
        var work = @"C:\ProgramData\SentinelAI-Setup\0123456789abcdef0123456789abcdef";
        var length = AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-install", work, metadata, code);
        var request = Encoding.UTF8.GetString(buffer, 0, length);
        Ensure(request == "{\"action\":\"agent-install\",\"workDirectory\":\"C:\\\\ProgramData\\\\SentinelAI-Setup\\\\0123456789abcdef0123456789abcdef\",\"keyId\":\"dev-agent-tests\",\"channel\":\"pilot\",\"version\":\"1.0.0\",\"coreUrl\":\"https://central-pc.example.test:5443\",\"coreCertificateSha256\":\"" + Pin + "\",\"enrollmentToken\":\"" + Token + "\"}\n",
            "install request");
        foreach (var action in new[] { "agent-inspect", "agent-uninstall" })
        {
            length = AgentSetupWorkflow.WriteWorkerRequest(buffer, action, work, metadata, null);
            request = Encoding.UTF8.GetString(buffer, 0, length);
            Ensure(request.Contains("\"coreUrl\":\"\",\"coreCertificateSha256\":\"\",\"enrollmentToken\":\"\"}", StringComparison.Ordinal) && !request.Contains(Token, StringComparison.Ordinal),
                action + " carries no code");
            Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, action, work, metadata, code), action + " never accepts a code");
        }
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-install", work, metadata, null), "install requires a code");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "complete", work, metadata, null), "full Setup action");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-inspect", work, metadata with { Product = SetupMetadata.FullProduct }, null), "full Setup product");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-install", work, metadata, code with { EnrollmentToken = new string('z', 64) }), "malformed token");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-install", work, metadata, code with { CertificateSha256 = Pin.ToLowerInvariant() }), "lowercase pin");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(new byte[8191], "agent-inspect", work, metadata, null), "fixed buffer");
        Reject(() => AgentSetupWorkflow.WriteWorkerRequest(buffer, "agent-inspect", new string('x', 261), metadata, null), "bounded work path");

        Ensure(AgentSetupWorkflow.ParseState("STATE|Fresh|") == new AgentSetupInstallation(AgentSetupInstallationKind.Fresh), "fresh state");
        Ensure(AgentSetupWorkflow.ParseState("STATE|Blocked|") == new AgentSetupInstallation(AgentSetupInstallationKind.Blocked), "blocked state");
        Ensure(AgentSetupWorkflow.ParseState("STATE|Installed|1.2.3") == new AgentSetupInstallation(AgentSetupInstallationKind.Installed, "1.2.3"), "installed state");
        foreach (var invalid in new[] { "STATE|Installed|", "STATE|Fresh|1.0.0", "STATE|Installed|01.0.0", "STATE|Retained|1.0.0", "STATE|fresh|", "STATE|Fresh", "STATE|Fresh||", "PROGRESS|agent" })
            Reject(() => AgentSetupWorkflow.ParseState(invalid), "rejects state " + invalid);

        // Nothing changes before Core accepts the code over the pinned connection; failures map to documented exit codes.
        async Task<(AgentSetupExitCode Code, string Calls)> Install(AgentSetupInstallationKind state, AgentCodeCheck check,
            AgentInstallOutcome outcome = AgentInstallOutcome.Installed, bool inspectFails = false)
        {
            var calls = new List<string>();
            var worker = new FakeAgentWorker(calls) { State = state, Outcome = outcome, InspectFails = inspectFails };
            var result = await AgentSetupWorkflow.InstallAsync(code, worker, new FakeProbe(calls, check), new SilentProgress(), CancellationToken.None);
            return (result, string.Join(',', calls));
        }
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Usable) == (AgentSetupExitCode.Success, "inspect,probe,install"), "fresh install");
        Ensure(await Install(AgentSetupInstallationKind.Installed, AgentCodeCheck.Usable) == (AgentSetupExitCode.AlreadyInstalled, "inspect"), "installed Agent");
        Ensure(await Install(AgentSetupInstallationKind.Blocked, AgentCodeCheck.Usable) == (AgentSetupExitCode.AlreadyInstalled, "inspect"), "other Agent");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.PinMismatch) == (AgentSetupExitCode.PinMismatch, "inspect,probe"), "wrong pin");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Refused) == (AgentSetupExitCode.CodeRefused, "inspect,probe"), "refused code");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Unreachable) == (AgentSetupExitCode.CoreUnreachable, "inspect,probe"), "unreachable Core");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Usable, AgentInstallOutcome.NotAcknowledged) ==
               (AgentSetupExitCode.EnrollmentNotAcknowledged, "inspect,probe,install"), "enrollment not acknowledged");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Usable, AgentInstallOutcome.Failed) ==
               (AgentSetupExitCode.InstallFailed, "inspect,probe,install"), "install failure");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Usable, AgentInstallOutcome.RollbackFailed) ==
               (AgentSetupExitCode.RollbackFailed, "inspect,probe,install") &&
               AgentSetupWorkflow.Describe(AgentSetupExitCode.RollbackFailed, false).Contains("/uninstall", StringComparison.Ordinal), "a failed removal after a failed install");
        Ensure(await Install(AgentSetupInstallationKind.Fresh, AgentCodeCheck.Usable, inspectFails: true) == (AgentSetupExitCode.InstallFailed, "inspect"), "inspection failure");
        async Task<(AgentSetupExitCode Code, string Calls)> Uninstall(AgentSetupInstallationKind state, bool fails = false)
        {
            var calls = new List<string>();
            var result = await AgentSetupWorkflow.UninstallAsync(new FakeAgentWorker(calls) { State = state, UninstallFails = fails }, new SilentProgress(), CancellationToken.None);
            return (result, string.Join(',', calls));
        }
        Ensure(await Uninstall(AgentSetupInstallationKind.Installed) == (AgentSetupExitCode.Success, "inspect,uninstall"), "uninstall");
        Ensure(await Uninstall(AgentSetupInstallationKind.Fresh) == (AgentSetupExitCode.NotInstalled, "inspect"), "nothing to uninstall");
        Ensure(await Uninstall(AgentSetupInstallationKind.Blocked) == (AgentSetupExitCode.NotInstalled, "inspect"), "another product is never uninstalled");
        Ensure(await Uninstall(AgentSetupInstallationKind.Installed, fails: true) == (AgentSetupExitCode.UninstallFailed, "inspect,uninstall"), "uninstall failure");
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel();
            var calls = new List<string>();
            try
            {
                _ = await AgentSetupWorkflow.InstallAsync(code, new FakeAgentWorker(calls), new FakeProbe(calls, AgentCodeCheck.Usable), new SilentProgress(), canceled.Token);
                Ensure(false, "canceled install");
            }
            catch (OperationCanceledException) { Ensure(calls.Count == 0, "cancellation changes nothing"); }
        }
        foreach (var exit in Enum.GetValues<AgentSetupExitCode>())
            Ensure(!AgentSetupWorkflow.Describe(exit, false).Contains(Token, StringComparison.Ordinal) && AgentSetupWorkflow.Describe(exit, true).Length > 0, "message " + exit);

        // The Agent payload: the Agent worker, signed Agent package and Updater; never Core or Desktop.
        string[] agentPayload = ["setup/SetupWorker.ps1", "setup/SetupLifecycle.ps1", "setup/AgentSetupWorker.ps1", "bundle/installer/PilotInstaller.psm1",
            "bundle/agent.zip", "bundle/agent.manifest.json", "bundle/updater/SentinelAI.Updater.exe"];
        async Task<bool> Verifies(string product, params string[] entries)
        {
            using var output = new MemoryStream();
            using (var zip = new System.IO.Compression.ZipArchive(output, System.IO.Compression.ZipArchiveMode.Create, true))
                foreach (var entry in entries) { using var writer = new StreamWriter(zip.CreateEntry(entry).Open()); writer.Write("synthetic " + entry); }
            var bytes = output.ToArray();
            try
            {
                await SetupPayload.VerifyAsync(new MemoryStream(bytes), metadata with { Product = product, PayloadLength = bytes.Length, PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) }, CancellationToken.None);
                return true;
            }
            catch (InvalidDataException) { return false; }
        }
        Ensure(await Verifies(SetupMetadata.AgentProduct, agentPayload), "complete Agent payload");
        Ensure(!await Verifies(SetupMetadata.FullProduct, agentPayload), "the full Setup requires Desktop");
        foreach (var missing in agentPayload.Where(entry => !entry.EndsWith("Lifecycle.ps1", StringComparison.Ordinal) && !entry.EndsWith("manifest.json", StringComparison.Ordinal)))
            Ensure(!await Verifies(SetupMetadata.AgentProduct, agentPayload.Where(entry => entry != missing).ToArray()), "Agent payload requires " + missing);
        foreach (var extra in new[] { "desktop/SentinelAI.Desktop.exe", "bundle/core.zip", "bundle/Core.manifest.json", "bundle/deployment.zip" })
            Ensure(!await Verifies(SetupMetadata.AgentProduct, [.. agentPayload, extra]), "Agent payload refuses " + extra);

        // Code files: pasted text or a .sentinelai-enroll file, bounded, with or without a byte order mark.
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-agent-setup-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var file = Path.Combine(directory, "pc-01" + EnrollmentCode.FileExtension);
            File.WriteAllText(file, code.Encode() + "\r\n", new UTF8Encoding(true));
            Ensure(AgentSetupWorkflow.TryReadCodeFile(file, out var read) && read == code, "code file");
            File.WriteAllText(file, code.Encode()[..^1] + (code.Encode()[^1] == '0' ? '1' : '0'));
            Ensure(!AgentSetupWorkflow.TryReadCodeFile(file, out read) && read is null, "tampered code file");
            File.WriteAllBytes(file, new byte[EnrollmentCode.MaximumFileBytes + 1]);
            Ensure(!AgentSetupWorkflow.TryReadCodeFile(file, out _), "oversized code file");
            File.WriteAllBytes(file, []);
            Ensure(!AgentSetupWorkflow.TryReadCodeFile(file, out _), "empty code file");
            Ensure(!AgentSetupWorkflow.TryReadCodeFile(Path.Combine(directory, "missing.sentinelai-enroll"), out _), "missing code file");
            Ensure(!AgentSetupWorkflow.TryReadCodeFile(directory, out _), "directory instead of a file");
        }
        finally { Directory.Delete(directory, recursive: true); }

        // The pre-check: Core's certificate is trusted only by the code's pin; 204 means usable, 410 refused.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request509 = new CertificateRequest("CN=sentinelai-agent-setup-test", key, HashAlgorithmName.SHA256);
        using var created = request509.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        using var certificate = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null);
        var pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var usable = await ProbeAsync(certificate, pin, "204 No Content");
        Ensure(usable.Result == AgentCodeCheck.Usable && usable.Request.StartsWith("POST /api/agent/enrollment-check HTTP/1.1\r\n", StringComparison.Ordinal) &&
               usable.Request.EndsWith("\r\n\r\n{\"enrollmentToken\":\"" + Token + "\"}", StringComparison.Ordinal) &&
               usable.Request.Contains("Content-Type: application/json", StringComparison.OrdinalIgnoreCase), "usable code");
        Ensure((await ProbeAsync(certificate, pin, "410 Gone")).Result == AgentCodeCheck.Refused, "refused code");
        Ensure((await ProbeAsync(certificate, pin, "404 Not Found")).Result == AgentCodeCheck.Unreachable, "not a SentinelAI Core");
        Ensure((await ProbeAsync(certificate, pin, "429 Too Many Requests")).Result == AgentCodeCheck.Unreachable, "rate-limited check");
        var mismatch = await ProbeAsync(certificate, new string('F', 64), "204 No Content");
        Ensure(mismatch.Result == AgentCodeCheck.PinMismatch && mismatch.Request.Length == 0, "wrong pin: the token is never sent");
        Ensure((await ProbeAsync(certificate, pin, null)).Result == AgentCodeCheck.Unreachable, "silent Core times out");
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        Ensure(await new HttpAgentCodeProbe(TimeSpan.FromSeconds(5)).CheckAsync(new EnrollmentCode("127.0.0.1", closedPort, pin, Token), CancellationToken.None) ==
               AgentCodeCheck.Unreachable, "closed port");
        return checks;
    }

    // A synthetic TLS endpoint: answers one request with the given status line, or never when it is null.
    private static async Task<(AgentCodeCheck Result, string Request)> ProbeAsync(X509Certificate2 certificate, string pin, string? status)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(stop.Token);
            await using var tls = new SslStream(client.GetStream());
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, stop.Token);
            }
            catch (Exception exception) when (exception is AuthenticationException or IOException) { return ""; }
            var received = new List<byte>();
            var buffer = new byte[1024];
            var expected = int.MaxValue;
            try
            {
                while (received.Count < expected)
                {
                    var count = await tls.ReadAsync(buffer, stop.Token);
                    if (count == 0) break;
                    received.AddRange(buffer.AsSpan(0, count));
                    var text = Encoding.UTF8.GetString(received.ToArray());
                    var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    var header = text.IndexOf("Content-Length: ", StringComparison.OrdinalIgnoreCase);
                    if (end > 0 && header > 0)
                        expected = end + 4 + int.Parse(text[(header + 16)..text.IndexOf("\r\n", header, StringComparison.Ordinal)]);
                }
                if (status is null) { while (await tls.ReadAsync(buffer, stop.Token) != 0) { } }
                else await tls.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), stop.Token);
            }
            catch (IOException) { }
            return Encoding.UTF8.GetString(received.ToArray());
        });
        var result = await new HttpAgentCodeProbe(TimeSpan.FromSeconds(status is null ? 2 : 10))
            .CheckAsync(new EnrollmentCode("127.0.0.1", port, pin, Token), CancellationToken.None);
        return (result, await server);
    }

    private sealed class SilentProgress : IProgress<string> { public void Report(string value) { } }

    private sealed class FakeProbe(List<string> calls, AgentCodeCheck result) : IAgentCodeProbe
    {
        public Task<AgentCodeCheck> CheckAsync(EnrollmentCode code, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); calls.Add("probe"); return Task.FromResult(result);
        }
    }

    private sealed class FakeAgentWorker(List<string> calls) : IAgentSetupWorker
    {
        public AgentSetupInstallationKind State { get; init; } = AgentSetupInstallationKind.Fresh;
        public AgentInstallOutcome Outcome { get; init; } = AgentInstallOutcome.Installed;
        public bool InspectFails { get; init; }
        public bool UninstallFails { get; init; }

        public Task<AgentSetupInstallation> InspectAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); calls.Add("inspect");
            if (InspectFails) throw new InvalidDataException("Synthetic inspection failure.");
            return Task.FromResult(new AgentSetupInstallation(State, State == AgentSetupInstallationKind.Installed ? "1.0.0" : null));
        }

        public Task<AgentInstallOutcome> InstallAsync(EnrollmentCode code, CancellationToken token) { calls.Add("install"); return Task.FromResult(Outcome); }

        public Task UninstallAsync(CancellationToken token)
        {
            calls.Add("uninstall");
            return UninstallFails ? Task.FromException(new InvalidDataException("Synthetic uninstall failure.")) : Task.CompletedTask;
        }
    }
}
