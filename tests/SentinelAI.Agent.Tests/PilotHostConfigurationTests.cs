using System.Net;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Agent;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class PilotHostConfigurationTests
{
    private static int assertions;

    public static async Task RunAsync(string root)
    {
        Directory.CreateDirectory(root);
        VerifyRejectedConfigurations(root);
        await VerifyTokenValidationAsync(root);
        await VerifyInstallerHostFlowAsync(root);
        Console.WriteLine($"Pilot host configuration tests passed ({assertions} assertions).");
    }

    private static void VerifyRejectedConfigurations(string root)
    {
        var coreData = Path.Combine(root, "core-validation");
        var agentData = Path.Combine(root, "agent-validation");
        var validCore = JsonSerializer.Serialize(new { urls = "http://127.0.0.1:5000", SentinelAI = new { DataDirectory = coreData } });
        var validAgent = JsonSerializer.Serialize(new { Agent = new { CoreUrl = "http://127.0.0.1:5000", DataDirectory = agentData } });
        var path = Path.Combine(root, "validation.json");
        foreach (var malformed in new[]
        {
            "[]", "null", "{", validCore + "{}",
            "{\"\\uD800\":\"Test-Only-Sensitive\"}",
            "{\"urls\":\"\\uD800\",\"SentinelAI\":{\"DataDirectory\":\"Test-Only-Sensitive\"}}",
            validCore.Replace("\"urls\":", "\"urls\":\"http://127.0.0.1:5000\",\"urls\":"),
            validCore.Replace("http://127.0.0.1:5000", "http://0.0.0.0:5000"),
            validCore.Replace("http://127.0.0.1:5000", "https://127.0.0.1:5000"),
            validCore.Replace("http://127.0.0.1:5000", "http://user:password@127.0.0.1:5000"),
            validCore.Replace("http://127.0.0.1:5000", "http://127.0.0.1:5000/?secret=value"),
            "{\"urls\":\"http://127.0.0.1:5000\",\"SentinelAI\":{\"DataDirectory\":\"relative\"}}",
            validCore.Replace("\"DataDirectory\":", "\"Password\":\"Test-Only-Sensitive\",\"DataDirectory\":"),
            validCore.Replace("\"DataDirectory\":", "\"DataDirectory\":false,\"Other\":"),
            "{\"urls\":\"http://127.0.0.1:5000\"}", new string(' ', 16 * 1024 + 1)
        })
        {
            File.WriteAllText(path, malformed);
            Reject(() => { using var host = CoreHost.Build(["--config", path]); }, "Core accepted an unsafe pilot configuration.");
        }
        foreach (var malformed in new[]
        {
            validAgent.Replace("\"CoreUrl\":", "\"EnrollmentToken\":\"Test-Only-Sensitive\",\"CoreUrl\":"),
            validAgent.Replace("\"CoreUrl\":", "\"CoreUrl\":\"http://127.0.0.1:5000\",\"coreurl\":"),
            validAgent.Replace("http://127.0.0.1:5000", "http://192.0.2.1:5000"),
            validAgent.Replace("\"CoreUrl\":", "\"PrivateKey\":\"Test-Only-Sensitive\",\"CoreUrl\":"),
            JsonSerializer.Serialize(new { Agent = new { CoreUrl = "http://127.0.0.1:5000", DataDirectory = agentData, EnrollmentTokenFile = Path.Combine(root, "arbitrary-file") } }),
            "{\"Agent\":{\"DataDirectory\":\"relative\",\"CoreUrl\":\"http://127.0.0.1:5000\"}}"
        })
        {
            File.WriteAllText(path, malformed);
            Reject(() => AgentHost.CreateBuilder(["--config", path]), "Agent accepted an unsafe pilot configuration.");
        }

        File.WriteAllText(path, validAgent);
        Reject(() => AgentHost.CreateBuilder(["--config", "relative.json"]), "Agent accepted a relative pilot configuration path.");
        Reject(() => AgentHost.CreateBuilder(["--config", path, "--Agent:CoreUrl", "http://192.0.2.1"]), "Pilot arguments overrode configuration.");
        Reject(() => AgentHost.CreateBuilder(["--config", path, "--config", path]), "Duplicate config arguments were accepted.");
        Reject(() => AgentHost.CreateBuilder(["--config=" + path]), "An unsupported config argument was accepted.");

        var originalToken = Environment.GetEnvironmentVariable("Agent__EnrollmentToken");
        try
        {
            Environment.SetEnvironmentVariable("Agent__EnrollmentToken", "Test-Only-Sensitive");
            Reject(() => AgentHost.CreateBuilder(["--config", path]), "Ambient enrollment tokens were accepted in pilot mode.");
        }
        finally { Environment.SetEnvironmentVariable("Agent__EnrollmentToken", originalToken); }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
            Reject(() => AgentHost.CreateBuilder(["--config", path]), "A writable pilot configuration was accepted.");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var link = Path.Combine(root, "config-link.json");
            File.CreateSymbolicLink(link, path);
            Reject(() => AgentHost.CreateBuilder(["--config", link]), "A linked pilot configuration was accepted.");
            File.Delete(link);
            var directoryLink = Path.Combine(root, "data-link");
            Directory.CreateSymbolicLink(directoryLink, root);
            File.WriteAllText(path, JsonSerializer.Serialize(new { Agent = new { CoreUrl = "http://127.0.0.1:5000", DataDirectory = Path.Combine(directoryLink, "data") } }));
            Reject(() => AgentHost.CreateBuilder(["--config", path]), "Linked pilot data ancestry was accepted.");
            Directory.Delete(directoryLink);
        }
    }

    private static async Task VerifyTokenValidationAsync(string root)
    {
        var directory = Path.Combine(root, "token-validation");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "pilot-enrollment-token");
        var config = Path.Combine(root, "token-validation.json");
        File.WriteAllText(config, JsonSerializer.Serialize(new { Agent = new
        {
            CoreUrl = "http://127.0.0.1:5000", DataDirectory = directory, EnrollmentTokenFile = path
        } }));
        var options = AgentOptions.FromConfiguration(AgentHost.CreateBuilder(["--config", config]).Configuration);
        using var handler = new CountingEnrollmentHandler();
        using var http = new HttpClient(handler);
        var client = new AgentEnrollmentClient(options, http);
        foreach (var invalid in new[] { "", "not-a-token", new string('F', 63), new string('G', 64), new string('F', 129), new string('F', 64) + "\n" + new string('E', 64) })
        {
            WritePrivateToken(path, invalid);
            await RejectAsync(() => client.EnrollAsync(Guid.NewGuid()), "Agent read an invalid enrollment handoff.");
            Check(File.Exists(path), "A rejected enrollment handoff was deleted.");
        }
        File.Delete(path);
        await RejectAsync(() => client.EnrollAsync(Guid.NewGuid()), "Agent ignored a missing enrollment handoff.");
        Check(handler.Requests == 0, "An invalid enrollment handoff reached the network.");

        if (!OperatingSystem.IsWindows())
        {
            WritePrivateToken(path, new string('F', 64));
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
            await RejectAsync(() => client.EnrollAsync(Guid.NewGuid()), "Agent accepted a readable enrollment handoff.");
            File.Delete(path);
            var source = Path.Combine(root, "private-token-source");
            WritePrivateToken(source, new string('F', 64));
            File.CreateSymbolicLink(path, source);
            await RejectAsync(() => client.EnrollAsync(Guid.NewGuid()), "Agent accepted a linked enrollment handoff.");
            Check(File.Exists(source), "A linked enrollment handoff changed its target.");
            File.Delete(path);
        }
        else
        {
            WritePrivateToken(path, new string('F', 64));
            MakeWindowsFilePublic(path);
            await RejectAsync(() => client.EnrollAsync(Guid.NewGuid()), "Agent accepted a public Windows enrollment handoff.");
        }

        WritePrivateToken(path, new string('F', 64));
        await client.EnrollAsync(Guid.NewGuid());
        Check(handler.Requests == 1 && File.Exists(path), "A rejected Core enrollment consumed the local handoff.");
    }

    private static async Task VerifyInstallerHostFlowAsync(string root)
    {
        var coreDirectory = Path.Combine(root, "core");
        var agentDirectory = Path.Combine(root, "agent");
        var config = Path.Combine(root, "core.json");
        var agentConfig = Path.Combine(root, "agent.json");
        var tokenPath = Path.Combine(agentDirectory, "pilot-enrollment-token");
        var receiptPath = Path.Combine(agentDirectory, "endpoint-id");
        File.WriteAllText(config, JsonSerializer.Serialize(new { urls = "http://127.0.0.1:5000", SentinelAI = new { DataDirectory = coreDirectory } }));
        var names = new[] { "SENTINELAI_BOOTSTRAP_USERNAME", "SENTINELAI_BOOTSTRAP_PASSWORD", "SentinelAI__DataDirectory", "Agent__CoreUrl", "Agent__DataDirectory", "Agent__EnrollmentToken", "ASPNETCORE_URLS" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        var username = "pilot-test-" + Guid.NewGuid().ToString("N");
        var password = "Test-Only-" + Guid.NewGuid().ToString("N") + "!";
        try
        {
            Environment.SetEnvironmentVariable(names[0], username);
            Environment.SetEnvironmentVariable(names[1], password);
            Environment.SetEnvironmentVariable(names[2], Path.Combine(root, "wrong-core"));
            Environment.SetEnvironmentVariable(names[3], "http://192.0.2.1:5000");
            Environment.SetEnvironmentVariable(names[4], Path.Combine(root, "wrong-agent"));
            Environment.SetEnvironmentVariable(names[5], null);
            Environment.SetEnvironmentVariable(names[6], "http://0.0.0.0:5000");

            await using var core = CoreHost.Build(["--config", config]);
            Check(core.Configuration["urls"] == "http://127.0.0.1:5000", "Ambient URLs changed the pilot listener.");
            Check(core.Services.GetRequiredService<AdminStore>().DatabasePath == Path.Combine(coreDirectory, "sentinelai.db"), "Ambient state changed the pilot database path.");
            core.Urls.Clear();
            core.Urls.Add("http://127.0.0.1:0");
            await core.StartAsync();
            try
            {
                var origin = core.Urls.Single();
                using var admin = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(origin) };
                using var login = await admin.PostAsJsonAsync("/api/auth/login", new { username, password });
                Check(login.StatusCode == HttpStatusCode.OK, "Pilot bootstrap administrator could not sign in.");
                using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
                admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.RootElement.GetProperty("accessToken").GetString());
                using var issue = await admin.PostAsync("/api/admin/enrollment-tokens", null);
                Check(issue.StatusCode == HttpStatusCode.OK, "Pilot administrator could not issue enrollment.");
                var token = await issue.Content.ReadFromJsonAsync<EnrollmentTokenResponse>() ?? throw new Exception("No enrollment token.");
                Directory.CreateDirectory(agentDirectory);
                WritePrivateToken(tokenPath, token.Token);
                File.WriteAllText(agentConfig, JsonSerializer.Serialize(new { Agent = new
                {
                    CoreUrl = origin, DataDirectory = agentDirectory, EnrollmentTokenFile = tokenPath,
                    HeartbeatInterval = "00:00:00.100", RetryDelay = "00:00:00.050", MaxRetryDelay = "00:00:00.200"
                } }));

                var logs = new CapturingLoggerProvider();
                Guid installationId;
                EnrollmentState state;
                var builder = AgentHost.CreateBuilder(["--config", agentConfig]);
                builder.Logging.ClearProviders();
                builder.Logging.AddProvider(logs);
                using (var agent = builder.Build())
                {
                    var verificationStartedUtc = DateTimeOffset.UtcNow;
                    await agent.StartAsync();
                    try
                    {
                        await WaitAsync(() => File.Exists(Path.Combine(agentDirectory, "installation-id")), "Pilot Agent did not create its identity.");
                        installationId = Guid.Parse(await File.ReadAllTextAsync(Path.Combine(agentDirectory, "installation-id")));
                        EnrollmentState? observed = null;
                        await WaitAsync(async () => (observed = await agent.Services.GetRequiredService<EnrollmentStateStore>().LoadAsync(installationId)) is not null,
                            "Pilot Agent did not save enrollment.");
                        state = observed!;
                        await WaitAsync(() => !File.Exists(tokenPath) && File.Exists(receiptPath), "Pilot Agent retained its token or omitted its endpoint receipt.");
                        Check(Guid.Parse(await File.ReadAllTextAsync(receiptPath)) == state.EndpointId, "Pilot endpoint receipt disagrees with enrollment.");
                        Check(state.CoreInstallationId == token.CoreInstallationId && state.OrganizationId == token.OrganizationId, "Pilot enrollment identity disagrees with Core.");
                        var savedBytes = await File.ReadAllBytesAsync(Path.Combine(agentDirectory, "enrollment-state"));
                        Check(savedBytes.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes(token.Token)) < 0, "Pilot enrollment persisted the one-use token.");
                        if (OperatingSystem.IsWindows())
                            Check(savedBytes.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes(state.AgentCredential)) < 0, "Pilot Windows enrollment omitted DPAPI protection.");
                        await WaitAsync(async () => (await core.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))?.EnrollmentStatus == DeviceEnrollmentStatus.Enrolled,
                            "Pilot Core did not receive enrolled heartbeat.");
                        await WaitAsync(async () => await core.Services.GetRequiredService<InventoryStore>().FindLatestAsync(state.EndpointId) is not null,
                            "Pilot Core did not receive inventory.");
                        using var devices = await admin.GetAsync("/api/admin/devices");
                        using var deviceJson = JsonDocument.Parse(await devices.Content.ReadAsStringAsync());
                        Check(devices.StatusCode == HttpStatusCode.OK && deviceJson.RootElement.EnumerateArray().Any(device => device.GetProperty("endpointId").GetGuid() == state.EndpointId),
                            "Pilot endpoint is missing from the dashboard Devices API.");
                        Check(!logs.Text.Contains(token.Token, StringComparison.Ordinal) && !logs.Text.Contains(password, StringComparison.Ordinal) && !logs.Text.Contains(state.AgentCredential, StringComparison.Ordinal),
                            "Pilot Agent logs exposed a secret.");
                        await VerifyPowerShellWorkflowAsync(origin, agentDirectory, verificationStartedUtc,
                            state.EndpointId, username, password, token.Token, state.AgentCredential);
                    }
                    finally { await agent.StopAsync(); }
                }

                var lastSeen = (await core.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))!.LastSeenUtc;
                File.Delete(receiptPath);
                // Recover the crash window after DPAPI state saved but before handoff removal.
                WritePrivateToken(tokenPath, token.Token);
                using (var restarted = AgentHost.Build(["--config", agentConfig]))
                {
                    await restarted.StartAsync();
                    try
                    {
                        await WaitAsync(() => File.Exists(receiptPath) && !File.Exists(tokenPath), "Restart did not reconstruct receipt and remove stale handoff.");
                        Check(Guid.Parse(await File.ReadAllTextAsync(receiptPath)) == state.EndpointId, "Restart changed the receipt identity.");
                        await WaitAsync(async () => (await core.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))?.LastSeenUtc > lastSeen,
                            "Pilot Agent could not restart with preserved enrollment.");
                    }
                    finally { await restarted.StopAsync(); }
                }
                lastSeen = (await core.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))!.LastSeenUtc;
                using (var withoutHandoff = AgentHost.Build(["--config", agentConfig]))
                {
                    await withoutHandoff.StartAsync();
                    try
                    {
                        await WaitAsync(async () => (await core.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))?.LastSeenUtc > lastSeen,
                            "An enrolled pilot Agent required the removed handoff to restart.");
                        Check(!File.Exists(tokenPath), "Restart recreated the enrollment secret handoff.");
                    }
                    finally { await withoutHandoff.StopAsync(); }
                }
                Check(!Directory.Exists(Path.Combine(root, "wrong-core")) && !Directory.Exists(Path.Combine(root, "wrong-agent")), "Pilot hosts wrote ambient state directories.");
            }
            finally { await core.StopAsync(); }
        }
        finally { foreach (var name in names) Environment.SetEnvironmentVariable(name, previous[name]); }
    }

    private static async Task VerifyPowerShellWorkflowAsync(string coreUrl, string agentDirectory,
        DateTimeOffset sinceUtc, Guid endpointId, string username, params string[] secrets)
    {
        var executable = File.Exists("/workspace/.powershell/bin/pwsh") ? "/workspace/.powershell/bin/pwsh" :
            (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator)
                .Select(directory => Path.Combine(directory, OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh"))
                .FirstOrDefault(File.Exists);
        if (executable is null)
        {
            Console.WriteLine("PowerShell pilot verification integration skipped: pwsh is unavailable.");
            return;
        }

        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null && !File.Exists(Path.Combine(repository.FullName, "SentinelAI.sln")))
            repository = repository.Parent;
        if (repository is null) throw new Exception("Pilot integration could not find the repository.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = repository.FullName
        };
        foreach (var argument in new[]
        {
            "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            Path.Combine(repository.FullName, "tests", "pilot", "Verify.Integration.ps1"),
            "-CoreUrl", coreUrl, "-AgentDataDirectory", agentDirectory,
            "-SinceUtc", sinceUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
        }) start.ArgumentList.Add(argument);
        start.Environment["SENTINELAI_PILOT_TEST_USERNAME"] = username;
        start.Environment["SENTINELAI_PILOT_TEST_PASSWORD"] = secrets[0];
        using var process = Process.Start(start) ?? throw new Exception("Pilot integration could not start PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw new Exception("PowerShell pilot verification exceeded its test deadline.");
        }
        var output = await outputTask;
        var error = await errorTask;
        Check(!secrets.Any(secret => output.Contains(secret, StringComparison.Ordinal) || error.Contains(secret, StringComparison.Ordinal)),
            "PowerShell pilot verification exposed a synthetic secret.");
        Check(process.ExitCode == 0, "The actual PowerShell pilot verifier rejected the live Core and Agent.");
        using var result = JsonDocument.Parse(output);
        Check(result.RootElement.GetProperty("EndpointId").GetGuid() == endpointId,
            "PowerShell pilot verification identified the wrong endpoint.");
        Check(result.RootElement.GetProperty("LastSeenUtc").GetDateTimeOffset() >= sinceUtc &&
              result.RootElement.GetProperty("InventoryCollectedUtc").GetDateTimeOffset() >= sinceUtc,
            "PowerShell pilot verification accepted stale heartbeat or inventory.");
        Check(result.RootElement.GetProperty("DashboardUrl").GetString() == new Uri(coreUrl).AbsoluteUri,
            "PowerShell pilot verification returned an unexpected dashboard origin.");
    }

    private static void WritePrivateToken(string path, string value)
    {
        File.WriteAllText(path, value);
        if (OperatingSystem.IsWindows()) RestrictWindowsFile(path);
        else File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictWindowsFile(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        using var identity = WindowsIdentity.GetCurrent();
        foreach (var sid in new[] { identity.User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void MakeWindowsFilePublic(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadData, AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    private static async Task WaitAsync(Func<Task<bool>> predicate, string message)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (await predicate()) { assertions++; return; }
            await Task.Delay(25);
        }
        throw new Exception(message);
    }
    private static Task WaitAsync(Func<bool> predicate, string message) => WaitAsync(() => Task.FromResult(predicate()), message);
    private static void Reject(Action action, string message)
    {
        try { action(); }
        catch (Exception exception) when (exception is InvalidOperationException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            Check(!exception.ToString().Contains("Test-Only-Sensitive", StringComparison.Ordinal), "A configuration error exposed a secret.");
            assertions++;
            return;
        }
        throw new Exception(message);
    }
    private static async Task RejectAsync(Func<Task> action, string message)
    {
        try { await action(); }
        catch (Exception exception) when (exception is InvalidOperationException or InvalidDataException or IOException or UnauthorizedAccessException) { assertions++; return; }
        throw new Exception(message);
    }
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); assertions++; }

    private sealed class CountingEnrollmentHandler : HttpMessageHandler
    {
        public int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        }
    }
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> messages = new();
        public string Text => string.Join("\n", messages);
        public ILogger CreateLogger(string categoryName) => new Logger(messages);
        public void Dispose() { }
        private sealed class Logger(System.Collections.Concurrent.ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception) + (exception?.ToString() ?? string.Empty));
        }
    }
}
