using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class CoreServiceHostingTests
{
    private static int assertions;

    public static async Task RunAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-core-service-tests-{Guid.NewGuid():N}");
        var variables = new[] { "SENTINELAI_BOOTSTRAP_USERNAME", "SENTINELAI_BOOTSTRAP_PASSWORD", "SentinelAI__DataDirectory", "ASPNETCORE_URLS" };
        var original = variables.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        Directory.CreateDirectory(root);
        try
        {
            VerifyStartupPolicy();
            Environment.SetEnvironmentVariable(variables[0], null);
            Environment.SetEnvironmentVariable(variables[1], null);
            await VerifyUninitializedServiceAsync(root);
            await VerifyLifecycleAndPersistenceAsync(root);
            Console.WriteLine($"Core service hosting tests passed ({assertions} assertions).");
        }
        finally
        {
            foreach (var variable in variables)
                Environment.SetEnvironmentVariable(variable, original[variable]);
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static void VerifyStartupPolicy()
    {
        const string sensitive = "Test-Only-Sensitive-Service-Configuration";
        CoreServiceHosting.ValidateStartup(false, false, sensitive, sensitive);
        Check(true, "Console development bootstrap must remain supported.");
        CoreServiceHosting.ValidateStartup(true, true, null, null);
        Check(CoreServiceHosting.ServiceName == "SentinelAICore", "Core's service name differs from the installer contract.");
        foreach (var (username, password) in new[] { (sensitive, (string?)null), ((string?)null, sensitive), (sensitive, sensitive), (" ", (string?)null) })
        {
            Reject(() => CoreServiceHosting.ValidateStartup(true, true, username, password), "The service accepted ambient bootstrap credentials.");
        }
        Reject(() => CoreServiceHosting.ValidateStartup(true, false, null, null), "The service accepted profile-default configuration.");
        Reject(() => { using var app = CoreHost.Build([], isWindowsService: true); }, "Service hosting accepted missing --config.");
        Reject(() => { using var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + sensitive], isWindowsService: true); }, "Service hosting accepted a command-line configuration override.");
    }

    private static async Task VerifyUninitializedServiceAsync(string root)
    {
        var data = Path.Combine(root, "uninitialized-data");
        var config = WriteConfiguration(root, "uninitialized.json", data);
        await using (var app = Build(config, service: true, new CapturedLogs()))
        {
            await RejectAsync(() => app.StartAsync(), "A service created a new administrator without local setup.");
            Check(!Directory.Exists(data), "Rejected first service startup created a new data directory.");
        }

        Directory.CreateDirectory(data);
        var database = Path.Combine(data, "sentinelai.db");
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE Administrators (Username TEXT PRIMARY KEY COLLATE NOCASE, PasswordHash TEXT NOT NULL);";
            await command.ExecuteNonQueryAsync();
        }
        await using (var app = Build(config, service: true, new CapturedLogs()))
        {
            await RejectAsync(() => app.StartAsync(), "An empty administrator table was bootstrapped by service mode.");
        }
        await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM Administrators;";
            Check(Convert.ToInt64(await command.ExecuteScalarAsync()) == 0, "Refused service startup changed the administrator table.");
            command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='CoreIdentity';";
            Check(Convert.ToInt64(await command.ExecuteScalarAsync()) == 0, "Refused service startup created a new Core identity.");
        }

        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", "Test-Only-Sensitive-Service-Configuration");
        try
        {
            Reject(() => { using var app = Build(config, service: true, new CapturedLogs()); }, "The actual service builder accepted an ambient bootstrap password.");
        }
        finally { Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", null); }
        Reject(() => { using var app = CoreHost.Build(["--config", config, "--urls", "http://0.0.0.0:5000"], isWindowsService: true); }, "Service command-line settings overrode the protected configuration.");
    }

    private static async Task VerifyLifecycleAndPersistenceAsync(string root)
    {
        var data = Path.Combine(root, "persistent-data");
        var config = WriteConfiguration(root, "core.json", data);
        var username = "test-core-service-" + Guid.NewGuid().ToString("N");
        var password = "Test-Only-" + Guid.NewGuid().ToString("N") + "!";
        var logs = new CapturedLogs();
        var installationId = Guid.NewGuid();
        CoreIdentity identity;
        AdminRecord administrator;
        DeviceRecord device;

        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);
        Environment.SetEnvironmentVariable("SentinelAI__DataDirectory", Path.Combine(root, "ambient-wrong-data"));
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://0.0.0.0:5000");

        await using (var app = Build(config, service: false, logs))
        {
            Check(!app.Services.GetRequiredService<CoreHostingMode>().IsWindowsService, "Console hosting was switched into service policy.");
            Check(app.Services.GetRequiredService<IHostLifetime>() is not WindowsServiceLifetime, "A console process selected SCM lifetime.");
            using var client = await StartAsync(app);
            await VerifyHealthAsync(client);
            administrator = (await app.Services.GetRequiredService<AdminStore>().FindByUsernameAsync(username))!;
            Check(administrator is not null && administrator.PasswordHash != password, "Console first-run setup did not create a hashed administrator.");
            identity = await app.Services.GetRequiredService<EnrollmentStore>().GetCoreIdentityAsync();
            using var heartbeat = await client.PostAsJsonAsync("/api/agent/heartbeat", new HeartbeatRequest(installationId));
            Check(heartbeat.StatusCode == HttpStatusCode.OK, "Console Core changed the existing loopback heartbeat contract.");
            device = (await app.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId))!;
            await VerifyLoginAsync(client, username, password, logs);
            await StopAsync(app);
        }

        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", null);
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", null);

        // This exercises real Core storage/API/lifecycle with service policy; the official
        // package activates SCM lifetime only under the actual Windows Service Manager.
        for (var restart = 0; restart < 2; restart++)
        {
            await using var app = Build(config, service: true, logs);
            Check(app.Services.GetRequiredService<CoreHostingMode>().IsWindowsService, "The portable test did not exercise service policy.");
            Check(string.Equals(Path.TrimEndingDirectorySeparator(app.Environment.ContentRootPath),
                Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal),
                "Service content root depends on the SCM working directory.");
            var options = app.Services.GetRequiredService<IOptions<HostOptions>>().Value;
            Check(options.ShutdownTimeout == TimeSpan.FromSeconds(15), "Service shutdown is not bounded by the documented timeout.");
            Check(options.BackgroundServiceExceptionBehavior == BackgroundServiceExceptionBehavior.StopHost, "A fatal background-service failure leaves Core running unpredictably.");
            Check(app.Configuration["urls"] == "http://127.0.0.1:5000", "Ambient URL configuration changed the service listener.");
            Check(app.Services.GetRequiredService<AdminStore>().DatabasePath == Path.Combine(data, "sentinelai.db"), "Ambient configuration changed the service database location.");
            using var client = await StartAsync(app);
            await VerifyHealthAsync(client);
            Check(await app.Services.GetRequiredService<EnrollmentStore>().GetCoreIdentityAsync() == identity, "Service restart changed the Core or organization identity.");
            Check(await app.Services.GetRequiredService<AdminStore>().FindByUsernameAsync(username) == administrator, "Service restart changed the persisted administrator or hash.");
            Check(await app.Services.GetRequiredService<DeviceStore>().FindByInstallationIdAsync(installationId) == device, "Service restart lost existing SQLite endpoint state.");
            await VerifyLoginAsync(client, username, password, logs);
            await StopAsync(app);
        }

        Check(!Directory.Exists(Path.Combine(root, "ambient-wrong-data")), "An ambient profile data directory was created.");
        Check(logs.Messages.All(message => !message.Contains(username, StringComparison.Ordinal) && !message.Contains(password, StringComparison.Ordinal)), "Core startup/API/shutdown logs contain bootstrap credentials.");
    }

    private static WebApplication Build(string config, bool service, CapturedLogs logs) =>
        CoreHost.Build(["--config", config], service, builder =>
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logs);
        });

    private static string WriteConfiguration(string root, string name, string data)
    {
        var path = Path.Combine(root, name);
        File.WriteAllText(path, JsonSerializer.Serialize(new { urls = "http://127.0.0.1:5000", SentinelAI = new { DataDirectory = data } }));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Check(app.Lifetime.ApplicationStarted.IsCancellationRequested && app.Urls.Single().StartsWith("http://127.0.0.1:", StringComparison.Ordinal), "Core did not start on an ephemeral loopback listener.");
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()),
            Timeout = TimeSpan.FromSeconds(5)
        };
    }

    private static async Task StopAsync(WebApplication app)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await app.StopAsync(deadline.Token);
        Check(app.Lifetime.ApplicationStopping.IsCancellationRequested && app.Lifetime.ApplicationStopped.IsCancellationRequested, "Core stop did not complete its graceful application lifetime.");
    }

    private static async Task VerifyHealthAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/health");
        Check(response.StatusCode == HttpStatusCode.OK && await response.Content.ReadAsStringAsync() == "{\"status\":\"healthy\"}", "Core changed the existing public health contract.");
        using var anonymous = await client.GetAsync("/api/admin/me");
        Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Service hosting bypassed administrator authentication.");
    }

    private static async Task VerifyLoginAsync(HttpClient client, string username, string password, CapturedLogs logs)
    {
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(login.StatusCode == HttpStatusCode.OK, "The persisted administrator could not log in after a service-policy restart.");
        using var json = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var token = json.RootElement.GetProperty("accessToken").GetString()!;
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var me = await client.SendAsync(request);
        Check(me.StatusCode == HttpStatusCode.OK, "Service-policy Core rejected a newly authenticated administrator.");
        Check(logs.Messages.All(message => !message.Contains(token, StringComparison.Ordinal)), "The administrator access token appeared in host logs.");
    }

    private static void Reject(Action action, string message)
    {
        try { action(); }
        catch (InvalidOperationException exception)
        {
            Check(!exception.ToString().Contains("Test-Only-Sensitive", StringComparison.Ordinal), "A service policy error revealed sensitive input.");
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static async Task RejectAsync(Func<Task> action, string message)
    {
        try { await action().WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (InvalidOperationException exception)
        {
            Check(exception.Message.Contains("local administrator", StringComparison.Ordinal), "The uninitialized service failed for an unrelated reason.");
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class CapturedLogs : ILoggerProvider
    {
        internal ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Logger(Messages);
        public void Dispose() { }

        private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }
}
