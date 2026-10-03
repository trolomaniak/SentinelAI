using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using SentinelAI.Core;

internal static class DesktopAuthenticationTests
{
    private static int assertions;

    public static async Task RunAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-desktop-auth-{Guid.NewGuid():N}");
        var data = Path.Combine(root, "data");
        var config = Path.Combine(root, "core.json");
        var username = " desktop-admin ";
        var password = "Desktop-Only-" + Guid.NewGuid().ToString("N");
        var otherPassword = "Other-Desktop-" + Guid.NewGuid().ToString("N");
        var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");

        Directory.CreateDirectory(root);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        await File.WriteAllTextAsync(config, JsonSerializer.Serialize(new
        {
            urls = "http://127.0.0.1:5000",
            SentinelAI = new { DataDirectory = data }
        }));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(config, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        try
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", null);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", null);
            var stateArgs = new[] { "--administrator-state", "--config", config };
            var initArgs = new[] { "--initialize-administrator", "--config", config };
            Check(AdministratorSetupCommand.IsSetupCommand(stateArgs) &&
                  AdministratorSetupCommand.IsSetupCommand(initArgs) &&
                  !AdministratorSetupCommand.IsSetupCommand(["--config", config]),
                "The one-shot setup command parser selected the wrong entry point.");

            var missing = await CallAsync(stateArgs);
            Check(missing is (0, "required") && !Directory.Exists(data),
                "A read-only setup-state check created or adopted missing storage.");

            var validPayload = JsonSerializer.Serialize(new { username, password });
            foreach (var payload in new[]
            {
                "", "{broken", "{\"username\":\"x\",\"password\":\"short\"}",
                "{\"username\":\"x\",\"password\":\"Desktop-Only-Password\",\"username\":\"y\"}",
                "{\"username\":\"x\",\"password\":\"Desktop-Only-Password\",\"unexpected\":true}",
                JsonSerializer.Serialize(new { username = new string('x', 129), password }),
                JsonSerializer.Serialize(new { username = "x", password = new string('x', 1025) }),
                new string('x', 16 * 1024 + 1)
            })
            {
                Check(await CallAsync(initArgs, payload) is (1, "invalid-input"),
                    "Malformed or oversized setup input was accepted.");
            }
            Check(!Directory.Exists(data), "Invalid setup input created administrator storage.");
            Check(await CallAsync(initArgs, validPayload, redirected: false) is (1, "invalid-input"),
                "Administrator initialization accepted an interactive stdin source.");
            Check(await CallAsync(["--initialize-administrator", "--config", config, "extra"], validPayload)
                  is (1, "invalid-input"), "Administrator initialization accepted extra arguments.");
            Check(await CallAsync(["--administrator-other", "--config", config]) is (1, "invalid-input"),
                "An unknown administrator command was accepted.");
            Check(await CallAsync(["--config", config, "--administrator-state"]) is (1, "invalid-input") &&
                  AdministratorSetupCommand.IsSetupCommand(["--config", config, "--administrator-state"]),
                "An out-of-order administrator command escaped the one-shot parser.");
            Check(await CallAsync(["--administrator-state", "--config", Path.Combine(root, "missing.json")])
                  is (1, "unavailable"), "A missing protected configuration exposed setup details.");
            Check(await CallAsync(initArgs, validPayload, service: true) is (1, "unavailable"),
                "An SCM-hosted process accepted administrator setup.");
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", "Ambient-Should-Be-Rejected");
            Check(await CallAsync(stateArgs) is (1, "unavailable") &&
                  await CallAsync(initArgs, validPayload) is (1, "unavailable"),
                "A one-shot setup command accepted ambient bootstrap credentials.");
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", null);
            Check(!Directory.Exists(data), "A rejected one-shot command created storage.");

            Directory.CreateDirectory(data);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var database = Path.Combine(data, "sentinelai.db");
            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE Unrelated (Id INTEGER);";
                await command.ExecuteNonQueryAsync();
            }
            SqliteConnection.ClearAllPools();
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(database, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var before = await File.ReadAllBytesAsync(database);
            Check(await CallAsync(stateArgs) is (0, "required") &&
                  (await File.ReadAllBytesAsync(database)).SequenceEqual(before),
                "A missing administrator table was not reported without writes.");

            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE Administrators (Username TEXT PRIMARY KEY COLLATE NOCASE, PasswordHash TEXT NOT NULL);";
                await command.ExecuteNonQueryAsync();
            }
            SqliteConnection.ClearAllPools();
            before = await File.ReadAllBytesAsync(database);
            Check(await CallAsync(stateArgs) is (0, "required") &&
                  (await File.ReadAllBytesAsync(database)).SequenceEqual(before),
                "An empty administrator table was not reported without writes.");

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                           UnixFileMode.GroupRead);
                Check(await CallAsync(stateArgs) is (1, "unavailable") &&
                      (File.GetUnixFileMode(data) & UnixFileMode.GroupRead) != 0,
                    "The read-only state check adopted shared storage.");
                Check(await CallAsync(initArgs, validPayload) is (1, "unavailable") &&
                      (File.GetUnixFileMode(data) & UnixFileMode.GroupRead) != 0,
                    "The initialization command adopted shared storage.");
                File.SetUnixFileMode(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            var corruptData = Path.Combine(root, "corrupt");
            var corruptConfig = Path.Combine(root, "corrupt.json");
            Directory.CreateDirectory(corruptData);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(corruptData, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await File.WriteAllTextAsync(corruptConfig, JsonSerializer.Serialize(new
            {
                urls = "http://127.0.0.1:5000",
                SentinelAI = new { DataDirectory = corruptData }
            }));
            await File.WriteAllBytesAsync(Path.Combine(corruptData, "sentinelai.db"), "not a SQLite database"u8.ToArray());
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(Path.Combine(corruptData, "sentinelai.db"),
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var corruptBefore = await File.ReadAllBytesAsync(Path.Combine(corruptData, "sentinelai.db"));
            Check(await CallAsync(["--administrator-state", "--config", corruptConfig]) is (1, "unavailable") &&
                  await CallAsync(["--initialize-administrator", "--config", corruptConfig], validPayload)
                      is (1, "unavailable") &&
                  (await File.ReadAllBytesAsync(Path.Combine(corruptData, "sentinelai.db"))).SequenceEqual(corruptBefore),
                "Corrupt administrator storage was adopted or modified.");

            var first = CallAsync(initArgs, validPayload);
            var second = CallAsync(initArgs, JsonSerializer.Serialize(new { username = "second-admin", password = otherPassword }));
            var attempts = await Task.WhenAll(first, second);
            Check(attempts.Count(attempt => attempt == (0, "created")) == 1 &&
                  attempts.Count(attempt => attempt == (0, "already-initialized")) == 1,
                "Concurrent setup commands did not serialize first administrator creation.");
            Check(await CallAsync(stateArgs) is (0, "initialized"),
                "The one-shot setup command did not initialize administrator state.");

            string storedUsername;
            string storedHash;
            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT Username, PasswordHash FROM Administrators;";
                await using var reader = await command.ExecuteReaderAsync();
                Check(await reader.ReadAsync(), "The setup command did not persist an administrator.");
                storedUsername = reader.GetString(0);
                storedHash = reader.GetString(1);
                Check(!await reader.ReadAsync(), "The setup race created multiple administrators.");
            }
            Check(storedHash != password && storedHash != otherPassword &&
                  !storedHash.Contains(password, StringComparison.Ordinal) &&
                  !storedHash.Contains(otherPassword, StringComparison.Ordinal),
                "The setup command stored a plaintext password.");
            var third = await CallAsync(initArgs, JsonSerializer.Serialize(new
            {
                username = "replacement-admin", password = "Replacement-Password-12345"
            }));
            Check(third is (0, "already-initialized"), "An existing administrator was not preserved.");
            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT Username, PasswordHash FROM Administrators;";
                await using var reader = await command.ExecuteReaderAsync();
                Check(await reader.ReadAsync() && reader.GetString(0) == storedUsername &&
                      reader.GetString(1) == storedHash && !await reader.ReadAsync(),
                    "Repeated setup replaced or duplicated the existing administrator.");
            }

            await VerifyCoreAuthenticationAsync(config, storedUsername,
                storedUsername == username.Trim() ? password : otherPassword);
            Console.WriteLine($"Desktop authentication tests passed ({assertions} assertions).");
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task VerifyCoreAuthenticationAsync(string config, string username, string password)
    {
        string accessToken;
        await using (var app = CoreHost.Build(["--config", config], isWindowsService: true,
                         configureBeforeAuthentication: host => host.Use(async (context, next) =>
                         {
                             if (context.Request.Headers.ContainsKey("X-Test-Remote"))
                                 context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
                             await next(context);
                         })))
        {
            using var client = await StartAsync(app);
            using (var anonymous = await client.GetAsync("/api/admin/me"))
                Check(anonymous.StatusCode == HttpStatusCode.Unauthorized,
                    "An anonymous desktop session accessed the administrator identity.");

            using var wrong = await client.PostAsJsonAsync("/api/auth/login", new
            {
                username, password = "Wrong-Desktop-Password"
            });
            using var unknown = await client.PostAsJsonAsync("/api/auth/login", new
            {
                username = "unknown-desktop-admin", password
            });
            Check(wrong.StatusCode == HttpStatusCode.Unauthorized &&
                  unknown.StatusCode == HttpStatusCode.Unauthorized &&
                  await wrong.Content.ReadAsStringAsync() == await unknown.Content.ReadAsStringAsync(),
                "Wrong-password and unknown-user login errors differ.");

            foreach (var path in new[] { "/api/auth/login", "/api/auth/login/", "/API/AUTH/LOGIN" })
            {
                using var remote = new HttpRequestMessage(HttpMethod.Post, path);
                remote.Headers.Add("X-Test-Remote", "1");
                remote.Content = new StringContent("{malformed", Encoding.UTF8, "application/json");
                using var blocked = await client.SendAsync(remote);
                Check(blocked.StatusCode == HttpStatusCode.Forbidden &&
                      blocked.Headers.CacheControl?.NoStore == true &&
                      string.IsNullOrEmpty(await blocked.Content.ReadAsStringAsync()),
                    "Remote plaintext login reached JSON body binding or exposed details.");
            }

            using (var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password }))
            {
                Check(login.StatusCode == HttpStatusCode.OK && login.Headers.CacheControl?.NoStore == true,
                    "A valid local administrator could not sign in safely.");
                using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
                accessToken = body.RootElement.GetProperty("accessToken").GetString() ?? "";
                Check(accessToken.Length > 0 && body.RootElement.GetProperty("expiresIn").GetInt32() == 900,
                    "Desktop authentication did not receive the short-lived Core bearer.");
            }

            using (var me = await GetMeAsync(client, accessToken))
            {
                using var body = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
                Check(me.StatusCode == HttpStatusCode.OK && me.Headers.CacheControl?.NoStore == true &&
                      body.RootElement.GetProperty("username").GetString() == username &&
                      body.RootElement.GetProperty("role").GetString() == "administrator",
                    "Core did not authoritatively verify the desktop bearer.");
            }
            using (var remote = new HttpRequestMessage(HttpMethod.Get, "/api/admin/me"))
            {
                remote.Headers.Add("X-Test-Remote", "1");
                remote.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                using var blocked = await client.SendAsync(remote);
                Check(blocked.StatusCode == HttpStatusCode.Forbidden &&
                      blocked.Headers.CacheControl?.NoStore == true,
                    "Core accepted a desktop bearer over remote plaintext HTTP.");
            }
        }

        await using (var restarted = CoreHost.Build(["--config", config], isWindowsService: true))
        {
            using var client = await StartAsync(restarted);
            using var expired = await GetMeAsync(client, accessToken);
            Check(expired.StatusCode == HttpStatusCode.Unauthorized,
                "A desktop bearer survived Core restart.");
            using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
            Check(login.StatusCode == HttpStatusCode.OK,
                "An existing installation could not sign in after Core restart.");
        }
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(app.Urls.Single()),
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    private static async Task<HttpResponseMessage> GetMeAsync(HttpClient client, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await client.SendAsync(request);
    }

    private static async Task<(int ExitCode, string Status)> CallAsync(string[] arguments,
        string payload = "", bool redirected = true, bool service = false)
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(payload));
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        var exitCode = await AdministratorSetupCommand.RunAsync(arguments, input, output, service, redirected);
        var text = output.ToString();
        using var response = JsonDocument.Parse(text);
        var hasStatus = response.RootElement.TryGetProperty("status", out var status);
        Check(response.RootElement.ValueKind == JsonValueKind.Object &&
              response.RootElement.EnumerateObject().Count() == 1 &&
              hasStatus &&
              (payload.Length == 0 || !text.Contains(payload, StringComparison.Ordinal)),
            "A setup command emitted anything beyond its generic status.");
        return (exitCode, status.GetString() ?? "");
    }

    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new Exception(message);
    }
}
