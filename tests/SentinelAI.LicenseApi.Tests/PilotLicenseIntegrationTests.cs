using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Licensing;

/// <summary>
/// MVP-3 pilot license through real Core with a controlled clock and a development key generated per run:
/// active, warning, ended, extension, clock rollback, migration of an existing database and damaged storage.
/// </summary>
internal static class PilotLicenseIntegrationTests
{
    private const string PilotPath = "/api/admin/license/pilot";
    private const string KeyId = "development-pilot";
    private static int _assertions;

    public static async Task RunAsync()
    {
        VerifyOptions();
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-pilot-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var dataDirectory = Path.Combine(directory, "core-data");
        var pilotDirectory = Path.Combine(directory, "pilot-license");
        var username = $"pilot-admin-{Guid.NewGuid():N}";
        var password = $"Development-Test-Only-{Guid.NewGuid():N}!";
        var previousUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var previousPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new SteppingTimeProvider(start);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            Directory.CreateDirectory(Path.Combine(pilotDirectory, "trust"));
            await File.WriteAllTextAsync(Path.Combine(pilotDirectory, "trust", KeyId + ".pem"), signer.ExportSubjectPublicKeyInfoPem());
            await File.WriteAllTextAsync(Path.Combine(pilotDirectory, "contact.json"),
                """{"company":"Example Company","email":"pilot@example.invalid","phone":"+00 000 000 000","website":"https://example.invalid"}""");
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);
            var unavailableArgs = new[] { $"--SentinelAI:DataDirectory={dataDirectory}", $"--SentinelAI:PilotLicense:Directory={Path.Combine(directory, "absent")}" };
            var pilotArgs = new[] { $"--SentinelAI:DataDirectory={dataDirectory}", $"--SentinelAI:PilotLicense:Directory={pilotDirectory}" };
            var expires = start.AddDays(30);
            string databasePath;

            // A build without pilot public keys has no pilot licensing; nothing is stored.
            await using (var core = CoreHost.Build(unavailableArgs, Configure(clock)))
            {
                using var client = await StartAsync(core);
                var token = await LoginAsync(client, username, password);
                var status = await PilotAsync(client, token, "unavailable");
                Check(status.GetProperty("contact").ValueKind == JsonValueKind.Null, "A build without contact details invented them.");
                using (var refused = await PostAsync(client, token, Issue(signer, KeyId, start, expires)))
                    Check(refused.StatusCode == HttpStatusCode.NotFound, "A pilot key was accepted without pilot trust.");
                databasePath = core.Services.GetRequiredService<AdminStore>().DatabasePath;
            }

            await using (var core = CoreHost.Build(pilotArgs, Configure(clock)))
            {
                using var client = await StartAsync(core);
                var token = await LoginAsync(client, username, password);
                foreach (var method in new[] { HttpMethod.Get, HttpMethod.Post })
                {
                    using var anonymous = new HttpRequestMessage(method, PilotPath) { Content = method == HttpMethod.Post ? JsonContent.Create(new { key = "x" }) : null };
                    using var denied = await client.SendAsync(anonymous);
                    Check(denied.StatusCode == HttpStatusCode.Unauthorized, "An anonymous caller reached the pilot license route.");
                }
                var none = await PilotAsync(client, token, "none");
                Check(none.GetProperty("contact").GetProperty("company").GetString() == "Example Company" &&
                      none.GetProperty("contact").GetProperty("email").GetString() == "pilot@example.invalid",
                    "Build-time contact details were not reported.");

                var valid = Issue(signer, KeyId, start, expires);
                foreach (var (key, expected, reason) in new[]
                {
                    ("not-a-key", HttpStatusCode.BadRequest, "malformed"),
                    (Tamper(valid), HttpStatusCode.BadRequest, "tampered"),
                    (Issue(stranger, KeyId, start, expires), HttpStatusCode.BadRequest, "wrong signer"),
                    (Issue(signer, "unknown-pilot", start, expires), HttpStatusCode.BadRequest, "unknown key ID"),
                    (new string('a', 2 * PilotLicenseFormat.MaxKeyLength + 1), HttpStatusCode.BadRequest, "over-length"),
                    (Issue(signer, KeyId, start.AddDays(-31), start.AddDays(-1)), HttpStatusCode.Conflict, "expired")
                })
                {
                    using var response = await PostAsync(client, token, key);
                    Check(response.StatusCode == expected && response.Headers.CacheControl?.NoStore == true, "Pilot key outcome was wrong: " + reason);
                    await PilotAsync(client, token, "none");
                }

                var active = await AcceptAsync(client, token, "  " + valid + "\r\n", "active");
                Check(active.GetProperty("customer").GetString() == "Zażółć Example" &&
                      Timestamp(active, "expiresUtc") == expires && active.GetProperty("daysLeft").GetInt32() == 30,
                    "Active pilot did not report customer, expiry and days left.");
                await using (var stored = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString()))
                {
                    await stored.OpenAsync();
                    using var read = stored.CreateCommand();
                    read.CommandText = "SELECT PilotKey FROM LicenseState;";
                    Check(await read.ExecuteScalarAsync() as string == valid, "The accepted pilot key was not stored trimmed.");
                }
                await LeaseAsync(client, token);

                clock.Advance(TimeSpan.FromDays(23) - TimeSpan.FromSeconds(1));
                token = await LoginAsync(client, username, password);
                var lastActive = await PilotAsync(client, token, "active");
                Check(lastActive.GetProperty("daysLeft").GetInt32() == 8, "Days left did not round up.");
                clock.Advance(TimeSpan.FromSeconds(1));
                token = await LoginAsync(client, username, password);
                var ending = await PilotAsync(client, token, "ending");
                Check(ending.GetProperty("daysLeft").GetInt32() == 7, "The warning did not start seven days before expiry.");
                clock.Advance(TimeSpan.FromDays(7) - TimeSpan.FromSeconds(1));
                token = await LoginAsync(client, username, password);
                Check((await PilotAsync(client, token, "ending")).GetProperty("daysLeft").GetInt32() == 1, "The last second was not still a warning.");
                clock.Advance(TimeSpan.FromSeconds(1));
                var ended = await PilotAsync(client, token, "ended");
                Check(ended.GetProperty("daysLeft").GetInt32() == 0 && ended.GetProperty("customer").GetString() == "Zażółć Example",
                    "Ended pilot lost its details.");
                await LeaseAsync(client, token);
            }

            // Turning the clock back across a restart cannot revive the pilot or admit a key that has expired.
            var rolledBack = new SteppingTimeProvider(start.AddDays(5));
            await using (var core = CoreHost.Build(pilotArgs, Configure(rolledBack)))
            {
                using var client = await StartAsync(core);
                var token = await LoginAsync(client, username, password);
                var ended = await PilotAsync(client, token, "ended");
                Check(Timestamp(ended, "effectiveUtc") >= expires, "Clock rollback moved the pilot's effective time backwards.");
                using (var stale = await PostAsync(client, token, Issue(signer, KeyId, start, start.AddDays(20))))
                    Check(stale.StatusCode == HttpStatusCode.Conflict, "Clock rollback admitted a key that had already expired.");
                Check((await LeaseAsync(client, token)).GetProperty("clockRollbackDetected").GetBoolean(), "Clock rollback was not recorded.");

                // A newer key replaces the ended one: first one that starts later, then an extension from now.
                var effective = Timestamp(ended, "effectiveUtc");
                var scheduledStart = DateTimeOffset.FromUnixTimeSeconds(effective.AddDays(2).ToUnixTimeSeconds());
                var scheduled = await AcceptAsync(client, token, Issue(signer, KeyId, scheduledStart, scheduledStart.AddDays(10), "Later Example"), "scheduled");
                Check(Timestamp(scheduled, "startsUtc") == scheduledStart && scheduled.GetProperty("daysLeft").ValueKind == JsonValueKind.Null,
                    "A scheduled pilot did not report its start.");
                var extensionStart = DateTimeOffset.FromUnixTimeSeconds(effective.ToUnixTimeSeconds());
                var extended = await AcceptAsync(client, token, Issue(signer, KeyId, extensionStart, extensionStart.AddDays(60)), "active");
                Check(extended.GetProperty("daysLeft").GetInt32() == 60, "A newer key did not extend the pilot.");
            }

            // An existing database from before MVP-3 gains the column additively and keeps its license state.
            DateTimeOffset highWater;
            await using (var database = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString()))
            {
                await database.OpenAsync();
                using var read = database.CreateCommand();
                read.CommandText = "SELECT HighWaterUtcTicks FROM LicenseState;";
                highWater = new DateTimeOffset((long)(await read.ExecuteScalarAsync())!, TimeSpan.Zero);
                using var drop = database.CreateCommand();
                drop.CommandText = "ALTER TABLE LicenseState DROP COLUMN PilotKey;";
                await drop.ExecuteNonQueryAsync();
            }
            await using (var core = CoreHost.Build(pilotArgs, Configure(rolledBack)))
            {
                using var client = await StartAsync(core);
                var token = await LoginAsync(client, username, password);
                var migrated = await PilotAsync(client, token, "none");
                Check(Timestamp(migrated, "effectiveUtc") >= highWater, "Migration lost the license clock high-water mark.");
                await SetStoredKeyAsync(databasePath, "damaged.pilot.key");
                await PilotAsync(client, token, "invalid");
                await SetStoredKeyAsync(databasePath, new string('a', PilotLicenseFormat.MaxKeyLength + 1));
                await PilotAsync(client, token, "none");
                await SetStoredKeyAsync(databasePath, Issue(stranger, KeyId, start, start.AddDays(365)));
                await PilotAsync(client, token, "invalid");
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", previousUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", previousPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine($"Pilot license integration tests passed ({_assertions} assertions).");
    }

    private static void VerifyOptions()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-pilot-options-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "trust"));
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(Path.Combine(root, "trust", "dev.pem"), key.ExportSubjectPublicKeyInfoPem());
            var loaded = Load(("Directory", root));
            Check(loaded.Configured && loaded.Contact is null, "Pilot trust without a contact file did not load.");
            Check(!Load(("Directory", Path.Combine(root, "absent"))).Configured, "A missing pilot directory was treated as configured.");
            Rejected(() => Load(("Directory", "relative")), "relative directory");
            Rejected(() => Load(("Directory", root), ("Trust", "x")), "unknown setting");
            File.WriteAllText(Path.Combine(root, "trust", "private.pem"), key.ExportPkcs8PrivateKeyPem());
            Rejected(() => Load(("Directory", root)), "private key in trust");
            File.Delete(Path.Combine(root, "trust", "private.pem"));
            File.WriteAllText(Path.Combine(root, "trust", "notes.txt"), "x");
            Rejected(() => Load(("Directory", root)), "non-PEM trust file");
            File.Delete(Path.Combine(root, "trust", "notes.txt"));
            File.WriteAllText(Path.Combine(root, "contact.json"), "{}");
            Rejected(() => Load(("Directory", root)), "invalid contact file");

            var contact = PilotLicenseOptions.ParseContact("""{"company":"Example","email":"","phone":"","website":""}"""u8);
            Check(contact == new PilotContact("Example", "", "", ""), "A minimal contact was not parsed.");
            foreach (var json in new[]
            {
                """{"company":"","email":"","phone":"","website":""}""",
                """{"company":"Example","email":"","phone":""}""",
                """{"company":"Example","email":"","phone":"","website":"","extra":""}""",
                """{"company":"Example","company":"Again","email":"","phone":"","website":""}""",
                """{"company":"Example","email":1,"phone":"","website":""}""",
                """{"company":"Exa\nmple","email":"","phone":"","website":""}""",
                $$"""{"company":"{{new string('x', PilotLicenseOptions.MaximumContactLength + 1)}}","email":"","phone":"","website":""}""",
                """["Example"]""", "", "{"
            })
            {
                Rejected(() => PilotLicenseOptions.ParseContact(Encoding.UTF8.GetBytes(json)), "invalid contact " + json);
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static PilotLicenseOptions Load(params (string Name, string Value)[] settings) =>
        PilotLicenseOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(
            settings.Select(setting => new KeyValuePair<string, string?>("SentinelAI:PilotLicense:" + setting.Name, setting.Value))).Build());

    private static void Rejected(Action action, string reason)
    {
        try { action(); }
        catch (Exception exception) when (exception is InvalidOperationException or JsonException) { _assertions++; return; }
        throw new Exception("Invalid pilot configuration was accepted: " + reason);
    }

    private static string Issue(ECDsa key, string keyId, DateTimeOffset issued, DateTimeOffset expires, string customer = "Zażółć Example")
    {
        var input = PilotLicenseFormat.CreateSigningInput(new PilotLicenseClaims(customer, issued, expires), keyId);
        return PilotLicenseFormat.Assemble(input, key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private static string Tamper(string key)
    {
        var parts = key.Split('.');
        var payload = Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[1]))).Replace("Example", "Exbmple", StringComparison.Ordinal);
        return parts[0] + "." + Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + "." + parts[2];
    }

    private static string Pad(string value) => value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);

    private static async Task SetStoredKeyAsync(string databasePath, string key)
    {
        await using var database = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());
        await database.OpenAsync();
        using var update = database.CreateCommand();
        update.CommandText = "UPDATE LicenseState SET PilotKey = $key;";
        update.Parameters.AddWithValue("$key", key);
        Check(await update.ExecuteNonQueryAsync() == 1, "The stored pilot key could not be replaced for the test.");
    }

    private static async Task<JsonElement> AcceptAsync(HttpClient client, string token, string key, string state)
    {
        using var response = await PostAsync(client, token, key);
        Check(response.StatusCode == HttpStatusCode.OK, "A valid pilot key was refused for state " + state);
        var status = await ReadAsync(response, state);
        var read = await PilotAsync(client, token, state);
        Check(read.GetRawText() == status.GetRawText(), "Status after entering a key differed from the next read.");
        return status;
    }

    private static async Task<JsonElement> PilotAsync(HttpClient client, string token, string state)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, PilotPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, "Pilot status could not be read.");
        return await ReadAsync(response, state);
    }

    private static async Task<JsonElement> ReadAsync(HttpResponseMessage response, string state)
    {
        Check(response.Headers.CacheControl?.NoStore == true, "Pilot status allowed caching.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var status = json.RootElement.Clone();
        Check(status.GetProperty("state").GetString() == state, $"Pilot state was {status.GetProperty("state").GetString()}, expected {state}.");
        return status;
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string token, string key)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, PilotPath) { Content = JsonContent.Create(new { key }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static async Task<JsonElement> LeaseAsync(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/license");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, "Lease status stopped working with a pilot key.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var status = json.RootElement.Clone();
        var capabilities = status.GetProperty("capabilities");
        Check(new[] { "criticalTelemetryCollection", "localDetectionRules", "criticalAlerts", "recentIncidents", "emergencyExport" }
                .All(property => capabilities.GetProperty(property).GetBoolean()),
            "Pilot license state degraded the local security baseline.");
        Check(status.GetProperty("mode").GetString() == "SAFE_MODE" && !capabilities.GetProperty("premiumFeatures").GetBoolean() &&
              status.GetProperty("enabledFeatures").GetArrayLength() == 0,
            "A pilot key granted lease, premium or cloud features.");
        return status;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic pilot administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(15)
        };
    }

    private static Action<WebApplicationBuilder> Configure(TimeProvider clock) => builder =>
        builder.Services.Replace(ServiceDescriptor.Singleton(clock));

    private static DateTimeOffset Timestamp(JsonElement element, string name) => element.GetProperty(name).GetDateTimeOffset();

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        _assertions++;
    }

    private sealed class SteppingTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        private long _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _timestamp;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration)
        {
            _utcNow = _utcNow.Add(duration);
            _timestamp = checked(_timestamp + duration.Ticks);
        }
    }
}
