using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

/// <summary>The installation language: public to read, administrators change it, it survives restarts and Core writes its texts in it.</summary>
internal static class LanguageApiTests
{
    public static async Task VerifyAsync(string username, string password)
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-language-tests-{Guid.NewGuid():N}");
        try
        {
            string[] arguments = [$"--SentinelAI:DataDirectory={Path.Combine(root, "data")}"];
            await using (var app = CoreHost.Build(arguments))
            {
                using var client = await StartAsync(app);
                try
                {
                    Check(await LanguageAsync(client) == "en", "A new installation was not in English.");
                    using (var anonymous = await client.PutAsync("/api/admin/settings/language", Json("{\"language\":\"pl\"}")))
                        Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "The language changed without a session.");
                    var token = await LoginAsync(client, username, password);
                    foreach (var body in new[] { "{\"language\":\"de\"}", "{}", "{\"language\":\"PL\"}" })
                        Check(await PutAsync(client, token, body) == HttpStatusCode.BadRequest, "An unknown language was accepted: " + body);
                    Check(await PutAsync(client, token, "{\"language\":\"pl\"}") == HttpStatusCode.OK && await LanguageAsync(client) == "pl",
                        "An administrator could not choose Polish.");

                    // Core writes its own texts in the installation language.
                    var endpointId = await EnrollAsync(app);
                    using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/devices/{endpointId:D}/risk");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    using var response = await client.SendAsync(request);
                    using var risk = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    var caution = risk.RootElement.GetProperty("coverage").GetProperty("caution").GetString()!;
                    Check(caution.StartsWith("Pokrycie obejmuje tylko 13 obsługiwanych reguł konfiguracji Windows.", StringComparison.Ordinal) &&
                          caution.Contains("Komputer nie zgłasza telemetrii", StringComparison.Ordinal), "The coverage caution was not written in Polish: " + caution);
                }
                finally
                {
                    await app.StopAsync();
                }
            }

            // The administrator's choice survives a restart and outlasts the language Setup configured.
            await using (var app = CoreHost.Build([.. arguments, "--SentinelAI:Language=en"]))
            {
                using var client = await StartAsync(app);
                try { Check(await LanguageAsync(client) == "pl", "The chosen language was lost across a restart."); }
                finally { await app.StopAsync(); }
            }

            // Setup's choice is the default of a new installation; anything but en or pl is refused at start.
            await using (var app = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "polish")}", "--SentinelAI:Language=pl"]))
            {
                using var client = await StartAsync(app);
                try { Check(await LanguageAsync(client) == "pl", "The language Setup configured was not used."); }
                finally { await app.StopAsync(); }
            }

            try
            {
                await using var refused = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "other")}", "--SentinelAI:Language=de"]);
                Check(false, "Core started with an unknown configured language.");
            }
            catch (InvalidOperationException) { }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }

        Console.WriteLine("Language API tests passed (public read, administrator change, refusals, restart, Setup default, Polish Core texts).");
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static async Task<string> LanguageAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/language");
        Check(response.StatusCode == HttpStatusCode.OK, "The installation language could not be read anonymously.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Check(json.RootElement.EnumerateObject().Count() == 1, "The language answer carried more than the language.");
        return json.RootElement.GetProperty("language").GetString()!;
    }

    private static async Task<HttpStatusCode> PutAsync(HttpClient client, string token, string body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, "/api/admin/settings/language") { Content = Json(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30) };
    }

    private static async Task<Guid> EnrollAsync(WebApplication app)
    {
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrollment = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        return (enrollment.Response ?? throw new InvalidOperationException("A synthetic endpoint could not enroll.")).EndpointId;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "The language test administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
