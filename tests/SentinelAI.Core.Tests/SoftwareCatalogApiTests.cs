using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.SoftwareCatalog;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class SoftwareCatalogApiTests
{
    private const string Route = "/api/admin/software-catalog";
    private const string ChangeRoute = Route + "/changes";
    private const string AgentRoute = "/api/agent/security-telemetry";
    private const string RemoteHeader = "Synthetic-Remote-Software-Catalog";
    private static readonly InstalledSoftwareItem Primary = new("Żółty Klient %", "1.0", "Zespół Example", "x64");
    private static readonly InstalledSoftwareItem Secondary = Primary with { Version = "2.0-pre+Vendor", Architecture = "x86" };
    private static readonly InstalledSoftwareItem DifferentPublisher = Primary with { Publisher = "Synthetic Other Publisher", Version = null, Architecture = null };
    private static readonly InstalledSoftwareItem Later = new("Synthetic Later Viewer", null);
    private static readonly InstalledSoftwareItem Earlier = new("Synthetic Earlier _ Tool", "2.0", "Synthetic Publisher", "x64");

    internal static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-software-catalog-{Guid.NewGuid():N}");
        try
        {
            await VerifyLiveCatalogAsync(Path.Combine(directory, "live"), username, password);
            await VerifyLegacyCatalogAsync(Path.Combine(directory, "legacy"), username, password, backfill: true);
            await VerifyLegacyCatalogAsync(Path.Combine(directory, "legacy-live"), username, password, backfill: false);
            await VerifyStorageLimitsAsync(Path.Combine(directory, "storage"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }

        Console.WriteLine("Software catalog API tests passed (agent ingest, search, versions, coverage, change history, restart and legacy telemetry, authorization).");
    }

    private static async Task VerifyLiveCatalogAsync(string directory, string username, string password)
    {
        var clock = new TestTime(DateTimeOffset.UtcNow);
        var initialTime = clock.UtcNow.AddMinutes(-10);
        await using var app = Build(directory, clock);
        using var client = await StartAsync(app);
        var token = await LoginAsync(client, username, password);
        var store = app.Services.GetRequiredService<EnrollmentStore>();
        var primary = await EnrollAsync(store);
        var stale = await EnrollAsync(store);
        var unavailable = await EnrollAsync(store);
        await EnrollAsync(store);
        var unknownProduct = new string('f', 64);
        var empty = await ReadAsync<SoftwareCatalogPage>(client, Route, token);
        Check(empty is { Total: 0, Offset: 0, Limit: 25, Coverage: { ActiveEndpoints: 4, MissingEndpoints: 4 } } &&
              empty.Items.Count == 0 && empty.GeneratedUtc == clock.UtcNow, "fresh fleet did not distinguish missing observations");
        await VerifyAccessAsync(client, token, primary, unknownProduct);

        var caseDuplicate = Primary with { Name = "ŻÓŁTY KLIENT %", Publisher = "ZESPÓŁ EXAMPLE" };
        await PostSectionAsync(client, primary, initialTime, Complete(Primary, caseDuplicate, Secondary, DifferentPublisher, Earlier));
        await PostSectionAsync(client, stale, initialTime.AddHours(-5), Complete(Primary));
        await PostSectionAsync(client, unavailable, initialTime, new(TelemetryAvailability.AccessDenied));
        var page = await ReadAsync<SoftwareCatalogPage>(client, Route, token);
        Check(page is { Total: 3, Coverage: { ActiveEndpoints: 4, CompleteEndpoints: 2, PartialEndpoints: 0,
                  UnavailableEndpoints: 1, MissingEndpoints: 1, StaleEndpoints: 1 } },
              "catalog grouped publishers incorrectly or lost coverage and stale reports");
        var product = page.Items.Single(item => string.Equals(item.Publisher, Primary.Publisher, StringComparison.OrdinalIgnoreCase));
        var otherPublisher = page.Items.Single(item => item.Publisher == DifferentPublisher.Publisher);
        var earlier = page.Items.Single(item => item.Name == Earlier.Name);
        Check(product.EndpointCount == 2 && product.VariantCount == 2 && product.ProductId != otherPublisher.ProductId,
              "catalog counted casing duplicates or merged unrelated publishers");
        var other = await ReadAsync<SoftwareInstallationsPage>(client, Installations(otherPublisher.ProductId), token);
        Check(other.Items.Single() is { Version: null, Architecture: null }, "unknown version or architecture became a concrete value");
        var devices = await ReadAsync<SoftwareInstallationsPage>(client, Installations(product.ProductId), token);
        Check(devices is { Total: 3, Offset: 0, Limit: 25 } && devices.ProductId == product.ProductId &&
              devices.Items.Count(item => item.EndpointId == primary.EndpointId && !item.Partial && !item.Stale) == 2 &&
              devices.Items.Single(item => item.Stale) is { CollectedUtc: var at } && at == initialTime.AddHours(-5) &&
              devices.Items.Any(item => item is { Version: "2.0-pre+Vendor", Architecture: "x86" }),
              "installations did not preserve exact co-installed variants, device identity or collection age");
        await VerifyPagesAndSearchAsync(client, token, product.ProductId, page, devices);
        Check((await ReadAsync<SoftwareChangesPage>(client, ChangeRoute, token)).Total == 0,
              "an initial observation invented a change");

        var replaced = Primary with { Version = "2.1-preview" };
        var changedAt = initialTime.AddMinutes(1);
        await PostSectionAsync(client, primary, changedAt, Complete(replaced, DifferentPublisher, Later));
        var changes = await ReadAsync<SoftwareChangesPage>(client, ChangeRoute, token);
        Check(changes.Total == 3 && changes.Items.All(item => item.EndpointId == primary.EndpointId &&
                  item.CollectedUtc == changedAt && item.PreviousCollectedUtc == initialTime),
              "the observation produced the wrong change chronology or endpoint");
        var changed = changes.Items.Single(item => item.ProductId == product.ProductId);
        Check(changed is { Kind: "variantsChanged", BeforeCount: 2, AfterCount: 1 } &&
              changed.Before.Contains(new SoftwareVariant(Primary.Version, Primary.Architecture)) &&
              changed.Before.Contains(new SoftwareVariant(Secondary.Version, Secondary.Architecture)) &&
              changed.After.SequenceEqual(new[] { new SoftwareVariant(replaced.Version, replaced.Architecture) }) &&
              changes.Items.Any(item => item is { Kind: "appeared", BeforeCount: 0, AfterCount: 1 } && item.Name == Later.Name) &&
              changes.Items.Any(item => item is { Kind: "disappeared", BeforeCount: 1, AfterCount: 0 } && item.ProductId == earlier.ProductId),
              "changes misclassified appearance, disappearance or co-installed version replacement");
        Check((await ReadAsync<SoftwareInstallationsPage>(client, Installations(earlier.ProductId), token)).Total == 0 &&
              (await ReadAsync<SoftwareChangesPage>(client, ChangeRoute + "?productId=" + earlier.ProductId, token)).Items.Single().Kind == "disappeared",
              "retained history became unreachable once a product disappeared from the active catalog");
        var otherChangePage = await ReadAsync<SoftwareChangesPage>(client, ChangeRoute + "?offset=1&limit=1", token);
        Check(otherChangePage is { Total: 3, Offset: 1, Limit: 1 } &&
              otherChangePage.Items.Single().ProductId == changes.Items[1].ProductId,
              "change paging did not preserve stable ordering");

        await PostSectionAsync(client, primary, changedAt, Complete());
        await PostSectionAsync(client, primary, changedAt.AddTicks(-1), Complete());
        await PostSectionAsync(client, primary, changedAt.AddTicks(1), new(TelemetryAvailability.Collected, [Primary], 0), HttpStatusCode.BadRequest);
        Check((await ReadAsync<SoftwareCatalogPage>(client, Route, token)).Items.Any(item => item.Name == Later.Name),
              "equal, stale or invalid telemetry replaced the current projection");

        await VerifyIncompleteAsync(client, token, primary, changedAt, product.ProductId, replaced);
        Check((await ReadAsync<SoftwareChangesPage>(client, ChangeRoute, token)).Total == 3,
              "replayed or incomplete reports invented changes");

        var database = app.Services.GetRequiredService<AdminStore>().DatabasePath;
        Check(await ReadEndpointRowsAsync(database, primary.EndpointId) == (1, 1, 1),
              "the retirement fixture lacked a current projection or its raw telemetry");
        Check(await store.RemoveEndpointAsync(primary.EndpointId) == EndpointRemoval.Removed, "synthetic endpoint could not be retired");
        Check(await ReadEndpointRowsAsync(database, primary.EndpointId) == (0, 0, 1),
              "retirement did not physically drop the projection while preserving the raw telemetry");
        await PostSectionAsync(client, primary, changedAt.AddMinutes(10), Complete(Primary), HttpStatusCode.Unauthorized);
        var retiredPage = await ReadAsync<SoftwareCatalogPage>(client, Route, token);
        var retained = await ReadAsync<SoftwareChangesPage>(client, ChangeRoute, token);
        Check(retiredPage is { Total: 1, Coverage: { ActiveEndpoints: 3 } } &&
              retiredPage.Items.Single() is { EndpointCount: 1, VariantCount: 1 } &&
              retained.Total == 3 && retained.Items.All(item => item.EndpointId == primary.EndpointId),
              "retirement kept current rows, created a synthetic change or erased retained observations");

        clock.UtcNow = clock.UtcNow.AddDays(SoftwareCatalogContract.RetentionDays + 1);
        token = await LoginAsync(client, username, password);
        Check((await ReadAsync<SoftwareChangesPage>(client, ChangeRoute, token)).Total == 0,
              "retention exposed expired change observations");
        await app.StopAsync();
    }

    private static async Task VerifyPagesAndSearchAsync(HttpClient client, string token, string productId,
        SoftwareCatalogPage page, SoftwareInstallationsPage devices)
    {
        var search = await ReadAsync<SoftwareCatalogPage>(client, Route + "?q=" + Uri.EscapeDataString("z\u0307o\u0301łTY klient %"), token);
        Check(search.Total == 2 && search.Items.Any(item => item.ProductId == productId) &&
              (await ReadAsync<SoftwareCatalogPage>(client, Route + "?q=%25", token)).Total == 2 &&
              (await ReadAsync<SoftwareCatalogPage>(client, Route + "?q=_", token)).Total == 1 &&
              (await ReadAsync<SoftwareCatalogPage>(client, Route + "?q=" + Uri.EscapeDataString("zesPÓŁ"), token)).Total == 1,
              "search did not match Polish casing, normalized Unicode, or literal punctuation");
        var next = await ReadAsync<SoftwareCatalogPage>(client, Route + "?offset=1&limit=1", token);
        Check(next is { Total: 3, Offset: 1, Limit: 1 } && next.Items.Single() == page.Items[1],
              "catalog pages did not preserve totals and stable ordering");
        var nextDevice = await ReadAsync<SoftwareInstallationsPage>(client, Installations(productId) + "?offset=2&limit=1", token);
        Check(nextDevice is { Total: 3, Offset: 2, Limit: 1 } && nextDevice.Items.Single() == devices.Items[2],
              "installation pages did not preserve totals and stable ordering");
    }

    private static async Task VerifyIncompleteAsync(HttpClient client, string token, EnrollmentResponse primary,
        DateTimeOffset changedAt, string productId, InstalledSoftwareItem replaced)
    {
        var partialAt = changedAt.AddMinutes(1);
        // The item list is unchanged. Refreshing coverage must still invalidate the comparison baseline.
        await PostSectionAsync(client, primary, partialAt, new(TelemetryAvailability.Collected, [replaced, DifferentPublisher, Later], 4, true));
        var partial = await ReadAsync<SoftwareInstallationsPage>(client, Installations(productId), token);
        Check(partial.Items.Single(item => item.EndpointId == primary.EndpointId) is { Partial: true, CollectedUtc: var at } && at == partialAt &&
              (await ReadAsync<SoftwareCatalogPage>(client, Route, token)).Coverage.PartialEndpoints == 1,
              "truncated positive observations lost their visible partial coverage");
        await PostSectionAsync(client, primary, changedAt.AddMinutes(2), Complete(DifferentPublisher));
        await PostSectionAsync(client, primary, changedAt.AddMinutes(3), new(TelemetryAvailability.Collected, [Later], 1, false, 1));
        Check((await ReadAsync<SoftwareCatalogPage>(client, Route, token)).Coverage.PartialEndpoints == 1,
              "a scan that skipped items was reported as complete");
        await PostSectionAsync(client, primary, changedAt.AddMinutes(4), Complete(Primary));
        await PostSectionAsync(client, primary, changedAt.AddMinutes(5), new(TelemetryAvailability.Unavailable));
        Check((await ReadAsync<SoftwareInstallationsPage>(client, Installations(productId), token)).Items.All(item => item.EndpointId != primary.EndpointId),
              "unavailable collection incorrectly kept outdated positive items");
        await PostSectionAsync(client, primary, changedAt.AddMinutes(6), Complete(DifferentPublisher));
    }

    private static async Task VerifyAccessAsync(HttpClient client, string token, EnrollmentResponse agent, string unknownProduct)
    {
        foreach (var path in new[] { Route, Installations(unknownProduct), ChangeRoute })
        {
            await ExpectAsync(client, path, HttpStatusCode.Unauthorized);
            await ExpectAsync(client, path, HttpStatusCode.Unauthorized, $"{agent.EndpointId:D}.{agent.AgentCredential}", scheme: "SentinelAgent");
            await ExpectAsync(client, path, HttpStatusCode.Forbidden, token, remote: true);
            Check(!LocalNetworkRoutes.IsAllowed("GET", path), "a catalog route was allowed on the Agent listener");
        }
        foreach (var q in new[] { "?offset=-1", "?offset=9999999999999", "?limit=0", "?limit=51", "?limit=1&limit=2",
                     "?q=one&q=two", "?q=%00", "?q=" + new string('q', 129), "?extra=1" })
            await ExpectAsync(client, Route + q, HttpStatusCode.BadRequest, token);
        await ExpectAsync(client, ChangeRoute + "?productId=invalid", HttpStatusCode.BadRequest, token);
        await ExpectAsync(client, ChangeRoute + "?productId=" + unknownProduct + "&productId=" + unknownProduct, HttpStatusCode.BadRequest, token);
        await ExpectAsync(client, Installations(unknownProduct) + "?q=test", HttpStatusCode.BadRequest, token);
        Check((await ReadAsync<SoftwareInstallationsPage>(client, Installations(unknownProduct), token)).Total == 0 &&
              (await ReadAsync<SoftwareChangesPage>(client, ChangeRoute + "?productId=" + unknownProduct, token)).Total == 0,
              "unknown product returned another product's data");
    }

    private static async Task VerifyLegacyCatalogAsync(string directory, string username, string password, bool backfill)
    {
        var clock = new TestTime(DateTimeOffset.UtcNow);
        var collection = clock.UtcNow.AddMinutes(-4);
        string path;
        EnrollmentResponse agent;
        await using (var app = Build(directory, clock))
        {
            using var client = await StartAsync(app);
            agent = await EnrollAsync(app.Services.GetRequiredService<EnrollmentStore>());
            await PostSectionAsync(client, agent, collection, Complete(Primary));
            path = app.Services.GetRequiredService<AdminStore>().DatabasePath;
            await app.StopAsync();
        }

        // Retain the accepted schema-1 telemetry and remove only the tables a legacy Core lacked.
        await using (var connection = TestDatabase(path))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE SoftwareInventoryItems; DROP TABLE SoftwareInventoryChanges; DROP TABLE SoftwareInventoryState;";
            await command.ExecuteNonQueryAsync();
        }

        await using var restarted = Build(directory, clock, backfill);
        using var reader = await StartAsync(restarted);
        var token = await LoginAsync(reader, username, password);
        if (backfill)
        {
            var page = await ReadAsync<SoftwareCatalogPage>(reader, Route, token);
            var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
            while (page.Total == 0 && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(100);
                page = await ReadAsync<SoftwareCatalogPage>(reader, Route, token);
            }
            var product = page.Items.SingleOrDefault();
            Check(product?.Name == Primary.Name && page is { Total: 1, Coverage: { CompleteEndpoints: 1, MissingEndpoints: 0 } },
                  "legacy accepted telemetry did not backfill as current observations");
            var restored = await ReadAsync<SoftwareInstallationsPage>(reader, Installations(product!.ProductId), token);
            Check(restored.Items.Single() is { CollectedUtc: var at, EndpointId: var id } && at == collection && id == agent.EndpointId,
                  "legacy backfill changed observation time or endpoint identity");
        }
        else
        {
            // Neither a replay nor a stale upload can seed the projection ahead of a newer report.
            await PostSectionAsync(reader, agent, collection, Complete());
            await PostSectionAsync(reader, agent, collection.AddTicks(-1), Complete());
            Check((await ReadAsync<SoftwareCatalogPage>(reader, Route, token)) is { Total: 0, Coverage.MissingEndpoints: 1 },
                  "a legacy endpoint appeared before backfill or a newer live observation");
        }
        Check((await ReadAsync<SoftwareChangesPage>(reader, ChangeRoute, token)).Total == 0,
              "the legacy projection or replay invented a change");

        var variants = Enumerable.Range(0, SoftwareCatalogContract.MaximumChangeVariants + 2)
            .Select(index => Primary with { Version = $"synthetic-v{index:D2}" }).ToArray();
        var observed = collection.AddMinutes(1);
        await PostSectionAsync(reader, agent, observed, Complete(variants));
        var change = (await ReadAsync<SoftwareChangesPage>(reader, ChangeRoute, token)).Items.Single();
        Check(change is { Kind: "variantsChanged", BeforeCount: 1 } && change.PreviousCollectedUtc == collection && change.CollectedUtc == observed &&
              change.Before.Single() == new SoftwareVariant(Primary.Version, Primary.Architecture) &&
              change.AfterCount == variants.Length && change.After.Count == SoftwareCatalogContract.MaximumChangeVariants &&
              change.After.All(variant => variants.Any(item => item.Version == variant.Version && item.Architecture == variant.Architecture)),
              "the next valid observation lost the actual legacy baseline or the bounded variant preview");
        var current = await ReadAsync<SoftwareInstallationsPage>(reader, Installations(change.ProductId), token);
        Check(current.Total == variants.Length && current.Items.All(item => item.CollectedUtc == observed && item.EndpointId == agent.EndpointId),
              "legacy comparison did not publish the newer current observation");
        await restarted.StopAsync();
    }

    private static async Task VerifyStorageLimitsAsync(string directory)
    {
        var clock = new TestTime(DateTimeOffset.UtcNow);
        var collected = clock.UtcNow.AddMinutes(-4);
        await using var app = Build(directory, clock);
        using var client = await StartAsync(app);
        var agent = await EnrollAsync(app.Services.GetRequiredService<EnrollmentStore>());
        await PostSectionAsync(client, agent, collected, Complete(Primary));
        var oldId = SoftwareCatalogContract.MaximumChanges + 3; // 2 over the cap, plus 1 already expired.
        await using var connection = TestDatabase(app.Services.GetRequiredService<AdminStore>().DatabasePath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            WITH RECURSIVE seed(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM seed WHERE id < $oldId)
            INSERT INTO SoftwareInventoryChanges (ChangeId, EndpointId, ProductId, Name, Publisher, Kind,
                 PreviousCollectedUtcTicks, CollectedUtcTicks, ReceivedUtcTicks, BeforeCount, AfterCount, BeforeJson, AfterJson)
            SELECT id, $endpoint, $product, 'Synthetic Storage Fixture', '', 'appeared', $collected - 1, $collected,
                   CASE WHEN id = $oldId THEN $expired ELSE $receipt END, 0, 1, '[]', '[{"version":"1","architecture":null}]'
            FROM seed;
            """;
        command.Parameters.AddWithValue("$oldId", oldId);
        command.Parameters.AddWithValue("$endpoint", agent.EndpointId.ToString("D"));
        command.Parameters.AddWithValue("$product", new string('a', 64));
        command.Parameters.AddWithValue("$collected", collected.UtcTicks);
        command.Parameters.AddWithValue("$receipt", clock.UtcNow.UtcTicks);
        command.Parameters.AddWithValue("$expired", clock.UtcNow.AddDays(-SoftwareCatalogContract.RetentionDays).AddTicks(-1).UtcTicks);
        await command.ExecuteNonQueryAsync();

        await PostSectionAsync(client, agent, collected.AddMinutes(1), Complete(Secondary));
        command.CommandText = "SELECT COUNT(*), MIN(ChangeId), MAX(ChangeId), COUNT(CASE WHEN ChangeId = $oldId THEN 1 END) FROM SoftwareInventoryChanges;";
        await using var rows = await command.ExecuteReaderAsync();
        Check(await rows.ReadAsync() && rows.GetInt64(0) == SoftwareCatalogContract.MaximumChanges &&
              rows.GetInt64(1) == 4 && rows.GetInt64(2) == oldId + 1 && rows.GetInt64(3) == 0,
              "a newer observation did not physically expire stale receipts and keep the latest rows under the cap");
    }

    private static async Task<(long Items, long State, long Telemetry)> ReadEndpointRowsAsync(string path, Guid endpointId)
    {
        await using var connection = TestDatabase(path);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM SoftwareInventoryItems WHERE EndpointId = $endpoint),
                   (SELECT COUNT(*) FROM SoftwareInventoryState WHERE EndpointId = $endpoint),
                   (SELECT COUNT(*) FROM EndpointSecurityTelemetry WHERE EndpointId = $endpoint);
            """;
        command.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        await using var rows = await command.ExecuteReaderAsync();
        await rows.ReadAsync();
        return (rows.GetInt64(0), rows.GetInt64(1), rows.GetInt64(2));
    }

    private static SqliteConnection TestDatabase(string path) => new(new SqliteConnectionStringBuilder { DataSource = path }.ToString());

    private static WebApplication Build(string directory, TestTime clock, bool backfill = true) => CoreHost.Build(
        ["--SentinelAI:DataDirectory=" + directory], false,
        builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<TimeProvider>(clock);
            if (!backfill)
                builder.Services.Remove(builder.Services.Single(service => service.ServiceType == typeof(IHostedService) &&
                    service.ImplementationType == typeof(SoftwareInventoryBackfillWorker)));
        },
        configureBeforeAuthentication: app => app.Use((context, next) =>
        {
            if (context.Request.Headers.ContainsKey(RemoteHeader))
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.67");
                context.Request.Scheme = "https";
            }
            return next(context);
        }));

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private static async Task<EnrollmentResponse> EnrollAsync(EnrollmentStore store)
    {
        var token = await store.IssueTokenAsync();
        var enrolled = await store.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token), overLocalNetwork: true);
        return enrolled.Response ?? throw new InvalidOperationException("Software catalog tests: synthetic enrollment failed.");
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        response.EnsureSuccessStatusCode();
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return document.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static InstalledSoftwareTelemetry Complete(params InstalledSoftwareItem[] items) =>
        new(TelemetryAvailability.Collected, items, items.Length);

    private static async Task PostSectionAsync(HttpClient client, EnrollmentResponse agent, DateTimeOffset collected,
        InstalledSoftwareTelemetry section, HttpStatusCode expected = HttpStatusCode.NoContent)
    {
        var report = EndpointTelemetryApiTests.Benign(agent.EndpointId, collected) with { Software = section };
        using var request = new HttpRequestMessage(HttpMethod.Post, AgentRoute)
        {
            Content = JsonContent.Create(report, options: EndpointTelemetryContract.Json)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{agent.EndpointId:D}.{agent.AgentCredential}");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == expected, $"expected agent ingest status {expected}, received {response.StatusCode}");
    }

    private static async Task<T> ReadAsync<T>(HttpClient client, string route, string token) where T : class
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
              $"expected a successful no-store catalog response, received {response.StatusCode}");
        var bytes = await response.Content.ReadAsByteArrayAsync();
        Check(bytes.Length <= SoftwareCatalogContract.MaximumResponseBytes, "catalog response exceeded its bound");
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        Check(!json.Contains("S-1-5-21-1000-1000-1000-", StringComparison.Ordinal) &&
              !json.Contains("credential", StringComparison.OrdinalIgnoreCase) && !json.Contains("reportJson", StringComparison.OrdinalIgnoreCase),
              "catalog response exposed agent telemetry outside the software projection");
        return JsonSerializer.Deserialize<T>(json, JsonSerializerOptions.Web) ??
               throw new InvalidOperationException("Software catalog tests: missing response.");
    }

    private static async Task ExpectAsync(HttpClient client, string path, HttpStatusCode status, string? token = null,
        bool remote = false, string scheme = "Bearer")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        if (remote) request.Headers.Add(RemoteHeader, "1");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == status && response.Headers.CacheControl?.NoStore == true,
              $"expected {status} and no-store for {path}, received {response.StatusCode}");
    }

    private static string Installations(string productId) => Route + "/" + productId + "/installations";

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("Software catalog tests: " + message);
    }

    private sealed class TestTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
