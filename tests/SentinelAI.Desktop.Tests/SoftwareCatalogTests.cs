using System.Net;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.SoftwareCatalog;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Localization;

internal static class SoftwareCatalogTests
{
    private const string Path = "/api/admin/software-catalog";
    private const string Token = "synthetic-software-token";
    private const string Search = "Łódź & tools";
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 30, 0, TimeSpan.Zero);
    private static readonly Guid Computer = Guid.Parse("1944a8f1-1ba6-49aa-91de-c99b7a9fa986");
    private static readonly string First = new('a', 64);
    private static readonly string Second = new('b', 64);
    private static readonly string Retired = new('c', 64);
    private static readonly SoftwareCatalogCoverage Coverage = new(4, 1, 1, 1, 1, 1);
    private static readonly SoftwareProduct Primary = new(First, "Synthetic editor", "Test publisher", 2, 2);
    private static readonly SoftwareInstallation Installation = new(Computer, "Synthetic computer", "2.4", "x64", Now.AddHours(-4), true, true);
    private static readonly SoftwareChange Change = new(Computer, "Synthetic computer", Retired, "Retired synthetic app", null,
        "disappeared", Now.AddHours(-8), Now.AddHours(-2), 1, 0, [new("1.5", "x86")], []);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static int _checks;

    internal static async Task<int> RunAsync()
    {
        _checks = 0;
        await TransportAsync();
        await WorkspaceAsync();
        await CancellationAsync();
        Console.WriteLine($"Desktop software catalog: {_checks} assertions passed.");
        return _checks;
    }

    private static async Task TransportAsync()
    {
        var trust = new Trust();
        using var handler = new Handler();
        using var client = new HttpAuthenticationClient(trust, handler);
        Check((await client.GetSoftwareCatalogAsync(string.Empty, 0, 1, default)).Outcome == DeviceReadOutcome.Unauthenticated && handler.LastUri is null,
            "Software reads sent a request before sign-in.");
        Check((await client.SignInAsync("admin", "synthetic-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
            "Synthetic sign-in failed.");
        var products = new SoftwareCatalogPage(Now, 2, 0, 1, Coverage, [Primary]);
        handler.Answer = () => Json(products);
        var result = await client.GetSoftwareCatalogAsync(Search, 0, 1, default);
        Check(result is { Outcome: DeviceReadOutcome.Success, Value.Total: 2 } && result.Value.Coverage == Coverage && result.Value.Items[0] == Primary &&
            handler.LastUri!.PathAndQuery == Path + "?offset=0&limit=1&q=" + Uri.EscapeDataString(Search) && handler.Authorization == "Bearer " + Token,
            "Catalog moved a query out of its value, lost evidence or lost the current bearer.");
        var reads = handler.Reads;
        Check((await client.GetSoftwareCatalogAsync("bad\u200btext", 0, 1, default)).Outcome == DeviceReadOutcome.InvalidResponse && handler.Reads == reads,
            "A query with a hidden format character reached Core.");
        foreach (var bad in new[]
                 {
                     products with { Offset = 1 }, products with { Coverage = Coverage with { MissingEndpoints = 2 } },
                     products with { Items = [Primary with { EndpointCount = 3 }] }, products with { Items = [Primary with { ProductId = First.ToUpperInvariant() }] },
                     products with { Items = [Primary with { Name = "invalid\u200bname" }] }, products with { Items = [] }
                 })
        {
            handler.Answer = () => Json(bad);
            Check((await client.GetSoftwareCatalogAsync(string.Empty, 0, 1, default)).Outcome == DeviceReadOutcome.InvalidResponse,
                "Catalog accepted an invalid product page, text, count or coverage.");
        }

        var variants = new SoftwareInstallationsPage(First, Now, 2, 0, 2, [Installation, Installation with { Version = null, Architecture = null }]);
        handler.Answer = () => Json(variants);
        var installations = await client.GetSoftwareInstallationsAsync(First, 0, 2, default);
        Check(installations is { Outcome: DeviceReadOutcome.Success, Value.Items.Count: 2 } && installations.Value.Items.SequenceEqual(variants.Items) &&
            handler.LastUri!.PathAndQuery == $"{Path}/{First}/installations?offset=0&limit=2", "Software detail discarded a variant for the same computer.");
        foreach (var bad in new[]
                 {
                     variants with { ProductId = Second }, variants with { Items = [Installation, Installation] },
                     variants with { Items = [Installation, Installation with { Version = "3", Architecture = "bad" }] }
                 })
        {
            handler.Answer = () => Json(bad);
            Check((await client.GetSoftwareInstallationsAsync(First, 0, 2, default)).Outcome == DeviceReadOutcome.InvalidResponse,
                "Detail accepted the wrong application, an invalid architecture or duplicate variant.");
        }

        var fleet = new SoftwareChangesPage(null, Now, 1, 0, 1, [Change]);
        handler.Answer = () => Json(fleet);
        var changes = await client.GetSoftwareChangesAsync(null, 0, 1, default);
        Check(changes is { Outcome: DeviceReadOutcome.Success, Value.Items.Count: 1 } && changes.Value.Items[0].ProductId == Retired &&
            changes.Value.Items[0].Before.SequenceEqual(Change.Before) && handler.LastUri!.PathAndQuery == Path + "/changes?offset=0&limit=1",
            "Whole-fleet history did not return the disappeared application.");
        handler.Answer = () => Json(fleet with { ProductId = Retired });
        Check((await client.GetSoftwareChangesAsync(Retired, 0, 1, default)).Outcome == DeviceReadOutcome.Success &&
            handler.LastUri!.PathAndQuery == $"{Path}/changes?offset=0&limit=1&productId={Retired}", "History lost the application filter.");
        foreach (var bad in new[]
                 {
                     fleet with { Total = SoftwareCatalogContract.MaximumChanges + 1 }, fleet with { ProductId = First },
                     fleet with { Items = [Change with { PreviousCollectedUtc = Change.CollectedUtc }] },
                     fleet with { Items = [Change with { Kind = "uninstalled" }] }, fleet with { Items = [Change with { Before = [] }] }
                 })
        {
            handler.Answer = () => Json(bad);
            Check((await client.GetSoftwareChangesAsync(null, 0, 1, default)).Outcome == DeviceReadOutcome.InvalidResponse,
                "History accepted an invalid scope, kind, time, count, or preview.");
        }
        handler.Answer = () => Json(new string(' ', SoftwareCatalogContract.MaximumResponseBytes));
        Check((await client.GetSoftwareChangesAsync(null, 0, 1, default)).Outcome == DeviceReadOutcome.TooLarge,
            "An oversized history response reached the parser.");
        reads = handler.Reads;
        trust.Allowed = false;
        Check((await client.GetSoftwareChangesAsync(null, 0, 1, default)).Outcome == DeviceReadOutcome.UntrustedConnection && handler.Reads == reads,
            "A catalogue request wrote a bearer to a connection that failed trust.");
    }

    private static async Task WorkspaceAsync()
    {
        var originalLanguage = Localizer.Current;
        Localizer.Use(UiLanguage.English);
        try
        {
            var client = new WorkspaceClient();
            using var model = new SoftwareCatalogViewModel(client);
            await model.OpenChangesAsync();
            Check(client.LastChanges is null, "A history view loaded without an active workspace.");
            await model.RefreshAsync();
            Check(model.Products.Count == 25 && model.CanNextProducts && !model.CanPreviousProducts &&
                model.CoverageText.Contains("1 partial", StringComparison.Ordinal) && model.CoverageText.Contains("1 older than 3 h", StringComparison.Ordinal),
                "Catalog lost the page or the coverage counts.");
            await model.NextProductsAsync();
            Check(client.LastCatalog == (string.Empty, 25) && model.Products.Count == 1 && model.CanPreviousProducts && !model.CanNextProducts,
                "The catalog did not advance independently.");
            model.SearchText = "  " + Search + "  ";
            await model.SearchAsync();
            Check(client.LastCatalog == (Search, 0) && model.SearchText == Search && model.Products.Count == 1,
                "Search did not trim the filter and reset catalog paging.");
            await model.SelectProductAsync(model.Products[0]);
            Check(client.LastInstallations == (First, 0) && model.Installations.Count == 25 && model.Installations[0].Version == "2.4 (x64)" &&
                model.Installations[0].Observation.Contains("Partial report · Stale", StringComparison.Ordinal), "Detail lost version or coverage evidence.");
            await model.NextInstallationsAsync();
            Check(client.LastInstallations == (First, 25) && model.Installations.Count == 1 && model.Products.Count == 1 && model.HasSelection,
                "Installation paging dropped product selection or products.");
            await model.OpenChangesAsync();
            Check(client.LastChanges == (null, 0) && model.Changes.Count == 25 && model.Changes[0].Application.Contains(Change.Name, StringComparison.Ordinal) &&
                model.Changes[0].Observation.Contains("Disappeared from report", StringComparison.Ordinal), "Fleet history lost the retired product or promoted an observation to a removal.");
            await model.NextChangesAsync();
            Check(client.LastChanges == (null, 25) && model.Changes.Count == 1 && model.HasSelection, "Change pagination modified other scopes.");
            await model.ShowProductChangesAsync();
            Check(client.LastChanges == (First, 0) && model.ChangesScopeText == Primary.Name && model.CanShowFleetChanges,
                "Product history did not start at the first page or show its scope.");
            await model.ShowFleetChangesAsync();
            Check(client.LastChanges == (null, 0) && model.ChangesScopeText == "All computers and applications" && !model.CanShowFleetChanges,
                "Whole-fleet history did not clear the application filter.");
            await model.ClearSearchAsync();
            Check(client.LastCatalog == (string.Empty, 0) && model.SearchText.Length == 0 && !model.HasSelection && model.Installations.Count == 0,
                "Clearing search retained old selection or filter state.");
        }
        finally { Localizer.Use(originalLanguage); }
    }

    private static async Task CancellationAsync()
    {
        var client = new WorkspaceClient();
        using var model = new SoftwareCatalogViewModel(client);
        var expirations = 0;
        model.SessionExpired += (_, _) => expirations++;
        await model.RefreshAsync();
        var held = new TaskCompletionSource<DeviceReadResult<SoftwareInstallationsPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.HoldInstallations = held.Task;
        var old = model.SelectProductAsync(model.Products[0]);
        var oldToken = client.InstallationsToken;
        client.HoldInstallations = null;
        await model.SelectProductAsync(model.Products[1]);
        held.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await old;
        Check(oldToken.IsCancellationRequested && model.SelectedProduct?.Product.ProductId == Second && model.Installations.Count == 25 && expirations == 0,
            "A cancelled previous selection replaced the current rows or expired the active session.");

        model.SearchText = Search;
        var pendingChanges = new TaskCompletionSource<DeviceReadResult<SoftwareChangesPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.HoldChanges = pendingChanges.Task;
        var late = model.ShowProductChangesAsync();
        model.Clear();
        pendingChanges.SetResult(new(DeviceReadOutcome.Success, new(Second, Now, 1, 0, 25, [Change with { ProductId = Second }])));
        await late;
        Check(client.ChangesToken.IsCancellationRequested && model.Products.Count == 0 && !model.HasSelection && model.Installations.Count == 0 &&
            model.Changes.Count == 0 && model.SearchText.Length == 0 && model.CoverageText.Length == 0 && !model.CanRefreshChanges,
            "Leaving the catalog retained signed-in data or accepted a late response.");

        client.HoldChanges = Task.FromResult(new DeviceReadResult<SoftwareChangesPage>(DeviceReadOutcome.Unauthenticated));
        await model.RefreshAsync();
        await model.OpenChangesAsync();
        Check(expirations == 1 && model.Products.Count == 0 && !model.CanRefreshProducts, "An expired session retained data or failed to notify the shell.");
    }

    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, JsonOptions), Encoding.UTF8, "application/json")
    };

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        _checks++;
    }

    private sealed class Trust : ICoreEndpointTrust
    {
        public bool Allowed { get; set; } = true;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) => Task.FromResult(Allowed);
    }

    private sealed class Handler : HttpMessageHandler
    {
        public Func<HttpResponseMessage> Answer { get; set; } = () => throw new InvalidOperationException("Unexpected software request.");
        public int Reads { get; private set; }
        public Uri? LastUri { get; private set; }
        public string? Authorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login")
                return Task.FromResult(Json(new { tokenType = "Bearer", accessToken = Token, expiresIn = 900 }));
            if (request.RequestUri.AbsolutePath == "/api/admin/me")
                return Task.FromResult(Json(new { username = "admin", role = "administrator" }));
            Reads++;
            LastUri = request.RequestUri;
            Authorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(Answer());
        }
    }

    private sealed class WorkspaceClient : ISoftwareCatalogClient
    {
        public (string Query, int Offset) LastCatalog { get; private set; }
        public (string ProductId, int Offset) LastInstallations { get; private set; }
        public (string? ProductId, int Offset)? LastChanges { get; private set; }
        public CancellationToken InstallationsToken { get; private set; }
        public CancellationToken ChangesToken { get; private set; }
        public Task<DeviceReadResult<SoftwareInstallationsPage>>? HoldInstallations { get; set; }
        public Task<DeviceReadResult<SoftwareChangesPage>>? HoldChanges { get; set; }

        public Task<DeviceReadResult<SoftwareCatalogPage>> GetSoftwareCatalogAsync(string query, int offset, int limit, CancellationToken cancellationToken)
        {
            LastCatalog = (query, offset);
            var total = query.Length == 0 ? 26 : 1;
            var items = Enumerable.Range(offset, Math.Min(limit, total - offset)).Select(i => i switch
            {
                0 => Primary,
                1 => Primary with { ProductId = Second, Name = "Synthetic browser" },
                _ => Primary with { ProductId = i.ToString("x64"), Name = "Synthetic application " + i }
            }).ToArray();
            return Task.FromResult(new DeviceReadResult<SoftwareCatalogPage>(DeviceReadOutcome.Success, new(Now, total, offset, limit, Coverage, items)));
        }

        public Task<DeviceReadResult<SoftwareInstallationsPage>> GetSoftwareInstallationsAsync(string productId, int offset, int limit, CancellationToken cancellationToken)
        {
            LastInstallations = (productId, offset);
            InstallationsToken = cancellationToken;
            var items = Enumerable.Repeat(Installation, Math.Min(limit, 26 - offset)).ToArray();
            return HoldInstallations ?? Task.FromResult(new DeviceReadResult<SoftwareInstallationsPage>(DeviceReadOutcome.Success, new(productId, Now, 26, offset, limit, items)));
        }

        public Task<DeviceReadResult<SoftwareChangesPage>> GetSoftwareChangesAsync(string? productId, int offset, int limit, CancellationToken cancellationToken)
        {
            LastChanges = (productId, offset);
            ChangesToken = cancellationToken;
            var items = Enumerable.Repeat(Change with { ProductId = productId ?? Retired }, Math.Min(limit, 26 - offset)).ToArray();
            return HoldChanges ?? Task.FromResult(new DeviceReadResult<SoftwareChangesPage>(DeviceReadOutcome.Success, new(productId, Now, 26, offset, limit, items)));
        }
    }
}
