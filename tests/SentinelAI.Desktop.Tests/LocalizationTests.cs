using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Localization;

// The Polish version: every text Desktop shows has a translation, translations keep their placeholders, unknown texts
// stay English, Desktop starts in the installation language and an administrator changes it in Settings.
internal static class LocalizationTests
{
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        try
        {
            Catalog();
            Coverage();
            Translation();
            await ResolutionAsync();
            await SettingsAsync();
            await CoreLanguageAsync();
            await ChangeRequestAsync();
        }
        finally
        {
            Localizer.Use(UiLanguage.English);
        }

        Console.WriteLine($"Desktop localization: {_assertions} assertions passed.");
        return _assertions;
    }

    private static void Catalog()
    {
        Ensure(TextCatalog.Polish.Entries.Count > 900, "The Polish catalog was not embedded.");
        foreach (var (json, reason) in new[]
                 {
                     ("{\"A\":\"B\",\"A\":\"C\"}", "a duplicate key"), ("{\"{0} of {1}\":\"{0} z\"}", "a lost placeholder"), ("{\"A\":\"\"}", "an empty translation"),
                     ("[\"A\"]", "a list"), ("{\"A\":1}", "a number"), ("{\"A {0}\":\"A {1}\"}", "a renumbered placeholder")
                 })
        {
            try
            {
                TextCatalog.Parse(Encoding.UTF8.GetBytes(json));
                Ensure(false, "The catalog parser accepted " + reason + ".");
            }
            catch (InvalidDataException) { _assertions++; }
            catch (System.Text.Json.JsonException) { _assertions++; }
        }
    }

    /// <summary>Every text Desktop, Setup and Agent Setup translate, in code and in views, has a Polish translation.</summary>
    private static void Coverage()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "SentinelAI.sln"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("Repository root not found.");
        var keys = new SortedSet<string>(StringComparer.Ordinal);
        var call = new Regex(@"\b(?:T|F)\(\s*""((?:[^""\\]|\\.)*)""");
        var view = new Regex(@"\{loc:T '((?:[^'\\]|\\.)*)'\}");
        var found = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var folder in new[] { "desktop", "installer" })
        {
            var before = keys.Count;
            foreach (var file in Sources(Path.Combine(root, folder), "*.cs"))
                foreach (Match match in call.Matches(File.ReadAllText(file))) keys.Add(Regex.Unescape(match.Groups[1].Value));
            foreach (var file in Sources(Path.Combine(root, folder), "*.xaml"))
                foreach (Match match in view.Matches(File.ReadAllText(file)))
                    keys.Add(WebUtility.HtmlDecode(match.Groups[1].Value.Replace("\\'", "'", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal)));
            found[folder] = keys.Count - before;
        }
        var missing = keys.Where(key => !TextCatalog.Polish.Entries.ContainsKey(key)).ToArray();
        Ensure(found["desktop"] > 800 && found["installer"] > 90 && missing.Length == 0,
            "Desktop or Setup texts without a Polish translation:" + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    private static IEnumerable<string> Sources(string folder, string pattern) =>
        Directory.EnumerateFiles(folder, pattern, SearchOption.AllDirectories).Where(file =>
            !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
            !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    private static void Translation()
    {
        Localizer.Use(UiLanguage.Polish);
        Ensure(Localizer.T("Refresh") == "Odśwież" && Localizer.T("Risk Register") == "Rejestr ryzyk", "Polish texts were not used.");
        Ensure(Localizer.F("{0} of {1} enrolled endpoints", 2, 5) == "2 z 5 dołączonych komputerów", "A Polish format did not place its values.");
        Ensure(Localizer.T("A text no catalog contains") == "A text no catalog contains", "An unknown text did not stay English.");
        using (var register = new RiskRegisterViewModel(new NoRegister()))
            Ensure(register.DistinctionText.StartsWith("Oceny w rejestrze", StringComparison.Ordinal), "A view model did not speak Polish.");
        Ensure(VulnerabilityRemediation("Update Example Viewer to 2.5.0 or later.") == "Zaktualizuj Example Viewer do wersji 2.5.0 lub nowszej." &&
               VulnerabilityRemediation("Install the latest Windows cumulative update.") == "Zainstaluj najnowszą aktualizację zbiorczą Windows." &&
               VulnerabilityRemediation("Something the data never says.") == "Something the data never says.",
            "Remediation from the vulnerability data was not shown in Polish.");
        Localizer.Use(UiLanguage.English);
        Ensure(Localizer.T("Refresh") == "Refresh" && Localizer.F("{0} of {1} enrolled endpoints", 2, 5) == "2 of 5 enrolled endpoints", "English did not return.");
    }

    private static string VulnerabilityRemediation(string text) =>
        (string)typeof(DeviceVulnerabilitiesViewModel).GetMethod("Remediation", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [text])!;

    private static async Task ResolutionAsync()
    {
        var cache = new MemoryCache();
        Ensure(await DesktopLanguage.ResolveAsync(_ => Task.FromResult<UiLanguage?>(UiLanguage.Polish), cache, CultureInfo.GetCultureInfo("en-US"), default) == UiLanguage.Polish &&
               cache.Value == UiLanguage.Polish, "Core's installation language was not used and remembered.");
        Ensure(await DesktopLanguage.ResolveAsync(_ => Task.FromResult<UiLanguage?>(null), cache, CultureInfo.GetCultureInfo("en-US"), default) == UiLanguage.Polish,
            "The remembered language was not used while Core did not answer.");
        Ensure(await DesktopLanguage.ResolveAsync(_ => throw new HttpRequestException(), new MemoryCache(), CultureInfo.GetCultureInfo("pl-PL"), default) == UiLanguage.Polish &&
               await DesktopLanguage.ResolveAsync(_ => Task.FromResult<UiLanguage?>(null), null, CultureInfo.GetCultureInfo("de-DE"), default) == UiLanguage.English,
            "Without Core or a remembered language, Windows' language was not used.");
    }

    private static async Task SettingsAsync()
    {
        var client = new LanguageClient();
        var cache = new MemoryCache();
        var settings = new LanguageSettingsViewModel(client, cache, UiLanguage.English);
        var expired = 0;
        settings.SessionExpired += (_, _) => expired++;
        Ensure(!settings.CanSave && LanguageSettingsViewModel.Options.Select(option => option.Text).SequenceEqual(["English", "Polski"]) &&
               LanguageSettingsViewModel.Options.Select(option => option.ToString()).SequenceEqual(["English", "Polski"]),
            "The language choice was not offered, each language named in itself.");
        settings.Selected = UiLanguage.Polish;
        await settings.SaveAsync();
        Ensure(client.Requests.Single() == UiLanguage.Polish && cache.Value == UiLanguage.Polish && !settings.CanSave &&
               settings.StatusText.Contains("Close and reopen SentinelAI", StringComparison.Ordinal), "The language was not saved in Core and remembered.");
        settings.Selected = UiLanguage.English;
        client.Outcome = LanguageRequestOutcome.Unavailable;
        await settings.SaveAsync();
        Ensure(settings.CanSave && settings.StatusText.StartsWith("Local Core is unavailable", StringComparison.Ordinal) && cache.Value == UiLanguage.Polish,
            "A failed change was reported as saved.");
        client.Outcome = LanguageRequestOutcome.Unauthenticated;
        await settings.SaveAsync();
        Ensure(expired == 1, "An expired session was not reported.");
    }

    private static async Task CoreLanguageAsync()
    {
        async Task<UiLanguage?> Read(HttpStatusCode status, string body)
        {
            using var core = new HttpCoreClient(new Answer(status, body));
            return await core.GetLanguageAsync(default);
        }

        Ensure(await Read(HttpStatusCode.OK, "{\"language\":\"pl\"}") == UiLanguage.Polish && await Read(HttpStatusCode.OK, "{\"language\":\"en\"}") == UiLanguage.English,
            "Core's installation language was not read.");
        Ensure(await Read(HttpStatusCode.OK, "{\"language\":\"de\"}") is null && await Read(HttpStatusCode.OK, "{\"language\":\"pl\",\"x\":1}") is null &&
               await Read(HttpStatusCode.NotFound, "{}") is null && await Read(HttpStatusCode.OK, "[\"pl\"]") is null, "An unexpected answer chose a language.");
    }

    private static async Task ChangeRequestAsync()
    {
        string? body = null;
        using var trust = new Trust();
        using var client = new HttpAuthenticationClient(trust, new Answer(HttpStatusCode.OK, "{\"language\":\"pl\"}", request => body = request));
        Ensure((await client.SignInAsync("admin", "synthetic-localization-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login failed.");
        var result = await client.SetInstallationLanguageAsync(UiLanguage.Polish, default);
        Ensure(result == (LanguageRequestOutcome.Success, UiLanguage.Polish) && body == "{\"language\":\"pl\"}", "The language change was not sent as Core expects.");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        _assertions++;
    }

    private sealed class MemoryCache : ILanguageCache
    {
        public UiLanguage? Value;
        public UiLanguage? Read() => Value;
        public void Save(UiLanguage language) => Value = language;
    }

    private sealed class LanguageClient : ILanguageSettingsClient
    {
        public List<UiLanguage> Requests { get; } = [];
        public LanguageRequestOutcome Outcome = LanguageRequestOutcome.Success;

        public Task<(LanguageRequestOutcome Outcome, UiLanguage? Language)> SetInstallationLanguageAsync(UiLanguage language, CancellationToken cancellationToken)
        {
            Requests.Add(language);
            return Task.FromResult<(LanguageRequestOutcome, UiLanguage?)>((Outcome, Outcome == LanguageRequestOutcome.Success ? language : null));
        }
    }

    private sealed class NoRegister : IRiskRegisterClient
    {
        public Task<RiskRegisterResult<RiskRegisterPage>> GetRiskRegisterAsync(RiskRegisterQuery query, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterPage>(RiskRegisterOutcome.Unavailable));
        public Task<RiskRegisterResult<RiskRegisterDetail>> GetRiskRecordAsync(Guid riskId, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Unavailable));
        public Task<RiskRegisterResult<RiskRegisterDetail>> CreateRiskRecordAsync(RiskRegisterDraft draft, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Unavailable));
        public Task<RiskRegisterResult<RiskRegisterDetail>> UpdateRiskRecordAsync(Guid riskId, long expectedVersion, RiskRegisterDraft draft, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Unavailable));
        public Task<RiskRegisterResult<RiskRegisterDetail>> ReviewRiskRecordAsync(Guid riskId, long expectedVersion, string nextReviewDate, string? note,
            CancellationToken cancellationToken) => Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Unavailable));
    }

    /// <summary>Answers every request except sign-in with one fixed response; records the last request body.</summary>
    private sealed class Answer(HttpStatusCode status, string body, Action<string?>? requestBody = null) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            static HttpResponseMessage Json(HttpStatusCode code, string text) => new(code) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Json(HttpStatusCode.OK, "{\"tokenType\":\"Bearer\",\"accessToken\":\"synthetic-localization-bearer\",\"expiresIn\":900}");
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Json(HttpStatusCode.OK, "{\"username\":\"admin\",\"role\":\"administrator\"}");
            requestBody?.Invoke(request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken));
            return Json(status, body);
        }
    }

    private sealed class Trust : ICoreEndpointTrust, IDisposable
    {
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) => Task.FromResult(true);
        public void Dispose() { }
    }
}
