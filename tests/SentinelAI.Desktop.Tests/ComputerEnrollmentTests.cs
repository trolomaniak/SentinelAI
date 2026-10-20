using System.Net;
using System.Text;
using System.Text.Json;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Enrollment;

// MVP-2: Devices -> "Add computers" (enrollment codes) and "Remove computer".
internal static partial class LocalNetworkSettingsTests
{
    private const string Token64 = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";

    internal static async Task<int> RunEnrollmentAsync()
    {
        var before = _assertions;
        await EnrollmentTransportAsync();
        await EnrollmentViewModelAsync();
        Console.WriteLine($"Desktop computer enrollment: {_assertions - before} assertions passed.");
        return _assertions - before;
    }

    private static string Options(string? extra = null, string recommended = "\"central-pc\"", bool available = true, string port = "5443") =>
        "{\"available\":" + (available ? "true" : "false") + ",\"listening\":true,\"port\":" + port + ",\"recommendedAddress\":" + recommended +
        ",\"addresses\":[{\"value\":\"central-pc\",\"kind\":\"name\",\"resolves\":true},{\"value\":\"10.0.0.5\",\"kind\":\"ipv4\",\"resolves\":true}]" + extra + "}";

    private static string Code(string address, int index) =>
        new EnrollmentCode(address, 5443, Pin, Token64[..60] + index.ToString("X4")).Encode();

    private static async Task EnrollmentTransportAsync()
    {
        using (var context = new Context((_, _) => Task.FromResult(Json(Options()))))
        {
            await context.SignInAsync();
            var result = await context.Client.GetEnrollmentOptionsAsync(default);
            var request = context.Handler.Requests.Last();
            Ensure(result.Outcome == ComputerEnrollmentOutcome.Success && result.Value is { Available: true, Listening: true, Port: 5443, RecommendedAddress: "central-pc" } options &&
                   options.Addresses.Count == 2 && options.Addresses[0] == new EnrollmentAddressOption("central-pc", true, true) && !options.Addresses[1].IsName &&
                   request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == "/api/admin/enrollment-options" &&
                   context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted,
                "Desktop did not read the addresses an enrollment code may carry through the trusted session.");
        }

        foreach (var (body, outcome) in new (string, ComputerEnrollmentOutcome)[]
                 {
                     (Options(",\"extra\":1"), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options(recommended: "\"other-pc\""), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options(available: false), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options(port: "0"), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options().Replace("\"kind\":\"ipv4\"", "\"kind\":\"name\""), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options().Replace("10.0.0.5", "central-pc"), ComputerEnrollmentOutcome.InvalidResponse),
                     (Options().Replace("central-pc\",\"kind", "bad name\",\"kind"), ComputerEnrollmentOutcome.InvalidResponse),
                     ("{\"available\":false,\"listening\":false,\"port\":null,\"recommendedAddress\":null,\"addresses\":[" +
                      string.Join(",", Enumerable.Range(1, 33).Select(index => $"{{\"value\":\"10.0.0.{index}\",\"kind\":\"ipv4\",\"resolves\":true}}")) + "]}",
                         ComputerEnrollmentOutcome.TooLarge),
                     ("not json", ComputerEnrollmentOutcome.InvalidResponse)
                 })
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetEnrollmentOptionsAsync(default)).Outcome == outcome, "Desktop accepted inconsistent enrollment options.");
        }

        using (var local = new Context((_, _) => Task.FromResult(Json("{\"available\":false,\"listening\":false,\"port\":null,\"recommendedAddress\":null,\"addresses\":[]}"))))
        {
            await local.SignInAsync();
            Ensure((await local.Client.GetEnrollmentOptionsAsync(default)).Value is { Available: false, Addresses.Count: 0 }, "Desktop refused a local-only installation's options.");
        }

        // Issue: the exact request, then only well-formed codes for the chosen address are shown.
        var expires = DateTimeOffset.UtcNow.AddHours(24);
        string Issued(params string[] codes) => "{\"codes\":[" + string.Join(",", codes.Select((code, index) =>
            $"{{\"id\":\"{new Guid(index + 1, 0, 0, new byte[8]):D}\",\"code\":\"{code}\",\"expiresUtc\":\"{expires:O}\"}}")) + "]}";
        string? sent = null;
        using (var context = new Context(async (request, token) =>
               {
                   sent = await request.Content!.ReadAsStringAsync(token);
                   return Json(Issued(Code("central-pc", 1), Code("central-pc", 2)));
               }))
        {
            await context.SignInAsync();
            var result = await context.Client.IssueCodesAsync(2, 24, "central-pc", default);
            var request = context.Handler.Requests.Last();
            using var json = JsonDocument.Parse(sent!);
            Ensure(result.Outcome == ComputerEnrollmentOutcome.Success && result.Value!.Count == 2 && result.Value[0].Code == Code("central-pc", 1) &&
                   request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/api/admin/enrollment-codes" &&
                   json.RootElement.GetProperty("count").GetInt32() == 2 && json.RootElement.GetProperty("validityHours").GetInt32() == 24 &&
                   json.RootElement.GetProperty("address").GetString() == "central-pc" && json.RootElement.EnumerateObject().Count() == 3 &&
                   !result.Value[0].ToString().Contains(Token64[..20], StringComparison.Ordinal),
                "Desktop did not request and show a batch of codes for the chosen address.");
        }

        foreach (var (answer, outcome) in new (Func<HttpResponseMessage>, ComputerEnrollmentOutcome)[]
                 {
                     (() => Json(Issued(Code("central-pc", 1))), ComputerEnrollmentOutcome.InvalidResponse),
                     (() => Json(Issued(Code("10.0.0.5", 1), Code("central-pc", 2))), ComputerEnrollmentOutcome.InvalidResponse),
                     (() => Json(Issued(Code("central-pc", 1), Code("central-pc", 1))), ComputerEnrollmentOutcome.InvalidResponse),
                     (() => Json(Issued(Code("central-pc", 1), "SAI1-AAAAA")), ComputerEnrollmentOutcome.InvalidResponse),
                     (() => new HttpResponseMessage(HttpStatusCode.Conflict), ComputerEnrollmentOutcome.Conflict),
                     (() => new HttpResponseMessage(HttpStatusCode.BadRequest), ComputerEnrollmentOutcome.Rejected),
                     (() => new HttpResponseMessage(HttpStatusCode.Unauthorized), ComputerEnrollmentOutcome.Unauthenticated)
                 })
        {
            using var context = new Context((_, _) => Task.FromResult(answer()));
            await context.SignInAsync();
            Ensure((await context.Client.IssueCodesAsync(2, 24, "central-pc", default)).Outcome == outcome, "Desktop misread the issued codes.");
        }

        using (var context = new Context((_, _) => throw new InvalidOperationException("No request is expected.")))
        {
            await context.SignInAsync();
            var count = context.Handler.Requests.Count;
            Ensure((await context.Client.IssueCodesAsync(0, 24, "central-pc", default)).Outcome == ComputerEnrollmentOutcome.Rejected &&
                   (await context.Client.IssueCodesAsync(51, 24, "central-pc", default)).Outcome == ComputerEnrollmentOutcome.Rejected &&
                   (await context.Client.IssueCodesAsync(1, 169, "central-pc", default)).Outcome == ComputerEnrollmentOutcome.Rejected &&
                   (await context.Client.IssueCodesAsync(1, 24, "bad name", default)).Outcome == ComputerEnrollmentOutcome.Rejected &&
                   context.Handler.Requests.Count == count,
                "Desktop sent an out-of-bounds code request.");
        }

        // Unused codes and revocation.
        var created = DateTimeOffset.UtcNow;
        using (var context = new Context((_, _) => Task.FromResult(Json(
                   $"{{\"codes\":[{{\"id\":\"{Guid.NewGuid():D}\",\"createdUtc\":\"{created:O}\",\"expiresUtc\":\"{created.AddHours(1):O}\"}}]}}"))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetUnusedCodesAsync(default)).Value is { Count: 1 }, "Desktop did not list the unused codes.");
        }

        using (var context = new Context((_, _) => Task.FromResult(Json(
                   $"{{\"codes\":[{{\"id\":\"{Guid.NewGuid():D}\",\"createdUtc\":\"{created:O}\",\"expiresUtc\":\"{created:O}\"}}]}}"))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetUnusedCodesAsync(default)).Outcome == ComputerEnrollmentOutcome.InvalidResponse, "Desktop listed a code that expires when created.");
        }

        var id = Guid.NewGuid();
        foreach (var (status, outcome) in new[] { (HttpStatusCode.NoContent, ComputerEnrollmentOutcome.Success), (HttpStatusCode.NotFound, ComputerEnrollmentOutcome.NotFound),
                     (HttpStatusCode.InternalServerError, ComputerEnrollmentOutcome.Unavailable) })
        {
            using var context = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status)));
            await context.SignInAsync();
            var revoked = await context.Client.RevokeCodeAsync(id, default);
            var revokeRequest = context.Handler.Requests.Last();
            var removed = await context.Client.RemoveComputerAsync(id, default);
            var removeRequest = context.Handler.Requests.Last();
            Ensure(revoked == outcome && removed == outcome && revokeRequest.Method == HttpMethod.Delete &&
                   revokeRequest.RequestUri!.AbsolutePath == $"/api/admin/enrollment-codes/{id:D}" &&
                   removeRequest.Method == HttpMethod.Delete && removeRequest.RequestUri!.AbsolutePath == $"/api/admin/devices/{id:D}",
                "Desktop did not revoke a code or remove a computer through the expected request.");
        }
    }

    private static async Task EnrollmentViewModelAsync()
    {
        var client = new FakeEnrollment();
        using var model = new ComputerEnrollmentViewModel(client);
        await model.LoadAsync();
        Ensure(model.IsAvailable && model.SelectedAddress?.Value == "central-pc" && model.Addresses.Count == 2 &&
               model.Addresses[0].DisplayText.Contains("recommended", StringComparison.Ordinal) && model.Validity.Hours == 24 && model.Count == 1 &&
               model.StatusText == "No unused codes." && model.CanIssue,
            "Add computers did not recommend the resolving computer name, 24 hours and one code.");
        model.Count = 0;
        var lowest = model.Count;
        model.Count = 99;
        Ensure(lowest == 1 && model.Count == 50, "Add computers allowed a code count outside 1 to 50.");
        model.Count = 3;
        model.Validity = ComputerEnrollmentViewModel.ValidityChoices[^1];
        model.SelectedAddress = model.Addresses[1];
        await model.IssueAsync();
        Ensure(client.Issued == (3, 168, "10.0.0.5") && model.IssuedCodes.Count == 3 && model.IssuedCodesText.Split(Environment.NewLine).Length == 3 &&
               model.UnusedCodes.Count == 3 && model.StatusText == "3 unused codes.",
            "Add computers did not create and show the requested codes.");
        await model.RevokeAsync(model.IssuedCodes[0].Id);
        Ensure(model.IssuedCodes.Count == 2 && model.UnusedCodes.Count == 2 && client.Revoked.Count == 1, "Revoking a code did not update the lists.");
        Ensure(await model.RemoveComputerAsync(Guid.NewGuid()) && model.ErrorText == "", "Remove computer did not report a removed computer.");
        client.RemoveOutcome = ComputerEnrollmentOutcome.Unavailable;
        Ensure(!await model.RemoveComputerAsync(Guid.NewGuid()) && model.ErrorText.Contains("could not be removed", StringComparison.Ordinal),
            "Remove computer hid a failure.");

        model.Clear();
        Ensure(model.IssuedCodes.Count == 0 && model.IssuedCodesText == "" && !model.IsAvailable && model.Addresses.Count == 0, "Sign-out kept the issued codes.");

        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        await model.LoadAsync();
        await model.IssueAsync();
        client.Expire = true;
        await model.RevokeAsync(model.IssuedCodes[0].Id);
        Ensure(expired == 1 && model.IssuedCodes.Count == 0 && !model.IsAvailable, "An expired session kept the codes or did not ask to sign in again.");

        // Saved code files: one per code, readable by the Agent Setup, never overwritten.
        var folder = Path.Combine(Path.GetTempPath(), "sentinelai-codes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var rows = new[] { new IssuedCodeRow(Guid.NewGuid(), Code("central-pc", 1), "x"), new IssuedCodeRow(Guid.NewGuid(), Code("central-pc", 2), "x") };
            var paths = EnrollmentCodeFiles.Write(folder, rows);
            Ensure(paths.Count == 2 && paths.All(path => path.EndsWith(EnrollmentCode.FileExtension, StringComparison.Ordinal)) &&
                   paths.Select((path, index) => EnrollmentCode.TryParseFile(File.ReadAllBytes(path), out var code) && code!.EnrollmentToken == Token64[..60] + (index + 1).ToString("X4")).All(ok => ok),
                "Saved code files could not be read back as codes.");
            var threw = false;
            try { EnrollmentCodeFiles.Write(folder, rows); } catch (IOException) { threw = true; }
            Ensure(threw && Directory.GetFiles(folder).Length == 2, "Saving codes overwrote existing code files.");
        }
        finally { Directory.Delete(folder, true); }

        using var local = new ComputerEnrollmentViewModel(new FakeEnrollment { LocalOnly = true });
        await local.LoadAsync();
        Ensure(!local.IsAvailable && !local.CanIssue && local.StatusText.Contains("local to this computer", StringComparison.Ordinal),
            "Add computers offered codes on a local-only installation.");
    }

    private sealed class FakeEnrollment : IComputerEnrollmentClient
    {
        private readonly List<UnusedComputerCode> _unused = [];
        internal (int, int, string)? Issued;
        internal List<Guid> Revoked { get; } = [];
        internal bool LocalOnly;
        internal bool Expire;
        internal ComputerEnrollmentOutcome RemoveOutcome = ComputerEnrollmentOutcome.Success;

        public Task<ComputerEnrollmentResult<ComputerEnrollmentOptions>> GetEnrollmentOptionsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ComputerEnrollmentResult<ComputerEnrollmentOptions>(ComputerEnrollmentOutcome.Success, LocalOnly
                ? new ComputerEnrollmentOptions(false, false, null, null, [])
                : new ComputerEnrollmentOptions(true, true, 5443, "central-pc",
                    [new("central-pc", true, true), new("10.0.0.5", false, true)])));

        public Task<ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>> IssueCodesAsync(int count, int validityHours, string address, CancellationToken cancellationToken)
        {
            Issued = (count, validityHours, address);
            var codes = Enumerable.Range(1, count).Select(index => new IssuedComputerCode(Guid.NewGuid(), Code(address, index), DateTimeOffset.UtcNow.AddHours(validityHours))).ToArray();
            _unused.AddRange(codes.Select(code => new UnusedComputerCode(code.Id, DateTimeOffset.UtcNow, code.ExpiresUtc)));
            return Task.FromResult(new ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>(ComputerEnrollmentOutcome.Success, codes));
        }

        public Task<ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>> GetUnusedCodesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>(ComputerEnrollmentOutcome.Success, _unused.ToArray()));

        public Task<ComputerEnrollmentOutcome> RevokeCodeAsync(Guid id, CancellationToken cancellationToken)
        {
            if (Expire) return Task.FromResult(ComputerEnrollmentOutcome.Unauthenticated);
            Revoked.Add(id);
            _unused.RemoveAll(code => code.Id == id);
            return Task.FromResult(ComputerEnrollmentOutcome.Success);
        }

        public Task<ComputerEnrollmentOutcome> RemoveComputerAsync(Guid endpointId, CancellationToken cancellationToken) => Task.FromResult(RemoveOutcome);
    }
}
