using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Licensing;

internal static class LicenseRenewalClientTests
{
    private const string Prefix = "SentinelAI:Licensing:Renewal:";
    private static int assertions;

    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-renewal-client-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var credential = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var credentialPath = Path.Combine(directory, "activation.txt");
        try
        {
            await WriteProtectedAsync(credentialPath, credential);
            await VerifyConfigurationAsync(directory, credentialPath);
            await VerifyTransportAsync(credentialPath, credential);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine($"License renewal client tests passed ({assertions} assertions).");
    }

    private static async Task VerifyConfigurationAsync(string directory, string credentialPath)
    {
        foreach (var url in new[]
                 {
                     "/relative", "ftp://issuer.example", "http://issuer.example", "http://127.0.0.1.example",
                     "https://issuer.example/path", "https://user:password@issuer.example",
                     "https://issuer.example?override=true", "https://issuer.example#fragment"
                 })
        {
            ExpectInvalid(() => LicenseRenewalOptions.Load(Config(credentialPath, url)), "Unsafe issuer destination was accepted.");
        }
        foreach (var setting in new[]
                 {
                     ("Unexpected", "true"), ("Url:Nested", "true"), ("IntervalSeconds", "0"),
                     ("IntervalSeconds", "86401"), ("TimeoutSeconds", "0"), ("TimeoutSeconds", "61"),
                     ("Automatic", "sometimes")
                 })
        {
            ExpectInvalid(() => LicenseRenewalOptions.Load(Config(credentialPath, "https://issuer.example", setting)),
                "Invalid renewal setting was accepted.");
        }
        ExpectInvalid(() => LicenseRenewalOptions.Load(Config("relative-credential.txt", "https://issuer.example")),
            "Relative activation credential path was accepted.");
        ExpectInvalid(() => LicenseRenewalOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { [Prefix + "Url"] = "https://issuer.example" }).Build()),
            "Renewal without an activation credential file was accepted.");
        ExpectInvalid(() => LicenseRenewalOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { [Prefix + "ActivationCredentialPath"] = credentialPath }).Build()),
            "Activation credential without a fixed issuer was accepted.");
        ExpectInvalid(() => LicenseRenewalOptions.Load(Config(Path.Combine(directory, "missing.txt"), "https://issuer.example")),
            "Missing activation credential file was accepted.");

        foreach (var malformed in new[] { "", new string('A', 42), new string('A', 44), new string('A', 42) + "!", new string('A', 43) + "\n" })
        {
            var path = Path.Combine(directory, $"invalid-{Guid.NewGuid():N}.txt");
            await WriteProtectedAsync(path, malformed);
            ExpectInvalid(() => LicenseRenewalOptions.Load(Config(path, "https://issuer.example")),
                "Malformed activation credential file was accepted.");
        }
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(credentialPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            ExpectInvalid(() => LicenseRenewalOptions.Load(Config(credentialPath, "https://issuer.example")),
                "Group-readable activation credential file was accepted.");
            File.SetUnixFileMode(credentialPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);
            ExpectInvalid(() => LicenseRenewalOptions.Load(Config(credentialPath, "https://issuer.example")),
                "Other-writable activation credential file was accepted.");
            File.SetUnixFileMode(credentialPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        ExpectInvalid(() => LicenseVerificationOptions.Load(Config(credentialPath, "https://issuer.example")),
            "Network renewal without public verification trust was accepted.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicPath = Path.Combine(directory, "public.pem");
        await WriteProtectedAsync(publicPath, key.ExportSubjectPublicKeyInfoPem());
        var trusted = Config(credentialPath, "https://issuer.example");
        trusted["SentinelAI:Licensing:TrustedPublicKeys:test-key"] = publicPath;
        _ = LicenseVerificationOptions.Load(trusted);
        Check(true, "Configured public trust should permit fixed-origin renewal.");
        foreach (var url in new[] { "http://127.0.0.2", "http://localhost", "http://[::1]" })
        {
            _ = LicenseRenewalOptions.Load(Config(credentialPath, url));
            Check(true, "Loopback development issuer was rejected.");
        }
    }

    private static async Task VerifyTransportAsync(string credentialPath, string credential)
    {
        var identity = new CoreIdentity(Guid.NewGuid(), Guid.NewGuid());
        await using var issuer = await IssuerFixture.StartAsync();
        using var client = new LicenseLeaseClient(LicenseRenewalOptions.Load(Config(credentialPath, issuer.Origin.AbsoluteUri)));
        issuer.Respond = async context =>
        {
            Check(context.Request.Headers.Authorization.ToString() == "Bearer " + credential,
                "Renewal did not use activation authentication.");
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            var root = body.RootElement;
            Check(root.EnumerateObject().Count() == 2 &&
                  root.GetProperty("organizationId").GetGuid() == identity.OrganizationId &&
                  root.GetProperty("installationId").GetGuid() == identity.CoreInstallationId,
                "Renewal sent client-controlled entitlements or incorrect identity binding.");
            await WriteJsonAsync(context, "{\"lease\":\"synthetic.signed.token\"}");
        };
        Check(await client.FetchAsync(identity) == "synthetic.signed.token", "Well-formed issuer response was not returned for local verification.");

        await using var redirectTarget = await IssuerFixture.StartAsync();
        issuer.Respond = context =>
        {
            context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
            context.Response.Headers.Location = new Uri(redirectTarget.Origin, "/api/licenses/lease").AbsoluteUri;
            return Task.CompletedTask;
        };
        Check(await client.FetchAsync(identity) is null && redirectTarget.Requests == 0,
            "Client followed an issuer redirect and sent activation authentication to another destination.");

        foreach (var body in new[]
                 {
                     "not-json", "[]", "{}", "{\"lease\":123}", "{\"lease\":\"\"}",
                     "{\"lease\":\"first\",\"lease\":\"second\"}", "{\"lease\":\"token\",\"plan\":\"override\"}",
                     JsonSerializer.Serialize(new { lease = new string('A', LeaseTokenFormat.MaxTokenLength + 1) })
                 })
        {
            issuer.Respond = context => WriteJsonAsync(context, body);
            Check(await client.FetchAsync(identity) is null, "Client accepted malformed or ambiguous lease response JSON.");
        }
        foreach (var status in new[] { StatusCodes.Status401Unauthorized, StatusCodes.Status429TooManyRequests, StatusCodes.Status503ServiceUnavailable })
        {
            issuer.Respond = context => { context.Response.StatusCode = status; return Task.CompletedTask; };
            Check(await client.FetchAsync(identity) is null, "Issuer HTTP failure was treated as a successful renewal.");
        }
        issuer.Respond = async context =>
        {
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("{\"lease\":\"token\"}");
        };
        Check(await client.FetchAsync(identity) is null, "Non-JSON response was accepted.");
        foreach (var declaredLength in new[] { true, false })
        {
            issuer.Respond = async context =>
            {
                context.Response.ContentType = "application/json";
                var body = new string(' ', 20 * 1024 + 1);
                if (declaredLength) context.Response.ContentLength = Encoding.UTF8.GetByteCount(body);
                else await context.Response.StartAsync();
                await context.Response.WriteAsync(body);
            };
            Check(await client.FetchAsync(identity) is null, "Declared or streamed oversized issuer response was accepted.");
        }

        using var timedClient = new LicenseLeaseClient(LicenseRenewalOptions.Load(
            Config(credentialPath, issuer.Origin.AbsoluteUri, ("TimeoutSeconds", "1"))));
        foreach (var startBody in new[] { false, true })
        {
            issuer.Respond = async context =>
            {
                if (startBody)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"lease\":\"");
                    await context.Response.Body.FlushAsync();
                }
                try { await Task.Delay(TimeSpan.FromSeconds(10), context.RequestAborted); }
                catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
            };
            Check(await timedClient.FetchAsync(identity) is null, "Header or streamed-body timeout did not fail renewal safely.");
        }
        var received = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        issuer.Respond = async context =>
        {
            received.SetResult();
            try { await Task.Delay(TimeSpan.FromSeconds(10), context.RequestAborted); }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
        };
        using var cancellation = new CancellationTokenSource();
        var fetch = client.FetchAsync(identity, cancellation.Token);
        await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        try
        {
            _ = await fetch;
            throw new Exception("Caller cancellation was swallowed as an issuer failure.");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Check(true, "Caller cancellation must propagate.");
        }
        await issuer.StopAsync();
        Check(await timedClient.FetchAsync(identity) is null, "Unavailable issuer network connection was treated as renewal success.");
    }

    private static IConfigurationRoot Config(string path, string url, params (string Key, string Value)[] extra)
    {
        var settings = new Dictionary<string, string?> { [Prefix + "Url"] = url, [Prefix + "ActivationCredentialPath"] = path };
        foreach (var setting in extra) settings[Prefix + setting.Key] = setting.Value;
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    private static void ExpectInvalid(Action action, string message)
    {
        try { action(); }
        catch (InvalidOperationException) { Check(true, message); return; }
        throw new Exception(message);
    }

    private static async Task WriteProtectedAsync(string path, string content)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var stream = new FileStream(path, options);
        await stream.WriteAsync(Encoding.UTF8.GetBytes(content));
    }

    private static async Task WriteJsonAsync(HttpContext context, string body)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(body);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        Interlocked.Increment(ref assertions);
    }

    private sealed class IssuerFixture(WebApplication app) : IAsyncDisposable
    {
        private int requests;
        public int Requests => Volatile.Read(ref requests);
        public Uri Origin { get; private set; } = null!;
        public Func<HttpContext, Task> Respond { get; set; } = context => WriteJsonAsync(context, "{\"lease\":\"token\"}");

        public static async Task<IssuerFixture> StartAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();
            var app = builder.Build();
            var fixture = new IssuerFixture(app);
            app.Use(async (context, next) => { Interlocked.Increment(ref fixture.requests); await next(context); });
            app.MapPost("/api/licenses/lease", (HttpContext context) => fixture.Respond(context));
            await app.StartAsync();
            fixture.Origin = new Uri(app.Urls.Single());
            return fixture;
        }

        public Task StopAsync() => app.StopAsync();
        public async ValueTask DisposeAsync() => await app.DisposeAsync();
    }
}
