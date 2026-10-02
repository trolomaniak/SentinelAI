using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.LicenseApi;

await LicenseApiIntegrationTests.RunAsync();
LicenseStateMachineTests.Run();
await LicenseStateIntegrationTests.RunAsync();
await LicenseRenewalClientTests.RunAsync();

internal static class LicenseApiIntegrationTests
{
    private const string VerifyPath = "/api/admin/license/verify";
    private const string IssuePath = "/api/licenses/lease";
    private static int _assertions;

    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-license-api-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var dataDirectory = Path.Combine(directory, "core-data");
        var username = $"license-test-admin-{Guid.NewGuid():N}";
        var password = $"Development-Test-Only-{Guid.NewGuid():N}!";
        var oldUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var oldPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        var clock = new MutableTimeProvider(DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        using var originalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rotationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var untrustedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(directory, "issuer-private.pem");
        var publicPath = Path.Combine(directory, "issuer-public.pem");
        var rotationPublicPath = Path.Combine(directory, "rotation-public.pem");
        var malformedPublicPath = Path.Combine(directory, "malformed-public.pem");
        var credential = Base64Url(RandomNumberGenerator.GetBytes(32));
        try
        {
            // Every key is generated for this run, held outside the repository,
            // and deleted afterwards. No credential or token is logged.
            await VerifyDevelopmentKeyGenerationAsync(Path.Combine(directory, "generated-development-keys"));
            await WriteTestFileAsync(privatePath, originalKey.ExportPkcs8PrivateKeyPem());
            await WriteTestFileAsync(publicPath, originalKey.ExportSubjectPublicKeyInfoPem());
            await WriteTestFileAsync(rotationPublicPath, rotationKey.ExportSubjectPublicKeyInfoPem());
            await WriteTestFileAsync(malformedPublicPath, "not a public key");
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);

            CoreIdentity identity;
            await using (var unconfigured = CoreHost.Build(CoreArgs(dataDirectory), ConfigureClock(clock)))
            {
                using var client = await StartAsync(unconfigured);
                var adminToken = await LoginAsync(client, username, password);
                identity = await unconfigured.Services.GetRequiredService<EnrollmentStore>().GetCoreIdentityAsync();
                using var disabled = await VerifyRequestAsync(client, adminToken, "synthetic-unverified-token");
                Check(disabled.StatusCode == HttpStatusCode.ServiceUnavailable && disabled.Headers.CacheControl?.NoStore == true,
                    "Unconfigured Core must report unavailable verification without permitting caching.");
                await VerifyMonitoringAsync(client, adminToken);
            }

            string lease;
            await using (var issuer = LicenseApiHost.Build(CloudArgs(privatePath, identity, credential), ConfigureClock(clock)))
            {
                using var client = await StartAsync(issuer);
                lease = await VerifyIssuanceAsync(client, identity, credential, username, password);
            }
            // The issuer has stopped before Core verifies its token. Verification
            // therefore cannot rely on a live license API or shared server state.
            var trustedArgs = CoreArgs(dataDirectory,
                $"--SentinelAI:Licensing:TrustedPublicKeys:development-key={publicPath}",
                $"--SentinelAI:Licensing:TrustedPublicKeys:rotation-key={rotationPublicPath}");
            await using (var core = CoreHost.Build(trustedArgs, ConfigureClock(clock)))
            {
                using var client = await StartAsync(core);
                var adminToken = await LoginAsync(client, username, password);
                Check(await core.Services.GetRequiredService<EnrollmentStore>().GetCoreIdentityAsync() == identity,
                    "Core changed its installation binding after restart.");
                var valid = await VerifyAsync(client, adminToken, lease, "valid");
                Check(valid.GetProperty("keyId").GetString() == "development-key" &&
                      valid.GetProperty("claims").ValueKind == JsonValueKind.Object,
                    "Valid offline verification did not expose the verified key and signed claims.");
                Check(valid.GetProperty("claims").GetRawText().Contains(identity.OrganizationId.ToString("D"), StringComparison.Ordinal) &&
                      valid.GetProperty("claims").GetRawText().Contains(identity.CoreInstallationId.ToString("D"), StringComparison.Ordinal),
                    "Verification returned claims with another Core or organization identity.");
                await VerifyAccessAsync(core, client, adminToken, lease);
                await VerifyTamperingAsync(client, adminToken, lease);
                await VerifyTimeAndBindingAsync(client, adminToken, lease, originalKey, identity, clock, username, password);
                await VerifySignedClaimValidationAsync(client, adminToken, lease, originalKey);
                await VerifyRequestBoundsAsync(client, adminToken, lease);

                var rotated = Sign(lease, rotationKey, "rotation-key");
                var rotatedResult = await VerifyAsync(client, adminToken, rotated, "valid");
                Check(rotatedResult.GetProperty("keyId").GetString() == "rotation-key",
                    "Configured public key rotation did not verify the new issuer key.");
                await VerifyAsync(client, adminToken, Sign(lease, untrustedKey, "untrusted-key"), "invalid");
                await VerifyAsync(client, adminToken, Sign(lease, untrustedKey, "development-key"), "invalid");
                await VerifyMonitoringAsync(client, adminToken);
            }

            // Removing the old public key takes effect on restart while the
            // persisted local identity and monitoring remain independent.
            await using (var rotatedCore = CoreHost.Build(CoreArgs(dataDirectory,
                             $"--SentinelAI:Licensing:TrustedPublicKeys:rotation-key={rotationPublicPath}"), ConfigureClock(clock)))
            {
                using var client = await StartAsync(rotatedCore);
                var adminToken = await LoginAsync(client, username, password);
                await VerifyAsync(client, adminToken, lease, "invalid");
                await VerifyAsync(client, adminToken, Sign(lease, rotationKey, "rotation-key"), "valid");
                await VerifyMonitoringAsync(client, adminToken);
            }

            await using (var remoteCore = CoreHost.Build(trustedArgs, ConfigureClock(clock)))
            {
                remoteCore.Use(async (context, next) =>
                {
                    context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
                    await next(context);
                });
                using var client = await StartAsync(remoteCore);
                var adminToken = await LoginAsync(client, username, password);
                using var denied = await VerifyRequestAsync(client, adminToken, lease);
                Check(denied.StatusCode == HttpStatusCode.Forbidden && denied.Headers.CacheControl?.NoStore == true,
                    "Core permitted or allowed caching of remote plaintext HTTP lease verification.");
            }

            ExpectCoreConfigurationFailure(CoreArgs(dataDirectory,
                $"--SentinelAI:Licensing:TrustedPublicKeys:development-key={privatePath}"),
                "Core accepted server-side private signing material as a verification key.");
            ExpectCoreConfigurationFailure(CoreArgs(dataDirectory,
                $"--SentinelAI:Licensing:TrustedPublicKeys:development-key={malformedPublicPath}"),
                "Core accepted a malformed public key at startup.");
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", oldUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", oldPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine($"License API integration tests passed ({_assertions} assertions).");
    }

    private static async Task VerifyDevelopmentKeyGenerationAsync(string directory)
    {
        var generated = DevelopmentKeyGenerator.Generate(directory);
        Check(generated.Count == 4 && generated.All(File.Exists), "Development setup did not generate all key and activation files.");
        using var signing = ECDsa.Create();
        using var verifying = ECDsa.Create();
        var privatePem = await File.ReadAllTextAsync(Path.Combine(directory, "private.pem"));
        signing.ImportFromPem(privatePem);
        verifying.ImportFromPem(await File.ReadAllTextAsync(Path.Combine(directory, "public.pem")));
        var syntheticMessage = RandomNumberGenerator.GetBytes(32);
        var signature = signing.SignData(syntheticMessage, HashAlgorithmName.SHA256);
        Check(verifying.VerifyData(syntheticMessage, signature, HashAlgorithmName.SHA256),
            "Development generation returned unrelated public and private keys.");
        var activation = await File.ReadAllTextAsync(Path.Combine(directory, "activation-credential.txt"));
        var digest = await File.ReadAllTextAsync(Path.Combine(directory, "activation-credential.sha256"));
        Check(activation.Length == 43 && FromBase64Url(activation).Length == 32 &&
              digest == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(activation))),
            "Development activation files did not contain a matching random credential and digest.");
        if (!OperatingSystem.IsWindows())
        {
            Check(File.GetUnixFileMode(directory) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
                "Development generation left its directory readable by another user.");
            var privateFiles = true;
            foreach (var path in generated)
                privateFiles &= File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Check(privateFiles,
                "Development generation left key or activation files readable by another user.");
        }
        var refusedOverwrite = false;
        try
        {
            DevelopmentKeyGenerator.Generate(directory);
        }
        catch (IOException)
        {
            refusedOverwrite = true;
        }
        Check(refusedOverwrite && await File.ReadAllTextAsync(Path.Combine(directory, "private.pem")) == privatePem,
            "Development setup overwrote an existing signing key directory.");
    }

    private static async Task<string> VerifyIssuanceAsync(
        HttpClient client, CoreIdentity identity, string credential, string username, string password)
    {
        var body = new { organizationId = identity.OrganizationId, installationId = identity.CoreInstallationId };
        using (var anonymous = await PostAsync(client, IssuePath, body))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Cloud issued a lease without activation authentication.");
        using (var wrongCredential = await PostAsync(client, IssuePath, body, "Bearer", Base64Url(RandomNumberGenerator.GetBytes(32))))
            Check(wrongCredential.StatusCode == HttpStatusCode.Unauthorized, "Cloud accepted an unknown activation credential.");
        using (var wrongIdentity = await PostAsync(client, IssuePath,
                   new { organizationId = Guid.NewGuid(), installationId = identity.CoreInstallationId }, "Bearer", credential))
            Check(wrongIdentity.StatusCode == HttpStatusCode.Unauthorized, "Cloud issued another organization's entitlement.");
        using (var privilegeOverride = await PostAsync(client, IssuePath,
                   new { body.organizationId, body.installationId, plan = "unlimited", endpointLimit = int.MaxValue }, "Bearer", credential))
            Check(privilegeOverride.StatusCode == HttpStatusCode.BadRequest,
                "Cloud accepted client-selected subscription claims instead of the configured entitlement.");
        using var issued = await PostAsync(client, IssuePath, body, "Bearer", credential);
        Check(issued.StatusCode == HttpStatusCode.OK && issued.Headers.CacheControl?.NoStore == true,
            "Configured entitlement did not produce an uncached signed lease.");
        var content = await issued.Content.ReadAsStringAsync();
        Check(!content.Contains(credential, StringComparison.Ordinal) && !content.Contains(password, StringComparison.Ordinal) &&
              !content.Contains(username, StringComparison.Ordinal) && !content.Contains("PRIVATE KEY", StringComparison.Ordinal),
            "Issuance exposed activation, administrator, or signing credentials.");
        using var json = JsonDocument.Parse(content);
        var lease = json.RootElement.GetProperty("lease").GetString() ?? throw new Exception("Cloud omitted the lease.");
        Check(lease.Split('.').Length == 3, "Cloud did not issue a compact signed token.");
        var payload = Payload(lease);
        Check(payload["plan"]!.GetValue<string>() == "development-test" && payload["endpoint_limit"]!.GetValue<int>() == 4 &&
              payload["enabled_features"]!.AsArray().Select(node => node!.GetValue<string>()).SequenceEqual(["inventory", "risk"]),
            "Cloud lease did not reflect the server-selected subscription grant.");
        return lease;
    }

    private static async Task VerifyAccessAsync(WebApplication app, HttpClient client, string adminToken, string lease)
    {
        using (var anonymous = await PostAsync(client, VerifyPath, new { lease }))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Core verified a lease for an anonymous caller.");
        var store = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await store.IssueTokenAsync();
        var attempt = await store.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        var enrolled = attempt.Response ?? throw new Exception("Could not provision a synthetic Agent credential.");
        using (var agent = await PostAsync(client, VerifyPath, new { lease }, "SentinelAgent",
                   $"{enrolled.EndpointId:D}.{enrolled.AgentCredential}"))
            Check(agent.StatusCode == HttpStatusCode.Unauthorized, "Core accepted Agent credentials for administrator lease verification.");
        using (var credentialAsBearer = await VerifyRequestAsync(client, enrolled.AgentCredential, lease))
            Check(credentialAsBearer.StatusCode == HttpStatusCode.Unauthorized, "Core accepted an Agent credential as an administrator bearer token.");
        using (var authenticated = await VerifyRequestAsync(client, adminToken, lease))
            Check(authenticated.StatusCode == HttpStatusCode.OK && authenticated.Headers.CacheControl?.NoStore == true,
                "Administrator lease verification was unavailable or cacheable.");
    }

    private static async Task VerifyTamperingAsync(HttpClient client, string adminToken, string lease)
    {
        var parts = lease.Split('.');
        var changedClaims = Payload(lease);
        changedClaims["endpoint_limit"] = 999_999;
        await VerifyAsync(client, adminToken, $"{parts[0]}.{Base64Url(Encoding.UTF8.GetBytes(changedClaims.ToJsonString()))}.{parts[2]}", "invalid");
        var signature = FromBase64Url(parts[2]);
        signature[0] ^= 0x80;
        await VerifyAsync(client, adminToken, $"{parts[0]}.{parts[1]}.{Base64Url(signature)}", "invalid");
        var changedHeader = JsonNode.Parse(FromBase64Url(parts[0]))!.AsObject();
        changedHeader["alg"] = "none";
        await VerifyAsync(client, adminToken, $"{Base64Url(Encoding.UTF8.GetBytes(changedHeader.ToJsonString()))}.{parts[1]}.{parts[2]}", "invalid");
        changedHeader["alg"] = "ES256";
        changedHeader["kid"] = "untrusted-key";
        await VerifyAsync(client, adminToken, $"{Base64Url(Encoding.UTF8.GetBytes(changedHeader.ToJsonString()))}.{parts[1]}.{parts[2]}", "invalid");
        await VerifyAsync(client, adminToken, lease + ".extra", "invalid");
        await VerifyAsync(client, adminToken, "not.a.lease", "invalid");
    }

    private static async Task VerifyTimeAndBindingAsync(HttpClient client, string adminToken, string lease,
        ECDsa key, CoreIdentity identity, MutableTimeProvider clock, string username, string password)
    {
        var payload = Payload(lease);
        var issuedAt = DateTimeOffset.Parse(payload["issued_at"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        var fullModeUntil = DateTimeOffset.Parse(payload["full_mode_until"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        Check(fullModeUntil - issuedAt == TimeSpan.FromDays(7), "Cloud lease duration did not match its fixed seven-day policy.");
        clock.UtcNow = fullModeUntil.AddTicks(-1);
        // The same clock controls administrator bearer expiry. Authenticate at
        // the advanced time instead of extending the production token lifetime.
        var boundaryAdminToken = await LoginAsync(client, username, password);
        await VerifyAsync(client, boundaryAdminToken, lease, "valid");
        clock.UtcNow = fullModeUntil;
        await VerifyAsync(client, boundaryAdminToken, lease, "expired");
        clock.UtcNow = fullModeUntil.AddTicks(1);
        await VerifyAsync(client, boundaryAdminToken, lease, "expired");
        clock.UtcNow = issuedAt.AddTicks(-1);
        await VerifyAsync(client, adminToken, lease, "notYetValid");
        clock.UtcNow = issuedAt;
        await VerifyAsync(client, adminToken, lease, "valid");

        var anotherOrganization = Payload(lease);
        anotherOrganization["organization_id"] = Guid.NewGuid().ToString("D");
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", anotherOrganization), "identityMismatch");
        var anotherInstallation = Payload(lease);
        anotherInstallation["installation_id"] = Guid.NewGuid().ToString("D");
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", anotherInstallation), "identityMismatch");
        Check(payload["organization_id"]!.GetValue<string>() == identity.OrganizationId.ToString("D") &&
              payload["installation_id"]!.GetValue<string>() == identity.CoreInstallationId.ToString("D"),
            "Cloud lease was not bound to the persisted Core identity.");
    }

    private static async Task VerifySignedClaimValidationAsync(HttpClient client, string adminToken, string lease, ECDsa key)
    {
        var noEndpointLimit = Payload(lease);
        noEndpointLimit.Remove("endpoint_limit");
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", noEndpointLimit), "invalid");
        var negativeLimit = Payload(lease);
        negativeLimit["endpoint_limit"] = -1;
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", negativeLimit), "invalid");
        var longPlan = Payload(lease);
        longPlan["plan"] = new string('x', 1024);
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", longPlan), "invalid");
        var tooManyFeatures = Payload(lease);
        tooManyFeatures["enabled_features"] = new JsonArray(Enumerable.Range(0, 200).Select(index =>
            JsonValue.Create($"feature-{index}")).Cast<JsonNode?>().ToArray());
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", tooManyFeatures), "invalid");
        var invertedLifetime = Payload(lease);
        invertedLifetime["full_mode_until"] = DateTimeOffset.Parse(invertedLifetime["issued_at"]!.GetValue<string>(),
            System.Globalization.CultureInfo.InvariantCulture).AddSeconds(-1).ToString("O");
        await VerifyAsync(client, adminToken, Sign(lease, key, "development-key", invertedLifetime), "invalid");
    }

    private static async Task VerifyRequestBoundsAsync(HttpClient client, string adminToken, string lease)
    {
        using (var missing = await PostAsync(client, VerifyPath, new { unrelated = true }, "Bearer", adminToken))
            Check(missing.StatusCode == HttpStatusCode.BadRequest, "Core accepted a request without a lease.");
        using (var oversized = await VerifyRequestAsync(client, adminToken, new string('x', 25 * 1024)))
            Check(oversized.StatusCode == HttpStatusCode.RequestEntityTooLarge,
                "Core accepted a lease verification body beyond its configured request limit.");
        using (var invalidType = await PostAsync(client, VerifyPath, new { lease = 42 }, "Bearer", adminToken))
            Check(invalidType.StatusCode == HttpStatusCode.BadRequest, "Core accepted a nonstring lease token.");
        using var repeatedRequest = new HttpRequestMessage(HttpMethod.Post, VerifyPath)
        {
            Content = new StringContent("{\"lease\":\"" + lease + "\",\"lease\":\"not.a.lease\"}", Encoding.UTF8, "application/json")
        };
        repeatedRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        using var repeated = await client.SendAsync(repeatedRequest);
        Check(repeated.StatusCode == HttpStatusCode.BadRequest, "Core accepted ambiguous duplicate lease fields.");
    }

    private static async Task VerifyMonitoringAsync(HttpClient client, string adminToken)
    {
        using (var health = await client.GetAsync("/api/health"))
            Check(health.StatusCode == HttpStatusCode.OK, "License state disabled Core health monitoring.");
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/devices");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        using var devices = await client.SendAsync(request);
        Check(devices.StatusCode == HttpStatusCode.OK, "License state disabled the existing administrator device API.");
    }

    private static async Task<JsonElement> VerifyAsync(HttpClient client, string adminToken, string lease, string status)
    {
        using var response = await VerifyRequestAsync(client, adminToken, lease);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            "Core lease verification failed or allowed caching: " + status);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var result = json.RootElement.Clone();
        Check(result.GetProperty("status").GetString() == status, "Core returned the wrong lease verification state: " + status);
        if (status == "invalid")
            Check(result.GetProperty("claims").ValueKind == JsonValueKind.Null,
                "Core exposed unverified attacker-controlled lease claims.");
        return result;
    }

    private static Task<HttpResponseMessage> VerifyRequestAsync(HttpClient client, string adminToken, string lease) =>
        PostAsync(client, VerifyPath, new { lease }, "Bearer", adminToken);

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string path, object body,
        string? scheme = null, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (scheme is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        return await client.SendAsync(request);
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

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic Core administrator could not authenticate.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static string[] CoreArgs(string dataDirectory, params string[] extra) =>
        [$"--SentinelAI:DataDirectory={dataDirectory}", .. extra];

    private static string[] CloudArgs(string privatePath, CoreIdentity identity, string credential) =>
    [
        "--SentinelAI:LicenseApi:KeyId=development-key",
        $"--SentinelAI:LicenseApi:SigningPrivateKeyPath={privatePath}",
        $"--SentinelAI:LicenseApi:Entitlements:0:OrganizationId={identity.OrganizationId:D}",
        $"--SentinelAI:LicenseApi:Entitlements:0:InstallationId={identity.CoreInstallationId:D}",
        $"--SentinelAI:LicenseApi:Entitlements:0:ActivationCredentialSha256={Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)))}",
        "--SentinelAI:LicenseApi:Entitlements:0:Plan=development-test",
        "--SentinelAI:LicenseApi:Entitlements:0:EndpointLimit=4",
        "--SentinelAI:LicenseApi:Entitlements:0:EnabledFeatures:0=inventory",
        "--SentinelAI:LicenseApi:Entitlements:0:EnabledFeatures:1=risk"
    ];

    private static Action<WebApplicationBuilder> ConfigureClock(TimeProvider clock) =>
        builder => builder.Services.Replace(ServiceDescriptor.Singleton(clock));

    private static void ExpectCoreConfigurationFailure(string[] args, string message)
    {
        try
        {
            using var unexpected = CoreHost.Build(args);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or CryptographicException)
        {
            Check(true, message);
            return;
        }
        throw new Exception(message);
    }

    private static JsonObject Payload(string lease) => JsonNode.Parse(FromBase64Url(lease.Split('.')[1]))!.AsObject();

    private static string Sign(string template, ECDsa key, string keyId, JsonObject? payload = null)
    {
        var header = JsonNode.Parse(FromBase64Url(template.Split('.')[0]))!.AsObject();
        header["kid"] = keyId;
        var input = Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
                    Base64Url(Encoding.UTF8.GetBytes((payload ?? Payload(template)).ToJsonString()));
        var signature = key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return input + "." + Base64Url(signature);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string encoded) =>
        Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + new string('=', (4 - encoded.Length % 4) % 4));

    private static async Task WriteTestFileAsync(string path, string content)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var stream = new FileStream(path, options);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(content);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        _assertions++;
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
