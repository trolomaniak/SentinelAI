using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Agent;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Hosting;

// MVP-1: the Agent trusts the central Core only by its exact certificate SHA-256 and reaches it over
// the local-network HTTPS listener. Certificates and identities are synthetic and generated per run.
internal static class LocalNetworkTrustTests
{
    private static int assertions;

    public static async Task RunAsync(string root)
    {
        VerifyTrustRule();
        VerifyProtocols();
        await VerifyAgentOverListenerAsync(root);
        Console.WriteLine($"Local-network Agent trust tests passed ({assertions} assertions).");
    }

    private static void VerifyTrustRule()
    {
        using var certificate = CreateCertificate("synthetic-core");
        using var other = CreateCertificate("synthetic-core");
        var pin = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        foreach (var errors in new[]
                 {
                     SslPolicyErrors.None, SslPolicyErrors.RemoteCertificateChainErrors, SslPolicyErrors.RemoteCertificateNameMismatch,
                     SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch
                 })
        {
            Check(CoreCertificateTrust.IsTrusted(certificate, errors, pin),
                "The Agent refused Core's own certificate although its exact SHA-256 matches the pin.");
            Check(!CoreCertificateTrust.IsTrusted(other, errors, pin) &&
                  !CoreCertificateTrust.IsTrusted(certificate, errors, new string('0', 64)),
                "The Agent accepted a certificate whose SHA-256 differs from the pin.");
        }

        Check(!CoreCertificateTrust.IsTrusted(null, SslPolicyErrors.RemoteCertificateNotAvailable, pin) &&
              !CoreCertificateTrust.IsTrusted(certificate, SslPolicyErrors.RemoteCertificateNotAvailable, pin),
            "The Agent accepted a connection without Core's certificate.");
        // Without a pin the existing full validation stays: any chain or name error is refused.
        Check(CoreCertificateTrust.IsTrusted(certificate, SslPolicyErrors.None, null) &&
              !CoreCertificateTrust.IsTrusted(certificate, SslPolicyErrors.RemoteCertificateChainErrors, null) &&
              !CoreCertificateTrust.IsTrusted(certificate, SslPolicyErrors.RemoteCertificateNameMismatch, null) &&
              !CoreCertificateTrust.IsTrusted(null, SslPolicyErrors.None, null),
            "An unpinned Core connection no longer requires full certificate validation.");
    }

    private static void VerifyProtocols()
    {
        var pin = new string('A', 64);
        using (var pinned = AgentHost.CreateCoreHandler(Options("https://192.0.2.10:5443", pin)))
            Check(pinned.SslOptions.EnabledSslProtocols == (SslProtocols.Tls12 | SslProtocols.Tls13) &&
                  pinned.SslOptions.RemoteCertificateValidationCallback is not null && !pinned.UseProxy && !pinned.AllowAutoRedirect,
                "A pinned Core connection does not enable exactly TLS 1.2 and 1.3.");
        using (var unpinned = AgentHost.CreateCoreHandler(Options("https://127.0.0.1:5443", null)))
            Check(unpinned.SslOptions.EnabledSslProtocols == SslProtocols.Tls13 && unpinned.SslOptions.RemoteCertificateValidationCallback is not null,
                "An unpinned HTTPS Core connection no longer requires TLS 1.3.");
        using (var loopback = AgentHost.CreateCoreHandler(Options("http://127.0.0.1:5000", null)))
            Check(loopback.SslOptions.RemoteCertificateValidationCallback is null, "The loopback HTTP connection changed.");
    }

    private static async Task VerifyAgentOverListenerAsync(string root)
    {
        var username = $"test-admin-{Guid.NewGuid():N}";
        var password = $"Test-Only-{Guid.NewGuid():N}!";
        var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        using var certificate = CreateServerCertificate("synthetic-core");
        var pin = LocalNetworkCertificate.Sha256(certificate);
        var port = FreePort();
        try
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);
            await using var core = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "core")}", "--urls=http://127.0.0.1:0",
                $"--SentinelAI:LocalNetworkPort={port}", $"--SentinelAI:LocalNetworkCertificateSha256={pin}"], builder =>
            {
                builder.Logging.ClearProviders();
                builder.Services.AddSingleton<ILocalNetworkCertificateSource>(new FixedSource(certificate));
            });
            await core.StartAsync();
            try
            {
                using var local = new HttpClient(new HttpClientHandler { UseProxy = false })
                    { BaseAddress = new Uri(core.Urls.Single(url => url.StartsWith("http://", StringComparison.Ordinal))) };
                var token = await IssueTokenAsync(local, username, password);
                // The certificate names "synthetic-core", not 127.0.0.1, and chains to no trusted root:
                // only the pin can make the Agent trust it.
                var coreUrl = $"https://127.0.0.1:{port}";

                // A wrong pin is refused before any request, so the one-use token is not spent.
                var wrongDirectory = Path.Combine(root, "wrong-pin");
                using (var wrong = BuildAgent(wrongDirectory, coreUrl, new string('0', 64), token))
                {
                    await wrong.StartAsync();
                    await Task.Delay(TimeSpan.FromSeconds(2));
                    await StopPromptlyAsync(wrong);
                }
                Check(!File.Exists(Path.Combine(wrongDirectory, "enrollment-state")) &&
                      await core.Services.GetRequiredService<DeviceStore>().CountAsync() == 0,
                    "The Agent sent enrollment to a Core whose certificate does not match its pin.");

                // An unpinned HTTPS Core keeps full validation, so this certificate is refused.
                var unpinnedDirectory = Path.Combine(root, "unpinned");
                using (var unpinned = BuildAgent(unpinnedDirectory, coreUrl, null, token))
                {
                    await unpinned.StartAsync();
                    await Task.Delay(TimeSpan.FromSeconds(2));
                    await StopPromptlyAsync(unpinned);
                }
                Check(!File.Exists(Path.Combine(unpinnedDirectory, "enrollment-state")) &&
                      await core.Services.GetRequiredService<DeviceStore>().CountAsync() == 0,
                    "An unpinned Agent accepted a certificate that fails chain and name validation.");

                // The correct pin enrolls with the same token and reports through the local-network listener.
                var agentDirectory = Path.Combine(root, "agent");
                using var agent = BuildAgent(agentDirectory, coreUrl, pin, token);
                await agent.StartAsync();
                try
                {
                    var deadline = DateTime.UtcNow.AddSeconds(20);
                    InventoryRecordProbe? probe = null;
                    while (DateTime.UtcNow < deadline && probe is null)
                    {
                        probe = await FindReportedEndpointAsync(core);
                        if (probe is null) await Task.Delay(100);
                    }

                    Check(probe is not null && File.Exists(Path.Combine(agentDirectory, "enrollment-state")),
                        "The pinned Agent did not enroll and report over the local-network listener.");
                }
                finally
                {
                    await StopPromptlyAsync(agent);
                }
            }
            finally
            {
                await core.StopAsync();
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
            SqliteConnection.ClearAllPools();
        }
    }

    private sealed record InventoryRecordProbe(Guid EndpointId);

    // The enrolled endpoint with a heartbeat and an inventory, as Core's device list shows it.
    private static async Task<InventoryRecordProbe?> FindReportedEndpointAsync(WebApplication core)
    {
        var devices = await core.Services.GetRequiredService<DeviceReadStore>().ListAsync(CancellationToken.None);
        return devices is [{ LastSeenUtc: not null, InventoryCollectedUtc: not null } device]
            ? new InventoryRecordProbe(device.EndpointId) : null;
    }

    private static async Task<string> IssueTokenAsync(HttpClient client, string username, string password)
    {
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(login.StatusCode == HttpStatusCode.OK, "The local-network test administrator could not log in.");
        using var session = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/enrollment-tokens");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.RootElement.GetProperty("accessToken").GetString());
        using var issued = await client.SendAsync(request);
        return (await issued.Content.ReadFromJsonAsync<EnrollmentTokenResponse>())!.Token;
    }

    private static IHost BuildAgent(string dataDirectory, string coreUrl, string? pin, string token)
    {
        var builder = AgentHost.CreateBuilder([]);
        builder.Configuration["Agent:CoreUrl"] = coreUrl;
        builder.Configuration["Agent:DataDirectory"] = dataDirectory;
        builder.Configuration["Agent:HeartbeatInterval"] = "00:00:00.300";
        builder.Configuration["Agent:RetryDelay"] = "00:00:00.100";
        builder.Configuration["Agent:MaxRetryDelay"] = "00:00:00.300";
        builder.Configuration["Agent:EnrollmentToken"] = token;
        builder.Configuration["Agent:CoreCertificateSha256"] = pin;
        builder.Services.RemoveAll<IEventLogAccess>();
        builder.Services.AddSingleton<IEventLogAccess>(new NoEventLogAccess());
        return builder.Build();
    }

    private static AgentOptions Options(string coreUrl, string? pin) =>
        new(new Uri(coreUrl), Path.GetTempPath(), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(1), null, pin);

    private static X509Certificate2 CreateCertificate(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateServerCertificate(string name)
    {
        using var ephemeral = CreateCertificate(name);
        // Windows TLS needs a key in a key store rather than an ephemeral one.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task StopPromptlyAsync(IHost host)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await host.StopAsync(timeout.Token).WaitAsync(TimeSpan.FromSeconds(3));
    }

    private sealed class FixedSource(X509Certificate2 certificate) : ILocalNetworkCertificateSource
    {
        public X509Certificate2? Find(string sha256) => certificate;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        assertions++;
    }
}
