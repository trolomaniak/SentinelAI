using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using SentinelAI.Hosting;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SentinelAI.Agent;

public static class AgentHost
{
    public static HostApplicationBuilder CreateBuilder(string[] args)
    {
        var pilot = PilotHostConfiguration.Read(args, agent: true);
        var builder = pilot.Values is null ? Host.CreateApplicationBuilder(args) :
            Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
            {
                Args = pilot.Arguments,
                ContentRootPath = AppContext.BaseDirectory
            });
        if (pilot.Values is not null)
        {
            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("Agent__EnrollmentToken")))
                throw new InvalidOperationException("Pilot configuration cannot be combined with an environment enrollment token.");
            builder.Configuration.Sources.Clear();
            builder.Configuration.AddInMemoryCollection(pilot.Values);
            // Validate before the service host starts, without reading the temporary token.
            _ = AgentOptions.FromConfiguration(builder.Configuration);
        }
        builder.Services.AddWindowsService(options => options.ServiceName = "SentinelAIAgent");

        builder.Services.AddSingleton(provider =>
            AgentOptions.FromConfiguration(provider.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>()));
        builder.Services.AddSingleton<InstallationIdentityStore>();
        builder.Services.AddSingleton<EnrollmentStateStore>();
        builder.Services.AddSingleton<InventoryCollector>();
        builder.Services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<AgentOptions>();
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false
            };
            if (options.CoreUrl.Scheme == Uri.UriSchemeHttps)
            {
                handler.SslOptions.EnabledSslProtocols = SslProtocols.Tls13;
                handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    CoreCertificateTrust.IsTrusted(certificate, errors, options.CoreCertificateSha256);
            }

            return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        });
        builder.Services.AddSingleton<AgentEnrollmentClient>();
        builder.Services.AddHostedService<HeartbeatWorker>();

        return builder;
    }

    public static IHost Build(string[] args) => CreateBuilder(args).Build();
}

public static class CoreCertificateTrust
{
    public static bool IsTrusted(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        string? expectedSha256)
    {
        if (certificate is null || errors != SslPolicyErrors.None)
        {
            return false;
        }

        return expectedSha256 is null || CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.GetRawCertData()),
            Convert.FromHexString(expectedSha256));
    }
}
