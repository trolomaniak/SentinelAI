using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
        builder.Services.AddSingleton<ISecurityPostureReader, SecurityPostureReader>();
        builder.Services.AddSingleton<InventoryCollector>();
        builder.Services.AddSingleton<IPostureChangeSource>(_ => OperatingSystem.IsWindows()
            ? RegistryPostureChangeSource.ForSecurityConfiguration()
            : new NoPostureChangeSource());
        builder.Services.AddSingleton<PostureMonitor>();
        builder.Services.AddSingleton(provider =>
            new HttpClient(CreateCoreHandler(provider.GetRequiredService<AgentOptions>())) { Timeout = TimeSpan.FromSeconds(10) });
        builder.Services.AddSingleton<AgentEnrollmentClient>();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AgentLink>();
        builder.Services.AddSingleton<IEventLogAccess>(provider => OperatingSystem.IsWindows()
            ? new WindowsEventLogAccess(SecurityEventCatalog.Production,
                SecurityEventTimings.From(provider.GetRequiredService<AgentOptions>()).ConfigurationRefresh)
            : new NoEventLogAccess());
        builder.Services.AddSingleton<EventCheckpointStore>();
        // Read once: the SCM texts of every installed display language, so detection does not depend on English.
        builder.Services.AddSingleton(_ => ServiceControlManagerText.Load());
        builder.Services.AddSingleton<ISecurityEventUploader, HttpSecurityEventUploader>();
        builder.Services.AddSingleton<SecurityEventPipeline>();
        builder.Services.AddSingleton<IEndpointTelemetrySource>(_ => OperatingSystem.IsWindows()
            ? new WindowsEndpointTelemetrySource()
            : new UnsupportedEndpointTelemetrySource());
        builder.Services.AddSingleton(provider => new EndpointTelemetryCollector(
            provider.GetRequiredService<IEndpointTelemetrySource>(), provider.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<IEndpointTelemetryUploader, HttpEndpointTelemetryUploader>();
        builder.Services.AddHostedService(provider => provider.GetRequiredService<PostureMonitor>());
        // Stops after the heartbeat worker: cancels any read, cancels an in-flight POST and flushes positions.
        builder.Services.AddHostedService(provider => provider.GetRequiredService<SecurityEventPipeline>());
        builder.Services.AddHostedService(provider => new EndpointTelemetryWorker(provider.GetRequiredService<AgentLink>(),
            provider.GetRequiredService<EndpointTelemetryCollector>(), provider.GetRequiredService<IEndpointTelemetryUploader>(),
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<EndpointTelemetryWorker>>()));
        // MVP-7: newer signed Agent packages offered by Core are fetched for the computer's SYSTEM updater.
        builder.Services.AddSingleton<AgentUpdateStager>();
        builder.Services.AddHostedService<AgentUpdateWorker>();
        builder.Services.AddHostedService<HeartbeatWorker>();

        return builder;
    }

    public static IHost Build(string[] args) => CreateBuilder(args).Build();

    public static SocketsHttpHandler CreateCoreHandler(AgentOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false
        };
        if (options.CoreUrl.Scheme == Uri.UriSchemeHttps)
        {
            // A pinned Core may run on Windows 10, which has no TLS 1.3; TLS 1.3 is still negotiated
            // whenever both sides support it. Unpinned HTTPS keeps TLS 1.3 only.
            handler.SslOptions.EnabledSslProtocols = options.CoreCertificateSha256 is null
                ? SslProtocols.Tls13 : SslProtocols.Tls12 | SslProtocols.Tls13;
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                CoreCertificateTrust.IsTrusted(certificate, errors, options.CoreCertificateSha256);
        }

        return handler;
    }
}

public static class CoreCertificateTrust
{
    // Owner decision (2026-10-19): with a pin, Core's own certificate is trusted when, and only when,
    // its exact SHA-256 matches, so chain and name errors are accepted only together with that match.
    // Without a pin, full chain and name validation applies unchanged.
    public static bool IsTrusted(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        string? expectedSha256)
    {
        if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
        {
            return false;
        }

        if (expectedSha256 is null)
        {
            return errors == SslPolicyErrors.None;
        }

        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.GetRawCertData()),
            Convert.FromHexString(expectedSha256));
    }
}
