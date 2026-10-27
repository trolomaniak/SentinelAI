using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using SentinelAI.Hosting;

namespace SentinelAI.Core;

// Core's local-network role: one HTTPS listener for Agents on other computers, next to the
// unchanged loopback HTTP listener for the local Desktop and Agent.
internal sealed record LocalNetworkOptions(int Port, string CertificateSha256)
{
    public const string PortKey = "SentinelAI:LocalNetworkPort";
    public const string CertificateKey = "SentinelAI:LocalNetworkCertificateSha256";

    public static LocalNetworkOptions? Load(IConfiguration configuration)
    {
        var portText = configuration[PortKey];
        var certificate = configuration[CertificateKey];
        if (portText is null && certificate is null) return null;
        if (portText is null || certificate is null ||
            !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
            port is < 1 or > 65535 || portText != port.ToString(CultureInfo.InvariantCulture) ||
            !LocalNetworkCertificate.IsSha256(certificate))
        {
            throw new InvalidOperationException(
                "The local-network listener requires a port and the uppercase SHA-256 of Core's certificate.");
        }

        return new LocalNetworkOptions(port, certificate);
    }

    // With the local-network listener the endpoints are configured in code, which replaces "urls";
    // the loopback HTTP origin is therefore bound explicitly and must be one loopback IP origin.
    public static IPEndPoint LoopbackEndpoint(string? urls, int localNetworkPort)
    {
        var text = string.IsNullOrWhiteSpace(urls) ? "http://127.0.0.1:5000" : urls.Trim();
        if (!Uri.TryCreate(text, UriKind.Absolute, out var origin) || origin.Scheme != Uri.UriSchemeHttp ||
            origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.UserInfo) || !string.IsNullOrEmpty(origin.Query) ||
            !string.IsNullOrEmpty(origin.Fragment) || !IPAddress.TryParse(origin.Host.Trim('[', ']'), out var address) ||
            !IPAddress.IsLoopback(address) || origin.Port == localNetworkPort)
        {
            throw new InvalidOperationException(
                "The local-network listener requires one loopback HTTP origin on another port for the local Desktop.");
        }

        return new IPEndPoint(address, origin.Port);
    }
}

internal interface ILocalNetworkCertificateSource
{
    X509Certificate2? Find(string sha256);
}

internal sealed class MachineStoreCertificateSource : ILocalNetworkCertificateSource
{
    // Core's certificate and its key ACL are provisioned by Setup in LocalMachine\My (Windows only).
    public X509Certificate2? Find(string sha256) =>
        OperatingSystem.IsWindows() ? LocalNetworkCertificate.FindInMachineStore(sha256) : null;
}

internal sealed class LocalNetworkState(LocalNetworkOptions? options)
{
    private volatile bool _listening;
    public LocalNetworkOptions? Options { get; } = options;
    public bool Listening => _listening;
    public void MarkListening() => _listening = true;
}

internal sealed record LocalNetworkView(
    bool Enabled,
    bool Listening,
    int? Port,
    string? CertificateSha256,
    string HostName,
    string? FullyQualifiedName,
    IReadOnlyList<string> Addresses)
{
    private const int MaximumAddresses = 16;

    public static LocalNetworkView From(LocalNetworkState state)
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var host = properties.HostName.TrimEnd('.');
        var domain = properties.DomainName.Trim('.');
        var options = state.Options;
        return new LocalNetworkView(options is not null, state.Listening, options?.Port, options?.CertificateSha256,
            host, domain.Length == 0 ? null : host + "." + domain, options is null ? [] : ActiveAddresses());
    }

    // IPv4 unicast addresses of the computer's active interfaces, without loopback and link-local.
    private static IReadOnlyList<string> ActiveAddresses()
    {
        var addresses = new SortedSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (network.OperationalStatus != OperationalStatus.Up ||
                    network.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                foreach (var unicast in network.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;
                    var bytes = address.GetAddressBytes();
                    if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address) ||
                        bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 0) continue;
                    addresses.Add(address.ToString());
                }
            }
        }
        catch (NetworkInformationException)
        {
            return [];
        }

        return addresses.Take(MaximumAddresses).ToArray();
    }
}

// Owner decision (2026-10-19): TLS 1.3 whenever both sides support it, TLS 1.2 only for Windows
// without TLS 1.3, and only ephemeral ECDHE key exchange with AES-GCM. Windows has no per-application
// cipher suite policy, so Core checks what each connection actually negotiated.
internal static class LocalNetworkTlsPolicy
{
    public const SslProtocols EnabledProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

    public static bool IsAllowed(SslProtocols protocol, TlsCipherSuite? cipherSuite) => protocol switch
    {
        // Every TLS 1.3 full handshake uses (EC)DHE; only its AES-GCM suites are accepted.
        SslProtocols.Tls13 => cipherSuite is TlsCipherSuite.TLS_AES_128_GCM_SHA256 or TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        SslProtocols.Tls12 => cipherSuite is TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 or
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 or TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        _ => false
    };
}

// Present on connections accepted by the local-network listener after the TLS gate.
internal sealed class LocalNetworkConnection
{
    public static readonly LocalNetworkConnection Marker = new();
    private LocalNetworkConnection() { }
}

internal static class LocalNetworkRoutes
{
    // The Agent routes only. Administrator, authentication, health and Desktop
    // routes stay on the loopback listener.
    private static readonly string[] AgentPaths =
    [
        "/api/agent/enroll", "/api/agent/enrollment-check", "/api/agent/heartbeat", "/api/agent/inventory",
        "/api/agent/security-events", "/api/agent/security-telemetry"
    ];

    // MVP-7: the signed Agent package, read by enrolled Agents.
    private static readonly string[] AgentReadPaths = ["/api/agent/update/manifest", "/api/agent/update/package"];

    public static bool IsAllowed(string method, string? path) =>
        path is not null &&
        (HttpMethods.IsPost(method) && AgentPaths.Any(allowed => string.Equals(path, allowed, StringComparison.OrdinalIgnoreCase)) ||
         HttpMethods.IsGet(method) && AgentReadPaths.Any(allowed => string.Equals(path, allowed, StringComparison.OrdinalIgnoreCase)));

    public static bool IsLocalNetworkRequest(HttpContext context) =>
        context.Features.Get<LocalNetworkConnection>() is not null;
}

internal static class LocalNetworkHosting
{
    public static void Configure(WebApplicationBuilder builder, LocalNetworkOptions options)
    {
        var loopback = LocalNetworkOptions.LoopbackEndpoint(builder.Configuration["urls"], options.Port);
        // Both endpoints are bound below; no hosting URL may add or override one.
        builder.WebHost.UseSetting(WebHostDefaults.ServerUrlsKey, string.Empty);
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(loopback);
            var services = kestrel.ApplicationServices;
            var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SentinelAI.Core.LocalNetwork");
            X509Certificate2? certificate;
            try
            {
                certificate = services.GetRequiredService<ILocalNetworkCertificateSource>().Find(options.CertificateSha256);
            }
            catch (Exception exception) when (exception is CryptographicException or InvalidOperationException or UnauthorizedAccessException)
            {
                certificate = null;
            }

            if (certificate is null)
            {
                // Local monitoring continues on loopback; Desktop Settings shows the listener as not listening.
                logger.LogError("Local-network listener disabled: the configured Core certificate is unavailable.");
                return;
            }

            // Kestrel binds every endpoint or none, so a port another program holds must not stop the loopback origin.
            if (!PortAvailable(options.Port))
            {
                logger.LogError("Local-network listener disabled: port {Port} is in use by another program.", options.Port);
                certificate.Dispose();
                return;
            }

            // Every IPv4 interface: Agents use IPv4 addresses, and Windows keeps separate IPv4 and IPv6 wildcard ports,
            // so Core holds the IPv4 port itself and no program started later can take Agent traffic.
            kestrel.Listen(IPAddress.Any, options.Port, listen =>
            {
                listen.Protocols = HttpProtocols.Http1;
                listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificate = certificate,
                    SslProtocols = LocalNetworkTlsPolicy.EnabledProtocols,
                    ClientCertificateMode = ClientCertificateMode.NoCertificate,
                    CheckCertificateRevocation = false,
                    HandshakeTimeout = TimeSpan.FromSeconds(10)
                });
                listen.Use(next => connection =>
                {
                    var tls = connection.Features.Get<ITlsHandshakeFeature>();
                    if (tls is null || !LocalNetworkTlsPolicy.IsAllowed(tls.Protocol, tls.NegotiatedCipherSuite))
                    {
                        logger.LogWarning("Local-network connection refused: TLS {Protocol} with {CipherSuite} is not permitted.",
                            tls?.Protocol, tls?.NegotiatedCipherSuite);
                        connection.Abort(new ConnectionAbortedException("TLS policy."));
                        return Task.CompletedTask;
                    }

                    connection.Features.Set(LocalNetworkConnection.Marker);
                    return next(connection);
                });
            });
            services.GetRequiredService<LocalNetworkState>().MarkListening();
        });
    }

    // Binds the IPv4 port the way Kestrel will and releases it at once.
    internal static bool PortAvailable(int port)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Bind(socket, new IPEndPoint(IPAddress.Any, port));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static void Bind(Socket socket, IPEndPoint endpoint)
    {
        // Like Kestrel's socket transport: address reuse outside Windows only, for ports still in TIME_WAIT.
        if (!OperatingSystem.IsWindows()) socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.Bind(endpoint);
        socket.Listen(1);
    }
}

internal sealed record EnrollmentCheckRequest(string? EnrollmentToken);
internal sealed record EnrollmentCodeRequest(int Count, int ValidityHours, string? Address);
internal sealed record EnrollmentCodeItem(Guid Id, string Code, DateTimeOffset ExpiresUtc);
internal sealed record EnrollmentCodeBatch(IReadOnlyList<EnrollmentCodeItem> Codes);
internal sealed record UnusedEnrollmentCodes(IReadOnlyList<SentinelAI.Core.Persistence.UnusedEnrollmentCode> Codes);
internal sealed record EnrollmentAddress(string Value, string Kind, bool Resolves);

// The addresses an enrollment code may carry: the central computer's DNS names (recommended when they resolve to one
// of its IPv4 addresses) and its active IPv4 addresses. Codes need the local-network listener to be configured.
internal sealed record EnrollmentCodeOptions(bool Available, bool Listening, int? Port, string? RecommendedAddress,
    IReadOnlyList<EnrollmentAddress> Addresses)
{
    private static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(2);

    public static async Task<EnrollmentCodeOptions> BuildAsync(LocalNetworkState state, CancellationToken cancellationToken)
    {
        if (state.Options is not { } options) return new EnrollmentCodeOptions(false, false, null, null, []);
        var view = LocalNetworkView.From(state);
        var addresses = new List<EnrollmentAddress>();
        foreach (var name in new[] { view.FullyQualifiedName, view.HostName })
        {
            var ascii = AsciiName(name);
            if (ascii is null || addresses.Any(address => string.Equals(address.Value, ascii, StringComparison.OrdinalIgnoreCase))) continue;
            addresses.Add(new EnrollmentAddress(ascii, "name", await ResolvesToAsync(ascii, view.Addresses, cancellationToken)));
        }

        addresses.AddRange(view.Addresses.Where(SentinelAI.Enrollment.EnrollmentCode.IsAddress).Select(address => new EnrollmentAddress(address, "ipv4", true)));
        var recommended = addresses.FirstOrDefault(address => address.Kind == "name" && address.Resolves) ??
                          addresses.FirstOrDefault(address => address.Kind == "ipv4");
        return new EnrollmentCodeOptions(true, state.Listening, options.Port, recommended?.Value, addresses);
    }

    private static string? AsciiName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        try
        {
            var ascii = name.All(char.IsAscii) ? name : new IdnMapping().GetAscii(name);
            return SentinelAI.Enrollment.EnrollmentCode.IsAddress(ascii) && !IPAddress.TryParse(ascii, out _) ? ascii : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static async Task<bool> ResolvesToAsync(string name, IReadOnlyList<string> local, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ResolveTimeout);
        try
        {
            var resolved = await Dns.GetHostAddressesAsync(name, AddressFamily.InterNetwork, timeout.Token);
            return resolved.Any(address => local.Contains(address.ToString()));
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException or ArgumentException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return false;
        }
    }
}
