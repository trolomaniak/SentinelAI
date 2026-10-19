using System.ComponentModel;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Hosting;

// MVP-1: Core's local-network listener (TLS gate, Agent-only routes, certificate, admin view).
// Certificates are generated per run; no real customer data is used.
internal static class LocalNetworkTests
{
    private static int assertions;

    public static async Task RunAsync(string username, string password)
    {
        VerifyOptions();
        VerifyTlsPolicy();
        VerifyRoutes();
        VerifyCertificateRequest();
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-local-network-{Guid.NewGuid():N}");
        var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        try
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);
            using var certificate = CreateServerCertificate("synthetic-core");
            await VerifyListenerAsync(Path.Combine(root, "listener"), certificate, username, password);
            await VerifyUnavailableCertificateAsync(Path.Combine(root, "missing"), username, password);
            await VerifyOccupiedPortAsync(Path.Combine(root, "occupied"), certificate, username, password);
            await VerifyLocalOnlyAsync(Path.Combine(root, "local-only"), username, password);
            if (OperatingSystem.IsWindows() && IsElevated())
                await VerifyMachineCertificateAsync(Path.Combine(root, "machine"), username, password);
            else
                Console.WriteLine("Local-network machine certificate checks require elevated Windows; they run on Windows CI.");
            Console.WriteLine($"Local-network listener tests passed ({assertions} assertions).");
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static void VerifyOptions()
    {
        var pin = new string('A', 64);
        Check(LocalNetworkOptions.Load(Configuration()) is null, "Core enabled the local network without configuration.");
        Check(LocalNetworkOptions.Load(Configuration(("SentinelAI:LocalNetworkPort", "5443"), ("SentinelAI:LocalNetworkCertificateSha256", pin)))
              == new LocalNetworkOptions(5443, pin), "Core rejected the default local-network configuration.");
        foreach (var (port, certificate) in new (string?, string?)[]
                 {
                     ("5443", null), (null, pin), ("0", pin), ("65536", pin), ("05443", pin), ("+5443", pin), (" 5443", pin),
                     ("5443", pin.ToLowerInvariant()), ("5443", new string('A', 63)), ("5443", new string('G', 64)), ("5443", "")
                 })
        {
            var values = new List<(string, string?)>();
            if (port is not null) values.Add(("SentinelAI:LocalNetworkPort", port));
            if (certificate is not null) values.Add(("SentinelAI:LocalNetworkCertificateSha256", certificate));
            Reject(() => LocalNetworkOptions.Load(Configuration(values.ToArray())), "Core accepted an invalid local-network configuration.");
        }

        Check(LocalNetworkOptions.LoopbackEndpoint(null, 5443).Equals(new IPEndPoint(IPAddress.Loopback, 5000)) &&
              LocalNetworkOptions.LoopbackEndpoint("http://127.0.0.1:5000", 5443).Equals(new IPEndPoint(IPAddress.Loopback, 5000)) &&
              LocalNetworkOptions.LoopbackEndpoint("http://[::1]:5001", 5443).Equals(new IPEndPoint(IPAddress.IPv6Loopback, 5001)),
            "Core did not keep the loopback Desktop origin next to the local-network listener.");
        foreach (var urls in new[]
                 {
                     "http://localhost:5000", "http://0.0.0.0:5000", "http://192.0.2.10:5000", "https://127.0.0.1:5000",
                     "http://127.0.0.1:5443", "http://127.0.0.1:5000/path", "http://127.0.0.1:5000;http://[::1]:5000", "not a url"
                 })
        {
            Reject(() => LocalNetworkOptions.LoopbackEndpoint(urls, 5443), "Core accepted a non-loopback or ambiguous Desktop origin.");
        }
    }

    private static void VerifyTlsPolicy()
    {
        foreach (var suite in new[] { TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsCipherSuite.TLS_AES_256_GCM_SHA384 })
            Check(LocalNetworkTlsPolicy.IsAllowed(SslProtocols.Tls13, suite), "The TLS gate refused TLS 1.3 with AES-GCM.");
        foreach (var suite in new[]
                 {
                     TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                     TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                 })
            Check(LocalNetworkTlsPolicy.IsAllowed(SslProtocols.Tls12, suite), "The TLS gate refused TLS 1.2 ECDHE with AES-GCM.");
        foreach (var suite in new TlsCipherSuite?[]
                 {
                     null, TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, TlsCipherSuite.TLS_AES_128_CCM_SHA256,
                     TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                 })
            Check(!LocalNetworkTlsPolicy.IsAllowed(SslProtocols.Tls13, suite), "The TLS gate accepted TLS 1.3 without AES-GCM.");
        foreach (var suite in new TlsCipherSuite?[]
                 {
                     null, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                     TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                     TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                     TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TlsCipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                     TlsCipherSuite.TLS_AES_128_GCM_SHA256
                 })
            Check(!LocalNetworkTlsPolicy.IsAllowed(SslProtocols.Tls12, suite), "The TLS gate accepted TLS 1.2 without ECDHE and AES-GCM.");
#pragma warning disable SYSLIB0039, CS0618 // Obsolete protocols are exactly what the gate must refuse.
        foreach (var protocol in new[] { SslProtocols.None, SslProtocols.Ssl2, SslProtocols.Ssl3, SslProtocols.Tls, SslProtocols.Tls11,
                     SslProtocols.Tls12 | SslProtocols.Tls13 })
#pragma warning restore SYSLIB0039, CS0618
            Check(!LocalNetworkTlsPolicy.IsAllowed(protocol, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) &&
                  !LocalNetworkTlsPolicy.IsAllowed(protocol, TlsCipherSuite.TLS_AES_128_GCM_SHA256),
                "The TLS gate accepted a protocol below TLS 1.2.");
        Check(LocalNetworkTlsPolicy.EnabledProtocols == (SslProtocols.Tls12 | SslProtocols.Tls13),
            "The local-network listener enables a protocol other than TLS 1.2 and 1.3.");
    }

    private static void VerifyRoutes()
    {
        foreach (var path in new[] { "/api/agent/enroll", "/api/agent/heartbeat", "/api/agent/inventory", "/api/agent/security-events",
                     "/api/agent/security-telemetry", "/API/Agent/Heartbeat" })
            Check(LocalNetworkRoutes.IsAllowed("POST", path), "The local-network listener refused an Agent route.");
        foreach (var (method, path) in new (string, string?)[]
                 {
                     ("GET", "/api/agent/heartbeat"), ("PUT", "/api/agent/inventory"), ("POST", "/api/agent/heartbeat/"),
                     ("POST", "/api/auth/login"), ("GET", "/api/admin/me"), ("POST", "/api/admin/enrollment-tokens"),
                     ("GET", "/api/admin/local-network"), ("GET", "/api/health"), ("GET", "/"), ("GET", "/index.html"),
                     ("GET", "/assets/app.js"), ("POST", "/api/agent"), ("POST", "/api/agent/enroll/extra"), ("POST", null), ("POST", "")
                 })
            Check(!LocalNetworkRoutes.IsAllowed(method, path), "The local-network listener allowed a non-Agent route.");
    }

    private static void VerifyCertificateRequest()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = new DateTimeOffset(2026, 10, 19, 12, 30, 15, 123, TimeSpan.Zero);
        var (notBefore, notAfter) = LocalNetworkCertificateProvisioning.Validity(now);
        Check(notBefore == new DateTimeOffset(2026, 10, 19, 11, 30, 15, TimeSpan.Zero) && notAfter == notBefore.AddYears(10),
            "Core's certificate is not valid for ten years from installation.");
        using var certificate = LocalNetworkCertificateProvisioning.CreateRequest(key, "synthetic-core", "synthetic-core.corp.example")
            .CreateSelfSigned(notBefore, notAfter);
        Check(certificate.Subject == "CN=synthetic-core" && certificate.GetECDsaPublicKey() is { KeySize: 256 } &&
              certificate.SignatureAlgorithm.Value == "1.2.840.10045.4.3.2",
            "Core's certificate is not an ECDSA P-256 certificate for the computer name.");
        var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames().ToArray();
        Check(names.SequenceEqual(["synthetic-core", "synthetic-core.corp.example"]),
            "Core's certificate subject names are not the computer's DNS name and FQDN.");
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().Single();
        var enhanced = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Check(!constraints.CertificateAuthority && constraints.Critical && usage.Critical &&
              usage.KeyUsages == X509KeyUsageFlags.DigitalSignature &&
              enhanced.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value).SequenceEqual(["1.3.6.1.5.5.7.3.1"]),
            "Core's certificate could act as a certificate authority or for purposes other than server authentication.");
        using var sameName = LocalNetworkCertificateProvisioning.CreateRequest(key, "synthetic-core", null).CreateSelfSigned(notBefore, notAfter);
        Check(sameName.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames().SequenceEqual(["synthetic-core"]),
            "A computer without a DNS domain received an invented FQDN.");
        foreach (var name in new[] { "", "bad name", "-leading", "trailing-", "a..b", new string('a', 64) })
            Reject(() => LocalNetworkCertificateProvisioning.CreateRequest(key, name, null), "Core's certificate accepted an invalid DNS name.");

        // Computer names: Windows accepts national letters and underscores; the names are informational and
        // never block the certificate, so they become IDN A-labels or the fixed fallback name.
        foreach (var (host, domain, expectedHost, expectedFqdn) in new (string, string, string, string?)[]
        {
            ("SYNTHETIC-CORE", "corp.example.", "SYNTHETIC-CORE", "SYNTHETIC-CORE.corp.example"),
            ("synthetic_core", "", "synthetic_core", null),
            ("Ksi\u0119gowo\u015b\u0107", "", "xn--ksigowo-c5a1nq1a", null),
            ("B\u00fcro-PC", "corp.example", "xn--bro-pc-3ya", "xn--bro-pc-3ya.corp.example"),
            ("B?ro-PC", "corp.example", LocalNetworkCertificateProvisioning.FallbackHostName, null),
            ("B\ufffdro-PC", "", LocalNetworkCertificateProvisioning.FallbackHostName, null),
            ("", "corp.example", LocalNetworkCertificateProvisioning.FallbackHostName, null),
            ("synthetic-core", "bad domain", "synthetic-core", null)
        })
        {
            var computer = LocalNetworkCertificateProvisioning.ComputerNames(host, domain);
            Check(string.Equals(computer.HostName, expectedHost, StringComparison.OrdinalIgnoreCase) &&
                  string.Equals(computer.FullyQualifiedName, expectedFqdn, StringComparison.OrdinalIgnoreCase),
                $"Core's certificate names for a computer named '{host}' were {computer.HostName} and {computer.FullyQualifiedName}.");
            using var named = LocalNetworkCertificateProvisioning.CreateRequest(key, computer.HostName, computer.FullyQualifiedName)
                .CreateSelfSigned(notBefore, notAfter);
            Check(named.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames().First()
                    .Equals(computer.HostName, StringComparison.OrdinalIgnoreCase),
                "Core's certificate does not carry the computer's DNS name.");
        }
        Check(LocalNetworkCertificate.Sha256(certificate) == Convert.ToHexString(SHA256.HashData(certificate.RawData)) &&
              LocalNetworkCertificate.IsSha256(LocalNetworkCertificate.Sha256(certificate)),
            "The exported pin is not the uppercase SHA-256 of the raw certificate.");
        Check(LocalNetworkCertificateProvisioning.KeySecurityDescriptorSddl ==
              "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900)",
            "Core's key ACL is not limited to SYSTEM, Administrators and Core's service account.");

        // The DACL check accepts the requested masks and the form Microsoft Software KSP reports, and nothing wider.
        const string system = "S-1-5-18", administrators = "S-1-5-32-544", core = LocalNetworkCertificate.CoreServiceSid;
        (bool, string, uint)[] Access(uint full, uint read) => [(true, system, full), (true, administrators, full), (true, core, read)];
        Check(LocalNetworkCertificateProvisioning.HasExpectedKeyAccess(true, Access(0x1F01FF, 0x120089)) &&
              LocalNetworkCertificateProvisioning.HasExpectedKeyAccess(true, Access(0xD01F01FF, 0x80120089)),
            "The key ACL check rejected the ACL Setup requests or the form Windows reports.");
        foreach (var (protectedDacl, entries, reason) in new (bool, (bool, string, uint)[], string)[]
        {
            (false, Access(0x1F01FF, 0x120089), "an inheritable DACL"),
            (true, Access(0x1F01FF, 0x120089 | 0x2), "Core write access"),
            (true, Access(0x1F01FF, 0x120089 | 0x10000), "Core delete access"),
            (true, Access(0x1F01FF, 0x120089 | 0x40000), "Core permission changes"),
            (true, Access(0x1F01FF, 0x80120089 | 0x40000000), "Core generic write access"),
            (true, Access(0x1F01FF, 0x10000000), "Core generic full control"),
            (true, Access(0x1F01FF, 0x80000000), "Core without specific read access"),
            (true, Access(0x120089, 0x120089), "SYSTEM and Administrators without full control"),
            (true, [.. Access(0x1F01FF, 0x120089), (true, "S-1-5-32-545", 0x120089)], "Users read access"),
            (true, [(true, system, 0x1F01FF), (true, administrators, 0x1F01FF), (true, "S-1-5-11", 0x120089)], "Authenticated Users instead of Core"),
            (true, [(true, system, 0x1F01FF), (true, system, 0x1F01FF), (true, core, 0x120089)], "a duplicate identity"),
            (true, [(true, system, 0x1F01FF), (false, administrators, 0x1F01FF), (true, core, 0x120089)], "a deny entry"),
            (true, Access(0x1F01FF, 0x120089)[..2], "no access for Core")
        })
        {
            Check(!LocalNetworkCertificateProvisioning.HasExpectedKeyAccess(protectedDacl, entries), "The key ACL check accepted " + reason + ".");
        }
    }

    private static async Task VerifyListenerAsync(string directory, X509Certificate2 certificate, string username, string password)
    {
        var pin = LocalNetworkCertificate.Sha256(certificate);
        var port = FreePort();
        await using var app = BuildCore(directory, port, pin, new FixedSource(certificate));
        await app.StartAsync();
        var loopback = new Uri(app.Urls.Single(url => url.StartsWith("http://", StringComparison.Ordinal)));
        Check(loopback.IsLoopback && app.Urls.Count == 2 && app.Urls.Any(url => url.StartsWith("https://", StringComparison.Ordinal) &&
              url.EndsWith(":" + port, StringComparison.Ordinal)), "Core did not bind loopback HTTP and the local-network HTTPS listener.");
        // Core holds the IPv4 wildcard port itself, so a program started later cannot take the Agents' traffic.
        Check(app.Urls.Any(url => url == $"https://0.0.0.0:{port}") && !LocalNetworkHosting.PortAvailable(port),
            "Another program could take the local-network IPv4 port while Core listens.");
        using var local = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = loopback, Timeout = TimeSpan.FromSeconds(10) };
        using var network = PinnedClient(new Uri($"https://127.0.0.1:{port}/"), pin);
        var token = await LoginAsync(local, username, password);

        using (var view = await GetAsync(local, "/api/admin/local-network", token))
        {
            Check(view.StatusCode == HttpStatusCode.OK && view.Headers.CacheControl?.NoStore == true, "Desktop could not read the local-network settings.");
            using var json = JsonDocument.Parse(await view.Content.ReadAsStringAsync());
            var root = json.RootElement;
            Check(root.GetProperty("enabled").GetBoolean() && root.GetProperty("listening").GetBoolean() &&
                  root.GetProperty("port").GetInt32() == port && root.GetProperty("certificateSha256").GetString() == pin &&
                  root.GetProperty("addresses").ValueKind == JsonValueKind.Array &&
                  root.GetProperty("addresses").EnumerateArray().All(address =>
                      IPAddress.TryParse(address.GetString(), out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork &&
                      !IPAddress.IsLoopback(parsed)) &&
                  !string.IsNullOrEmpty(root.GetProperty("hostName").GetString()),
                "The local-network settings do not show the listener, port, pin and addresses.");
        }
        using (var anonymous = await local.GetAsync("/api/admin/local-network"))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "The local-network settings were readable without authentication.");
        using (var health = await local.GetAsync("/api/health"))
            Check(health.StatusCode == HttpStatusCode.OK, "The loopback Desktop origin stopped serving health.");

        // Administrator, authentication, health, dashboard and Desktop routes are refused on the local network,
        // even with a valid administrator bearer and from this computer.
        foreach (var (method, path, bearer) in new (HttpMethod, string, bool)[]
                 {
                     (HttpMethod.Get, "/api/health", false), (HttpMethod.Get, "/", false), (HttpMethod.Get, "/index.html", false),
                     (HttpMethod.Get, "/assets/app.js", false), (HttpMethod.Post, "/api/auth/login", false),
                     (HttpMethod.Get, "/api/admin/me", true), (HttpMethod.Get, "/api/admin/devices", true),
                     (HttpMethod.Get, "/api/admin/local-network", true), (HttpMethod.Post, "/api/admin/enrollment-tokens", true),
                     (HttpMethod.Get, "/api/admin/license", true), (HttpMethod.Get, "/api/agent/heartbeat", false)
                 })
        {
            using var request = new HttpRequestMessage(method, path);
            if (bearer) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (path == "/api/auth/login") request.Content = JsonContent.Create(new { username, password });
            using var refused = await network.SendAsync(request);
            Check(refused.StatusCode == HttpStatusCode.NotFound && refused.Headers.CacheControl?.NoStore == true &&
                  (await refused.Content.ReadAsByteArrayAsync()).Length == 0,
                "The local-network listener served an administrator, authentication or Desktop route.");
        }

        // An Agent on another computer enrolls and reports through the pinned HTTPS listener.
        var issued = await PostAsync(local, "/api/admin/enrollment-tokens", token);
        var enrollmentToken = JsonDocument.Parse(issued).RootElement.GetProperty("token").GetString()!;
        var installationId = Guid.NewGuid();
        using var enrolled = await network.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(installationId, enrollmentToken));
        Check(enrolled.StatusCode == HttpStatusCode.OK, "An Agent could not enroll over the local-network listener.");
        var identity = (await enrolled.Content.ReadFromJsonAsync<EnrollmentResponse>())!;
        using (var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat") { Content = JsonContent.Create(new HeartbeatRequest(installationId)) })
        {
            heartbeat.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{identity.EndpointId:D}.{identity.AgentCredential}");
            using var accepted = await network.SendAsync(heartbeat);
            Check(accepted.StatusCode == HttpStatusCode.OK, "An enrolled Agent could not send a heartbeat over the local network.");
        }
        var inventory = new InventoryReport(identity.EndpointId, DateTimeOffset.UtcNow, "0.1.0-test", "synthetic-network-endpoint",
            "Windows", "10.0.19045.0", "X64", new("Synthetic CPU", 4), null, [], new(true, true, true));
        using (var report = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory") { Content = JsonContent.Create(inventory) })
        {
            report.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{identity.EndpointId:D}.{identity.AgentCredential}");
            using var accepted = await network.SendAsync(report);
            Check(accepted.StatusCode == HttpStatusCode.NoContent, "An enrolled Agent could not report inventory over the local network.");
        }
        using (var oversized = await network.PostAsync("/api/agent/enroll",
                   new StringContent("{\"installationId\":\"" + Guid.NewGuid() + "\",\"enrollmentToken\":\"" + new string('a', 17 * 1024) + "\"}",
                       Encoding.UTF8, "application/json")))
            Check(oversized.StatusCode == HttpStatusCode.RequestEntityTooLarge, "Core read an oversized enrollment body from the local network.");

        await VerifyTlsGateAsync(port, pin);
        await app.StopAsync();
    }

    private static async Task VerifyTlsGateAsync(int port, string pin)
    {
        // TLS 1.2 with ECDHE and AES-GCM, the Windows 10 case, is accepted.
        var (protocol, suite, response) = await RawRequestAsync(port, pin, SslProtocols.Tls12, null);
        Check(protocol == SslProtocols.Tls12 && LocalNetworkTlsPolicy.IsAllowed(protocol, suite) &&
              response.StartsWith("HTTP/1.1 404", StringComparison.Ordinal), "Core refused TLS 1.2 with ECDHE and AES-GCM.");
        (protocol, suite, response) = await RawRequestAsync(port, pin, SslProtocols.Tls12 | SslProtocols.Tls13, null);
        Check(LocalNetworkTlsPolicy.IsAllowed(protocol, suite) && response.StartsWith("HTTP/1.1 404", StringComparison.Ordinal),
            "Core refused the protocol both sides negotiated.");
        if (protocol != SslProtocols.Tls13)
            Console.WriteLine("This platform negotiated TLS 1.2 although both sides enable TLS 1.3.");
#pragma warning disable SYSLIB0039 // Core must refuse TLS 1.1 clients.
        Check(await HandshakeFailsAsync(port, pin, SslProtocols.Tls11), "Core accepted a TLS 1.1 handshake.");
#pragma warning restore SYSLIB0039

        // Windows has no per-application cipher suite policy; elsewhere a client can force a suite the gate refuses.
        if (!OperatingSystem.IsWindows())
        {
            foreach (var (refusedProtocol, refusedSuite) in new[]
                     {
                         (SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
                         (SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
                         (SslProtocols.Tls13, TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256)
                     })
            {
                try
                {
                    var (negotiated, negotiatedSuite, refusedResponse) = await RawRequestAsync(port, pin, refusedProtocol, [refusedSuite]);
                    Check(negotiatedSuite == refusedSuite && refusedResponse.Length == 0,
                        "Core answered a connection whose negotiated cipher suite is not ECDHE with AES-GCM.");
                    _ = negotiated;
                }
                catch (Exception exception) when (exception is IOException or AuthenticationException)
                {
                    // The server aborts right after the handshake; a client may observe that during the handshake.
                    assertions++;
                }
            }
        }
    }

    private static async Task VerifyUnavailableCertificateAsync(string directory, string username, string password)
    {
        var port = FreePort();
        await using var app = BuildCore(directory, port, new string('B', 64), new FixedSource(null));
        await app.StartAsync();
        Check(app.Urls.Count == 1, "Core opened the local-network listener without its certificate.");
        using var local = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()) };
        var token = await LoginAsync(local, username, password);
        using var view = await GetAsync(local, "/api/admin/local-network", token);
        using var json = JsonDocument.Parse(await view.Content.ReadAsStringAsync());
        Check(json.RootElement.GetProperty("enabled").GetBoolean() && !json.RootElement.GetProperty("listening").GetBoolean(),
            "Desktop could not see that the local-network listener is unavailable.");
        using var probe = new TcpClient();
        Reject(() => probe.Connect(IPAddress.Loopback, port), "Core listened on the local network without its certificate.");
        await app.StopAsync();
    }

    // Another program holding the local-network port after a restart leaves the loopback origin and local monitoring running.
    private static async Task VerifyOccupiedPortAsync(string directory, X509Certificate2 certificate, string username, string password)
    {
        var holder = new TcpListener(IPAddress.Any, 0);
        holder.Start();
        try
        {
            var port = ((IPEndPoint)holder.LocalEndpoint).Port;
            Check(!LocalNetworkHosting.PortAvailable(port), "The local-network port probe missed a port another program holds.");
            await using var app = BuildCore(directory, port, LocalNetworkCertificate.Sha256(certificate), new FixedSource(certificate));
            await app.StartAsync();
            Check(app.Urls.Count == 1, "Core opened the local-network listener on a port another program holds.");
            using var local = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()) };
            var token = await LoginAsync(local, username, password);
            using var view = await GetAsync(local, "/api/admin/local-network", token);
            using var json = JsonDocument.Parse(await view.Content.ReadAsStringAsync());
            Check(json.RootElement.GetProperty("enabled").GetBoolean() && !json.RootElement.GetProperty("listening").GetBoolean(),
                "Desktop could not see that the local-network port is unavailable.");
            await app.StopAsync();
        }
        finally
        {
            holder.Stop();
        }

        var free = FreePort();
        Check(LocalNetworkHosting.PortAvailable(free) && LocalNetworkHosting.PortAvailable(free),
            "The local-network port probe held or misjudged a free port.");
    }

    private static async Task VerifyLocalOnlyAsync(string directory, string username, string password)
    {
        await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"], builder => builder.Logging.ClearProviders());
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        using var local = new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()) };
        var token = await LoginAsync(local, username, password);
        using var view = await GetAsync(local, "/api/admin/local-network", token);
        using var json = JsonDocument.Parse(await view.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Check(!root.GetProperty("enabled").GetBoolean() && !root.GetProperty("listening").GetBoolean() &&
              root.GetProperty("port").ValueKind == JsonValueKind.Null && root.GetProperty("certificateSha256").ValueKind == JsonValueKind.Null &&
              root.GetProperty("addresses").GetArrayLength() == 0, "A local-only Core reported a local-network listener.");
        await app.StopAsync();
        Reject(() => { using var invalid = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}", "--SentinelAI:LocalNetworkPort=5443"]); },
            "Core started with a local-network port but no certificate pin.");
        Reject(() =>
        {
            using var invalid = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}", "--urls=http://localhost:5000",
                "--SentinelAI:LocalNetworkPort=5443", "--SentinelAI:LocalNetworkCertificateSha256=" + new string('C', 64)]);
        }, "Core accepted an ambiguous loopback origin next to the local-network listener.");
    }

    // Elevated Windows only: the certificate Setup creates in LocalMachine\My, its key ACL, its use by Core and its removal.
    [SupportedOSPlatform("windows")]
    private static async Task VerifyMachineCertificateAsync(string directory, string username, string password)
    {
        var before = DateTimeOffset.UtcNow;
        var pin = LocalNetworkCertificateProvisioning.Create(before);
        string? keyName = null;
        try
        {
            using (var certificate = LocalNetworkCertificate.FindInMachineStore(pin))
            {
                Check(certificate is not null && certificate.FriendlyName == LocalNetworkCertificate.FriendlyName &&
                      certificate.NotAfter.ToUniversalTime() >= before.AddYears(10).AddHours(-2).UtcDateTime &&
                      certificate.NotBefore.ToUniversalTime() <= before.UtcDateTime,
                    "Setup did not add a ten-year Core certificate with its key to LocalMachine\\My.");
                var (hostName, _) = LocalNetworkCertificateProvisioning.ComputerNames();
                Check(certificate!.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames()
                        .First().Equals(hostName, StringComparison.OrdinalIgnoreCase),
                    "Core's certificate does not name this computer.");
                using var key = (ECDsaCng)certificate.GetECDsaPrivateKey()!;
                keyName = key.Key.KeyName;
                Check(key.Key.IsMachineKey && key.Key.ExportPolicy == CngExportPolicies.None && key.KeySize == 256 &&
                      key.Key.Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    "Core's private key is not a non-exportable P-256 machine key.");
                var descriptor = new RawSecurityDescriptor(key.Key.GetProperty("Security Descr", (CngPropertyOptions)4).GetValue()!, 0);
                var entries = descriptor.DiscretionaryAcl!.Cast<GenericAce>().Select(entry => entry is CommonAce common
                    ? (common.AceQualifier == AceQualifier.AccessAllowed, common.SecurityIdentifier.Value, unchecked((uint)common.AccessMask))
                    : (false, "", 0u)).ToArray();
                Check(LocalNetworkCertificateProvisioning.HasExpectedKeyAccess(
                        (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, entries),
                    "Core's private key is usable by identities other than Core's service account, SYSTEM and Administrators: " +
                    descriptor.GetSddlForm(AccessControlSections.Access));
                foreach (var root in new[] { StoreName.Root, StoreName.CertificateAuthority })
                {
                    using var store = new X509Store(root, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadOnly);
                    Check(store.Certificates.All(trusted => { using (trusted) return LocalNetworkCertificate.Sha256(trusted) != pin; }),
                        "Setup added Core's certificate to a trusted certificate authority store.");
                }
            }

            // Core uses the machine certificate exactly as the installed service does.
            var port = FreePort();
            await using (var app = BuildCore(directory, port, pin, new MachineStoreCertificateSource()))
            {
                await app.StartAsync();
                using var network = PinnedClient(new Uri($"https://127.0.0.1:{port}/"), pin);
                using var refused = await network.GetAsync("/api/admin/me");
                Check(refused.StatusCode == HttpStatusCode.NotFound, "Core did not serve its machine certificate on the local-network listener.");
                await app.StopAsync();
            }
        }
        finally
        {
            Check(LocalNetworkCertificateProvisioning.Remove(pin) == 1, "Confirmed data removal did not remove Core's certificate.");
        }

        Check(LocalNetworkCertificate.FindInMachineStore(pin) is null &&
              keyName is not null && !CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey),
            "Removing Core's certificate left its certificate or private key behind.");
        Console.WriteLine("Local-network machine certificate, key ACL, TLS use and removal verified on Windows.");
    }

    private static WebApplication BuildCore(string directory, int port, string pin, ILocalNetworkCertificateSource source) =>
        CoreHost.Build([$"--SentinelAI:DataDirectory={directory}", "--urls=http://127.0.0.1:0",
            $"--SentinelAI:LocalNetworkPort={port}", $"--SentinelAI:LocalNetworkCertificateSha256={pin}"], builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton(source);
        });

    private static async Task<(SslProtocols Protocol, TlsCipherSuite Suite, string Response)> RawRequestAsync(
        int port, string pin, SslProtocols protocols, TlsCipherSuite[]? suites)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using var tls = new SslStream(tcp.GetStream());
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = "synthetic-core",
            EnabledSslProtocols = protocols,
            RemoteCertificateValidationCallback = (_, certificate, _, _) => certificate is not null && LocalNetworkCertificate.Sha256(certificate) == pin
        };
        if (suites is not null && !OperatingSystem.IsWindows()) options.CipherSuitesPolicy = new CipherSuitesPolicy(suites);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await tls.AuthenticateAsClientAsync(options, deadline.Token);
        var protocol = tls.SslProtocol;
        var suite = tls.NegotiatedCipherSuite;
        try
        {
            await tls.WriteAsync(Encoding.ASCII.GetBytes("GET /api/health HTTP/1.1\r\nHost: synthetic-core\r\nConnection: close\r\n\r\n"), deadline.Token);
            var buffer = new byte[256];
            var read = await tls.ReadAsync(buffer, deadline.Token);
            return (protocol, suite, Encoding.ASCII.GetString(buffer, 0, read));
        }
        catch (IOException) when (suites is not null)
        {
            return (protocol, suite, string.Empty);
        }
    }

    private static async Task<bool> HandshakeFailsAsync(int port, string pin, SslProtocols protocols)
    {
        try
        {
            await RawRequestAsync(port, pin, protocols, null);
            return false;
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException or PlatformNotSupportedException or Win32Exception)
        {
            return true;
        }
    }

    private static HttpClient PinnedClient(Uri origin, string pin) =>
        new(new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    certificate is not null && LocalNetworkCertificate.Sha256(certificate) == pin
            }
        }) { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(10) };

    private static X509Certificate2 CreateServerCertificate(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.UtcNow;
        using var ephemeral = LocalNetworkCertificateProvisioning.CreateRequest(key, name, null).CreateSelfSigned(now.AddHours(-1), now.AddDays(1));
        // Windows TLS needs a key in a key store rather than an ephemeral one.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(login.StatusCode == HttpStatusCode.OK, "The local-network test administrator could not log in.");
        using var json = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static async Task<string> PostAsync(HttpClient client, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, "A loopback administrator request failed.");
        return await response.Content.ReadAsStringAsync();
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static IConfiguration Configuration(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(value => new KeyValuePair<string, string?>(value.Key, value.Value))).Build();

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // Like the machine store, every lookup returns a certificate the caller owns.
    private sealed class FixedSource(X509Certificate2? certificate) : ILocalNetworkCertificateSource
    {
        public X509Certificate2? Find(string sha256) => certificate is null ? null : new X509Certificate2(certificate);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        assertions++;
    }

    private static void Reject(Action action, string message)
    {
        try { action(); }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or SocketException or FormatException)
        {
            assertions++;
            return;
        }

        throw new Exception(message);
    }
}
