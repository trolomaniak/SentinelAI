using System.Globalization;
using Microsoft.Extensions.Configuration;
using SentinelAI.Hosting;

namespace SentinelAI.Agent;

public sealed record AgentOptions(
    Uri CoreUrl,
    string DataDirectory,
    TimeSpan HeartbeatInterval,
    TimeSpan RetryDelay,
    TimeSpan MaxRetryDelay,
    string? EnrollmentToken,
    string? CoreCertificateSha256,
    string? EnrollmentTokenFile = null)
{
    // Posture monitoring: periodic verification when notifications are missed or unavailable,
    // quiet period that coalesces a burst of notifications, and minimum spacing between
    // change-triggered inventory deliveries.
    public TimeSpan PostureCheckInterval { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan PostureSettleDelay { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan PostureDeliveryInterval { get; init; } = TimeSpan.FromSeconds(30);
    // Security event polling; every other event timing derives from it (SecurityEventTimings).
    public TimeSpan EventPollInterval { get; init; } = TimeSpan.FromSeconds(5);
    // MVP-7 automatic updates: the first check after the Agent links to Core, then the regular interval.
    public TimeSpan UpdateCheckDelay { get; init; } = TimeSpan.FromMinutes(1);
    public TimeSpan UpdateCheckInterval { get; init; } = TimeSpan.FromHours(1);

    public bool HasEnrollmentToken => EnrollmentToken is not null || EnrollmentTokenFile is not null;
    public Uri HeartbeatUrl => new(CoreUrl, "/api/agent/heartbeat");
    public Uri EnrollmentUrl => new(CoreUrl, "/api/agent/enroll");
    public Uri InventoryUrl => new(CoreUrl, "/api/agent/inventory");
    public Uri SecurityEventsUrl => new(CoreUrl, "/api/agent/security-events");
    public Uri SecurityTelemetryUrl => new(CoreUrl, "/api/agent/security-telemetry");
    public Uri UpdateManifestUrl => new(CoreUrl, "/api/agent/update/manifest");
    public Uri UpdatePackageUrl => new(CoreUrl, "/api/agent/update/package");
    public override string ToString() => nameof(AgentOptions);

    public static AgentOptions FromConfiguration(IConfiguration configuration)
    {
        var coreUrlText = configuration["Agent:CoreUrl"] ?? "http://127.0.0.1:5000";
        if (!Uri.TryCreate(coreUrlText, UriKind.Absolute, out var coreUrl) ||
            (coreUrl.Scheme != Uri.UriSchemeHttp && coreUrl.Scheme != Uri.UriSchemeHttps) ||
            coreUrl.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(coreUrl.UserInfo) ||
            !string.IsNullOrEmpty(coreUrl.Query) ||
            !string.IsNullOrEmpty(coreUrl.Fragment))
        {
            throw new InvalidOperationException(
                "Agent:CoreUrl must be an HTTP or HTTPS origin without credentials or a path.");
        }

        var certificatePin = configuration["Agent:CoreCertificateSha256"]?.Trim();
        if (certificatePin is { Length: 0 })
        {
            certificatePin = null;
        }

        if (certificatePin is not null)
        {
            if (certificatePin.Length != 64 || !IsHex(certificatePin))
            {
                throw new InvalidOperationException("Agent:CoreCertificateSha256 must be a SHA-256 certificate fingerprint.");
            }

            certificatePin = certificatePin.ToUpperInvariant();
        }

        if (!coreUrl.IsLoopback && (coreUrl.Scheme != Uri.UriSchemeHttps || certificatePin is null))
        {
            throw new InvalidOperationException(
                "A non-loopback Core URL requires HTTPS and Agent:CoreCertificateSha256.");
        }

        if (certificatePin is not null && coreUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("A Core certificate fingerprint requires HTTPS.");
        }

        var dataDirectory = configuration["Agent:DataDirectory"] ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelAI",
            "Agent");
        if (string.IsNullOrWhiteSpace(dataDirectory) || !Path.IsPathFullyQualified(dataDirectory))
        {
            throw new InvalidOperationException("Agent:DataDirectory must be an absolute path.");
        }

        var heartbeatInterval = ReadPositiveInterval(configuration, "Agent:HeartbeatInterval", TimeSpan.FromSeconds(30));
        var retryDelay = ReadPositiveInterval(configuration, "Agent:RetryDelay", TimeSpan.FromSeconds(5));
        var maxRetryDelay = ReadPositiveInterval(configuration, "Agent:MaxRetryDelay", TimeSpan.FromMinutes(1));
        if (retryDelay > maxRetryDelay)
        {
            throw new InvalidOperationException("Agent:RetryDelay must not exceed Agent:MaxRetryDelay.");
        }

        var postureCheckInterval = ReadBoundedInterval(configuration, "Agent:PostureCheckInterval",
            TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(1), TimeSpan.FromHours(6));
        var postureSettleDelay = ReadBoundedInterval(configuration, "Agent:PostureSettleDelay",
            TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(100), TimeSpan.FromMinutes(1));
        var postureDeliveryInterval = ReadBoundedInterval(configuration, "Agent:PostureDeliveryInterval",
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(1), TimeSpan.FromHours(1));
        var eventPollInterval = ReadBoundedInterval(configuration, "Agent:EventPollInterval",
            TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(100), TimeSpan.FromMinutes(5));
        var updateCheckDelay = ReadBoundedInterval(configuration, "Agent:UpdateCheckDelay",
            TimeSpan.FromMinutes(1), TimeSpan.FromMilliseconds(100), TimeSpan.FromHours(1));
        var updateCheckInterval = ReadBoundedInterval(configuration, "Agent:UpdateCheckInterval",
            TimeSpan.FromHours(1), TimeSpan.FromSeconds(1), TimeSpan.FromDays(1));

        var enrollmentToken = string.IsNullOrWhiteSpace(configuration["Agent:EnrollmentToken"])
            ? null : configuration["Agent:EnrollmentToken"]!.Trim();
        var enrollmentTokenFile = configuration["Agent:EnrollmentTokenFile"];
        if (enrollmentTokenFile is not null)
        {
            if (!Path.IsPathFullyQualified(enrollmentTokenFile) ||
                !string.Equals(Path.GetFullPath(enrollmentTokenFile),
                    Path.Combine(Path.GetFullPath(dataDirectory), "pilot-enrollment-token"),
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidOperationException("Agent:EnrollmentTokenFile must be the pilot-enrollment-token file in Agent:DataDirectory.");
            if (enrollmentToken is not null)
                throw new InvalidOperationException("Only one Agent enrollment token source may be configured.");
            PilotHostConfiguration.RejectLinks(enrollmentTokenFile);
            enrollmentTokenFile = Path.GetFullPath(enrollmentTokenFile);
        }

        return new AgentOptions(
            coreUrl,
            Path.GetFullPath(dataDirectory),
            heartbeatInterval,
            retryDelay,
            maxRetryDelay,
            enrollmentToken,
            certificatePin,
            enrollmentTokenFile)
        {
            PostureCheckInterval = postureCheckInterval,
            PostureSettleDelay = postureSettleDelay,
            PostureDeliveryInterval = postureDeliveryInterval,
            EventPollInterval = eventPollInterval,
            UpdateCheckDelay = updateCheckDelay,
            UpdateCheckInterval = updateCheckInterval
        };
    }

    private static TimeSpan ReadPositiveInterval(IConfiguration configuration, string key, TimeSpan fallback)
    {
        var text = configuration[key];
        if (text is null)
        {
            return fallback;
        }

        if (!TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out var interval) || interval <= TimeSpan.Zero)
        {
            throw new InvalidOperationException($"{key} must be a positive TimeSpan.");
        }

        return interval;
    }

    private static TimeSpan ReadBoundedInterval(IConfiguration configuration, string key, TimeSpan fallback,
        TimeSpan minimum, TimeSpan maximum)
    {
        var interval = ReadPositiveInterval(configuration, key, fallback);
        if (interval < minimum || interval > maximum)
        {
            throw new InvalidOperationException(
                $"{key} must be between {minimum.ToString("c", CultureInfo.InvariantCulture)} and " +
                $"{maximum.ToString("c", CultureInfo.InvariantCulture)}.");
        }

        return interval;
    }

    private static bool IsHex(string value)
    {
        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}
