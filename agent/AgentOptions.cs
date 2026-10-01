using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace SentinelAI.Agent;

public sealed record AgentOptions(
    Uri CoreUrl,
    string DataDirectory,
    TimeSpan HeartbeatInterval,
    TimeSpan RetryDelay,
    TimeSpan MaxRetryDelay,
    string? EnrollmentToken,
    string? CoreCertificateSha256)
{
    public Uri HeartbeatUrl => new(CoreUrl, "/api/agent/heartbeat");
    public Uri EnrollmentUrl => new(CoreUrl, "/api/agent/enroll");
    public Uri InventoryUrl => new(CoreUrl, "/api/agent/inventory");
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

        return new AgentOptions(
            coreUrl,
            Path.GetFullPath(dataDirectory),
            heartbeatInterval,
            retryDelay,
            maxRetryDelay,
            string.IsNullOrWhiteSpace(configuration["Agent:EnrollmentToken"])
                ? null : configuration["Agent:EnrollmentToken"]!.Trim(),
            certificatePin);
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
