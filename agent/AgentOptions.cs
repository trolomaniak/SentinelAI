using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace SentinelAI.Agent;

public sealed record AgentOptions(
    Uri CoreUrl,
    string DataDirectory,
    TimeSpan HeartbeatInterval,
    TimeSpan RetryDelay,
    TimeSpan MaxRetryDelay)
{
    public Uri HeartbeatUrl => new(CoreUrl, "/api/agent/heartbeat");

    public static AgentOptions FromConfiguration(IConfiguration configuration)
    {
        var coreUrlText = configuration["Agent:CoreUrl"] ?? "http://127.0.0.1:5000";
        if (!Uri.TryCreate(coreUrlText, UriKind.Absolute, out var coreUrl) ||
            (coreUrl.Scheme != Uri.UriSchemeHttp && coreUrl.Scheme != Uri.UriSchemeHttps) ||
            !coreUrl.IsLoopback ||
            coreUrl.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(coreUrl.UserInfo) ||
            !string.IsNullOrEmpty(coreUrl.Query) ||
            !string.IsNullOrEmpty(coreUrl.Fragment))
        {
            throw new InvalidOperationException(
                "Agent:CoreUrl must be a loopback HTTP or HTTPS origin until authenticated enrollment is available.");
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
            maxRetryDelay);
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
}
