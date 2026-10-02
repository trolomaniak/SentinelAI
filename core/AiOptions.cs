using System.Globalization;
using System.Net;
using System.Text;

namespace SentinelAI.Core;

/// <summary>Opt-in transport configuration for Core's fixed AI Gateway, never a model provider.</summary>
public sealed class AiOptions
{
    private AiOptions(Uri? gatewayUrl, string? credential, TimeSpan timeout)
    {
        GatewayUrl = gatewayUrl;
        GatewayCredential = credential;
        Timeout = timeout;
    }

    public bool Configured => GatewayUrl is not null;
    public Uri? GatewayUrl { get; }
    public TimeSpan Timeout { get; }
    internal string? GatewayCredential { get; }
    public override string ToString() => nameof(AiOptions);

    public static AiOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:Ai");
        var entries = section.GetChildren().ToArray();
        if (section.Value is not null || entries.Any(entry => entry.GetChildren().Any() ||
                !new[] { "GatewayUrl", "GatewayCredentialPath", "TimeoutSeconds" }
                    .Contains(entry.Key, StringComparer.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Unknown or non-scalar AI setting.");

        var seconds = 15;
        if (section["TimeoutSeconds"] is { } text &&
            (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) ||
             seconds is < 1 or > 60))
            throw new InvalidOperationException("AI TimeoutSeconds must be between 1 and 60.");
        if (entries.Length == 0) return new(null, null, TimeSpan.FromSeconds(seconds));

        if (!Uri.TryCreate(section["GatewayUrl"], UriKind.Absolute, out var url) ||
            (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp) ||
            url.AbsolutePath != "/" || !string.IsNullOrEmpty(url.UserInfo) ||
            !string.IsNullOrEmpty(url.Query) || !string.IsNullOrEmpty(url.Fragment) ||
            (url.Scheme == Uri.UriSchemeHttp && !IsLoopback(url)))
            throw new InvalidOperationException("AI GatewayUrl must be an HTTPS origin, or an HTTP loopback origin for development.");
        var path = section["GatewayCredentialPath"];
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("AI requires an absolute gateway credential file path.");
        return new(url, ReadCredential(path), TimeSpan.FromSeconds(seconds));
    }

    private static bool IsLoopback(Uri url) =>
        string.Equals(url.IdnHost, "localhost", StringComparison.OrdinalIgnoreCase) ||
        (IPAddress.TryParse(url.IdnHost, out var address) && IPAddress.IsLoopback(address));

    private static string ReadCredential(string path)
    {
        const string error = "AI gateway credential must be a protected file containing exactly 43 base64url characters.";
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length != 43 || (!OperatingSystem.IsWindows() &&
                (File.GetUnixFileMode(stream.SafeFileHandle) &
                 (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0))
                throw new InvalidOperationException(error);
            Span<byte> bytes = stackalloc byte[43];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new InvalidOperationException(error);
            foreach (var character in bytes)
                if (!(character is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or
                      >= (byte)'0' and <= (byte)'9' or (byte)'_' or (byte)'-'))
                    throw new InvalidOperationException(error);
            return Encoding.ASCII.GetString(bytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            // File exceptions can contain paths; configuration errors must not disclose credentials.
            throw new InvalidOperationException(error);
        }
    }
}
