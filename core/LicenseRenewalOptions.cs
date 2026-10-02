using System.Globalization;
using System.Net;
using System.Text;

namespace SentinelAI.Core;

/// <summary>A fixed issuer destination and a locally protected activation credential.</summary>
public sealed class LicenseRenewalOptions
{
    private LicenseRenewalOptions(Uri? url, string? credential, TimeSpan interval,
        TimeSpan timeout, bool automatic)
    {
        Url = url;
        ActivationCredential = credential;
        Interval = interval;
        Timeout = timeout;
        Automatic = automatic;
    }

    public bool Configured => Url is not null;
    public Uri? Url { get; }
    public TimeSpan Interval { get; }
    public TimeSpan Timeout { get; }
    public bool Automatic { get; }
    internal string? ActivationCredential { get; }

    public override string ToString() => nameof(LicenseRenewalOptions);

    public static LicenseRenewalOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:Licensing:Renewal");
        var entries = section.GetChildren().ToArray();
        if (section.Value is not null || entries.Any(entry => entry.GetChildren().Any() ||
                !new[] { "Url", "ActivationCredentialPath", "IntervalSeconds", "TimeoutSeconds", "Automatic" }
                    .Contains(entry.Key, StringComparer.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Unknown or non-scalar license renewal setting.");
        }

        var interval = ReadSeconds(section, "IntervalSeconds", 21_600, 60, 86_400);
        var timeout = ReadSeconds(section, "TimeoutSeconds", 10, 1, 60);
        var automatic = true;
        if (section["Automatic"] is { } automaticText && !bool.TryParse(automaticText, out automatic))
        {
            throw new InvalidOperationException("License renewal Automatic must be true or false.");
        }
        if (entries.Length == 0)
        {
            return new LicenseRenewalOptions(null, null, interval, timeout, automatic);
        }

        if (!Uri.TryCreate(section["Url"], UriKind.Absolute, out var url) ||
            (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp) ||
            url.AbsolutePath != "/" || !string.IsNullOrEmpty(url.UserInfo) ||
            !string.IsNullOrEmpty(url.Query) || !string.IsNullOrEmpty(url.Fragment) ||
            (url.Scheme == Uri.UriSchemeHttp && !IsLoopback(url)))
        {
            throw new InvalidOperationException(
                "License renewal Url must be an HTTPS origin, or an HTTP loopback origin for development.");
        }
        var credentialPath = section["ActivationCredentialPath"];
        if (string.IsNullOrWhiteSpace(credentialPath) || !Path.IsPathFullyQualified(credentialPath))
        {
            throw new InvalidOperationException("License renewal requires an absolute activation credential file path.");
        }
        var credential = ReadCredential(credentialPath);
        return new LicenseRenewalOptions(url, credential, interval, timeout, automatic);
    }

    private static TimeSpan ReadSeconds(IConfiguration section, string name, int defaultValue,
        int minimum, int maximum)
    {
        var seconds = defaultValue;
        if (section[name] is { } text &&
            (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out seconds) ||
             seconds < minimum || seconds > maximum))
        {
            throw new InvalidOperationException($"License renewal {name} must be between {minimum} and {maximum}.");
        }
        return TimeSpan.FromSeconds(seconds);
    }

    private static bool IsLoopback(Uri url) =>
        string.Equals(url.IdnHost, "localhost", StringComparison.OrdinalIgnoreCase) ||
        (IPAddress.TryParse(url.IdnHost, out var address) && IPAddress.IsLoopback(address));

    private static string ReadCredential(string path)
    {
        const string error = "License activation credential must be a protected file containing exactly 43 base64url characters.";
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length != 43 || (!OperatingSystem.IsWindows() &&
                    (File.GetUnixFileMode(stream.SafeFileHandle) &
                     (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                      UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0))
            {
                throw new InvalidOperationException(error);
            }
            Span<byte> buffer = stackalloc byte[43];
            stream.ReadExactly(buffer);
            if (stream.ReadByte() != -1)
            {
                throw new InvalidOperationException(error);
            }
            foreach (var character in buffer)
            {
                if (!(character is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or
                      >= (byte)'0' and <= (byte)'9' or (byte)'_' or (byte)'-'))
                {
                    throw new InvalidOperationException(error);
                }
            }
            return Encoding.ASCII.GetString(buffer);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            // File exceptions can contain paths; never expose activation configuration in an error.
            throw new InvalidOperationException(error);
        }
    }
}
