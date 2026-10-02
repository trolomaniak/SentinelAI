using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace SentinelAI.AiGateway;

public sealed class AiGatewayOptions
{
    public byte[] ClientCredentialDigest { get; }
    public string? Model { get; }
    public TimeSpan Timeout { get; }

    private AiGatewayOptions(byte[] clientCredentialDigest, string? model, TimeSpan timeout)
    {
        ClientCredentialDigest = clientCredentialDigest;
        Model = model;
        Timeout = timeout;
    }

    public static AiGatewayOptions Load(IConfiguration configuration, bool providerKeyPresent)
    {
        var section = configuration.GetSection("SentinelAI:AiGateway");
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ClientCredentialSha256", "Model", "TimeoutSeconds"
        };
        if (section.GetChildren().Any(item => !allowed.Contains(item.Key) || item.GetChildren().Any()))
        {
            throw new InvalidOperationException("AI Gateway settings contain an unsupported setting.");
        }
        var digest = section["ClientCredentialSha256"];
        if (digest is null || digest.Length != 64 || !digest.All(char.IsAsciiHexDigit))
        {
            throw new InvalidOperationException("AI Gateway requires the SHA-256 digest of its client credential.");
        }
        var model = section["Model"];
        if (model is not null && (model.Length is < 1 or > 128
            || !model.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':')))
        {
            throw new InvalidOperationException("AI Gateway model is invalid.");
        }
        if (providerKeyPresent && model is null)
        {
            throw new InvalidOperationException("AI Gateway requires a configured model when the provider is enabled.");
        }
        var timeoutSeconds = 20;
        var configuredTimeout = section["TimeoutSeconds"];
        if (configuredTimeout is not null && (!int.TryParse(configuredTimeout, NumberStyles.None,
            CultureInfo.InvariantCulture, out timeoutSeconds) || timeoutSeconds is < 1 or > 60))
        {
            throw new InvalidOperationException("AI Gateway timeout must be between 1 and 60 seconds.");
        }
        return new AiGatewayOptions(Convert.FromHexString(digest), model, TimeSpan.FromSeconds(timeoutSeconds));
    }
}
