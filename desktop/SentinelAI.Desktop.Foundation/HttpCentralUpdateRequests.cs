using System.Globalization;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : ICentralUpdateClient
{
    private const int MaximumCentralUpdateBytes = 4 * 1024;
    private static readonly string[] CentralUpdateChecks = ["never", "checking", "current", "ready", "failed"];

    public Task<CentralUpdateRequestResult> GetCentralUpdateAsync(CancellationToken cancellationToken) =>
        SendCentralUpdateAsync(HttpMethod.Get, "api/admin/updates", null, cancellationToken);

    public Task<CentralUpdateRequestResult> SetCentralUpdateSettingsAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("checkEnabled", checkEnabled);
            writer.WriteBoolean("autoInstall", autoInstall);
            writer.WriteEndObject();
        }
        return SendCentralUpdateAsync(HttpMethod.Post, "api/admin/updates/settings", body.ToArray(), cancellationToken);
    }

    public Task<CentralUpdateRequestResult> CheckCentralUpdateAsync(CancellationToken cancellationToken) =>
        SendCentralUpdateAsync(HttpMethod.Post, "api/admin/updates/check", null, cancellationToken);

    // The same trusted loopback administrator request as computer enrollment: 404 and 409 are Core's answers.
    private async Task<CentralUpdateRequestResult> SendCentralUpdateAsync(HttpMethod method, string path, byte[]? body, CancellationToken cancellationToken)
    {
        var result = await SendEnrollmentAsync(method, path, body, MaximumCentralUpdateBytes, ParseCentralUpdate, cancellationToken).ConfigureAwait(false);
        return new(result.Outcome switch
        {
            ComputerEnrollmentOutcome.Success => CentralUpdateRequestOutcome.Success,
            ComputerEnrollmentOutcome.Unauthenticated => CentralUpdateRequestOutcome.Unauthenticated,
            ComputerEnrollmentOutcome.UntrustedConnection => CentralUpdateRequestOutcome.UntrustedConnection,
            ComputerEnrollmentOutcome.InvalidResponse => CentralUpdateRequestOutcome.InvalidResponse,
            ComputerEnrollmentOutcome.TooLarge => CentralUpdateRequestOutcome.TooLarge,
            ComputerEnrollmentOutcome.NotFound when method == HttpMethod.Post => CentralUpdateRequestOutcome.NotConfigured,
            ComputerEnrollmentOutcome.Conflict when method == HttpMethod.Post => CentralUpdateRequestOutcome.NotEnabled,
            _ => CentralUpdateRequestOutcome.Unavailable
        }, result.Value);
    }

    private static CentralUpdateInfo ParseCentralUpdate(JsonElement root)
    {
        var fields = ReadProperties(root, ["configured", "server", "checkEnabled", "autoInstall", "installedVersion", "lastCheck", "lastCheckUtc",
            "readyVersion", "installAttempts", "lastAttemptUtc"]);
        if (fields.Count != 10 || fields["configured"].ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            fields["checkEnabled"].ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            fields["autoInstall"].ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            fields["lastCheck"].ValueKind != JsonValueKind.String || !CentralUpdateChecks.Contains(fields["lastCheck"].GetString(), StringComparer.Ordinal) ||
            !fields["installAttempts"].TryGetInt32(out var attempts) || attempts is < 0 or > 1000)
            throw new InvalidResponseException();
        var configured = fields["configured"].GetBoolean();
        var server = fields["server"].ValueKind switch
        {
            JsonValueKind.Null when !configured => null,
            JsonValueKind.String when configured && fields["server"].GetString() is { Length: > 0 and <= 260 } host &&
                                      host.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or ':') => host,
            _ => throw new InvalidResponseException()
        };
        var installed = Version(fields["installedVersion"]) ?? throw new InvalidResponseException();
        var ready = fields["readyVersion"].ValueKind == JsonValueKind.Null ? null : Version(fields["readyVersion"]) ?? throw new InvalidResponseException();
        if (!configured && (fields["checkEnabled"].GetBoolean() || ready is not null)) throw new InvalidResponseException();
        return new(configured, server, fields["checkEnabled"].GetBoolean(), fields["autoInstall"].GetBoolean(), installed,
            fields["lastCheck"].GetString()!, OptionalDate(fields["lastCheckUtc"]), ready, attempts, OptionalDate(fields["lastAttemptUtc"]));
    }

    private static string? Version(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { Length: >= 5 and <= 17 } text) return null;
        var parts = text.Split('.');
        return parts.Length == 3 && parts.All(part => part.Length is >= 1 and <= 5 && (part.Length == 1 || part[0] != '0') &&
                                                       part.All(char.IsAsciiDigit) && int.Parse(part, CultureInfo.InvariantCulture) <= 65535) ? text : null;
    }

    private static DateTimeOffset? OptionalDate(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : LicenseDate(value);
}
