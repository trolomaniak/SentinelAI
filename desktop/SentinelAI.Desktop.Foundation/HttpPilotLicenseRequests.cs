using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IPilotLicenseClient
{
    private const int MaximumPilotBytes = 4 * 1024;
    private const int MaximumPilotKeyCharacters = 1024;
    private const int MaximumPilotContactCharacters = 128;
    private static readonly string[] PilotStates = ["unavailable", "none", "invalid", "scheduled", "active", "ending", "ended"];

    public Task<PilotLicenseResult> GetPilotLicenseAsync(CancellationToken cancellationToken) => SendPilotAsync(null, cancellationToken);

    public Task<PilotLicenseResult> SetPilotLicenseKeyAsync(string key, CancellationToken cancellationToken)
    {
        var text = key?.Trim(' ', '\t', '\r', '\n') ?? string.Empty;
        // A pilot key is three base64url parts; anything else never leaves Desktop.
        if (text.Length is 0 or > MaximumPilotKeyCharacters || text.Count(character => character == '.') != 2 ||
            !text.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.'))
            return Task.FromResult(new PilotLicenseResult(PilotLicenseOutcome.Rejected));
        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteString("key", text);
            writer.WriteEndObject();
        }
        return SendPilotAsync(body.ToArray(), cancellationToken);
    }

    // The same trusted loopback administrator request as computer enrollment: 400, 404 and 409 are Core's answers.
    private async Task<PilotLicenseResult> SendPilotAsync(byte[]? body, CancellationToken cancellationToken)
    {
        var result = await SendEnrollmentAsync(body is null ? HttpMethod.Get : HttpMethod.Post, "api/admin/license/pilot", body,
            MaximumPilotBytes, ParsePilotLicense, cancellationToken).ConfigureAwait(false);
        return new(result.Outcome switch
        {
            ComputerEnrollmentOutcome.Success => PilotLicenseOutcome.Success,
            ComputerEnrollmentOutcome.Unauthenticated => PilotLicenseOutcome.Unauthenticated,
            ComputerEnrollmentOutcome.UntrustedConnection => PilotLicenseOutcome.UntrustedConnection,
            ComputerEnrollmentOutcome.InvalidResponse => PilotLicenseOutcome.InvalidResponse,
            ComputerEnrollmentOutcome.TooLarge => PilotLicenseOutcome.TooLarge,
            ComputerEnrollmentOutcome.NotFound when body is not null => PilotLicenseOutcome.NotConfigured,
            ComputerEnrollmentOutcome.Rejected when body is not null => PilotLicenseOutcome.Rejected,
            ComputerEnrollmentOutcome.Conflict when body is not null => PilotLicenseOutcome.Expired,
            _ => PilotLicenseOutcome.Unavailable
        }, result.Value);
    }

    private static PilotLicenseInfo ParsePilotLicense(JsonElement root)
    {
        var fields = ReadProperties(root, ["state", "customer", "startsUtc", "expiresUtc", "daysLeft", "effectiveUtc", "contact"]);
        if (fields.Count != 7 || fields["state"].ValueKind != JsonValueKind.String || fields["state"].GetString() is not { } state ||
            !PilotStates.Contains(state, StringComparer.Ordinal)) throw new InvalidResponseException();
        string? customer = fields["customer"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String when fields["customer"].GetString() is { Length: > 0 and <= 64 } value && value == value.Trim() && !value.Any(char.IsControl) => value,
            _ => throw new InvalidResponseException()
        };
        var starts = LicenseOptionalDate(fields["startsUtc"]);
        var expires = LicenseOptionalDate(fields["expiresUtc"]);
        int? daysLeft = fields["daysLeft"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.Number when fields["daysLeft"].TryGetInt32(out var value) && value is >= 0 and <= 366 => value,
            _ => throw new InvalidResponseException()
        };
        var effective = LicenseDate(fields["effectiveUtc"]);
        PilotContactDetails? contact = null;
        if (fields["contact"].ValueKind != JsonValueKind.Null)
        {
            var values = ReadProperties(fields["contact"], ["company", "email", "phone", "website"]);
            if (values.Count != 4 || values.Values.Any(value => value.ValueKind != JsonValueKind.String ||
                    value.GetString() is not { Length: <= MaximumPilotContactCharacters } text || text.Any(char.IsControl)) ||
                values["company"].GetString()!.Length == 0) throw new InvalidResponseException();
            contact = new(values["company"].GetString()!, values["email"].GetString()!, values["phone"].GetString()!, values["website"].GetString()!);
        }
        // Core reports details exactly for a trusted key, and days left exactly while it has started.
        var trusted = state is "scheduled" or "active" or "ending" or "ended";
        if ((trusted ? customer is null || starts is null || expires is null || starts >= expires : customer is not null || starts is not null || expires is not null) ||
            (state is "active" or "ending" or "ended") != daysLeft.HasValue ||
            state == "ended" && daysLeft != 0 || state == "active" && daysLeft < 1 || state == "ending" && daysLeft is < 1 or > 7)
            throw new InvalidResponseException();
        return new(state, customer, starts, expires, daysLeft, effective, contact);
    }
}
