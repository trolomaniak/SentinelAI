using System.Text.Json;
using SentinelAI.Localization;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : ILanguageSettingsClient
{
    private sealed record LanguageResponse(UiLanguage Language);

    public async Task<(LanguageRequestOutcome Outcome, UiLanguage? Language)> SetInstallationLanguageAsync(UiLanguage language,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string> { ["language"] = UiLanguages.Code(language) });
        var result = await SendEnrollmentAsync(HttpMethod.Put, "api/admin/settings/language", body, 1024, ParseLanguage, cancellationToken)
            .ConfigureAwait(false);
        return (result.Outcome switch
        {
            ComputerEnrollmentOutcome.Success => LanguageRequestOutcome.Success,
            ComputerEnrollmentOutcome.Unauthenticated => LanguageRequestOutcome.Unauthenticated,
            ComputerEnrollmentOutcome.UntrustedConnection => LanguageRequestOutcome.UntrustedConnection,
            ComputerEnrollmentOutcome.InvalidResponse or ComputerEnrollmentOutcome.TooLarge => LanguageRequestOutcome.InvalidResponse,
            ComputerEnrollmentOutcome.Rejected => LanguageRequestOutcome.Rejected,
            _ => LanguageRequestOutcome.Unavailable
        }, result.Value?.Language);
    }

    private static LanguageResponse ParseLanguage(JsonElement root)
    {
        var fields = ReadProperties(root, ["language"]);
        if (fields.Count != 1 || fields["language"].ValueKind != JsonValueKind.String || !UiLanguages.TryParse(fields["language"].GetString(), out var language))
            throw new InvalidResponseException();
        return new LanguageResponse(language);
    }
}
