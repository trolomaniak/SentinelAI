using System.Globalization;
using System.Text.Json;
using SentinelAI.Contracts.RiskHistory;

namespace SentinelAI.Desktop.Foundation;

public interface IRiskHistoryClient
{
    Task<RiskReadResult<RiskHistoryView>> GetRiskHistoryAsync(Guid? endpointId, int periodHours, CancellationToken cancellationToken);
}

public sealed partial class HttpAuthenticationClient : IRiskHistoryClient
{
    public Task<RiskReadResult<RiskHistoryView>> GetRiskHistoryAsync(Guid? endpointId, int periodHours, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (endpointId == Guid.Empty || !RiskHistoryContract.PeriodHours.Contains(periodHours)) return InvalidRiskRequest<RiskHistoryView>();
        var scope = endpointId is { } id ? "/" + id.ToString("D") : string.Empty;
        return ReadRiskResourceAsync("api/admin/risk-history" + scope + "?hours=" + periodHours.ToString(CultureInfo.InvariantCulture),
            RiskHistoryContract.MaximumResponseBytes, root => ParseRiskHistory(root, endpointId, periodHours), allowNotFound: false, cancellationToken);
    }

    private static RiskHistoryView ParseRiskHistory(JsonElement root, Guid? endpointId, int periodHours)
    {
        var fields = ReadProperties(root, ["endpointId", "periodHours", "generatedUtc", "startUtc", "points"]);
        var generated = RiskDate(RiskRequired(fields, "generatedUtc"));
        var start = RiskDate(RiskRequired(fields, "startUtc"));
        if (RiskHistoryIdentity(RiskRequired(fields, "endpointId")) != endpointId ||
            RiskInteger(fields, "periodHours", periodHours, periodHours) != periodHours ||
            start.UtcTicks != Math.Max(0, generated.UtcTicks - periodHours * TimeSpan.TicksPerHour))
            throw new InvalidResponseException();

        var maximumPoints = Math.Min(RiskHistoryContract.MaximumPoints, periodHours / RiskHistoryContract.CaptureIntervalHours + 1);
        var points = RiskArray(RiskRequired(fields, "points"), maximumPoints, element => ParseRiskHistoryPoint(element, endpointId is null));
        DateTimeOffset? previous = null;
        foreach (var point in points)
        {
            if (point.CapturedUtc < start || point.CapturedUtc > generated ||
                point.ComparedWithUtc is { } compared && HistoryBucket(compared) >= HistoryBucket(point.CapturedUtc) ||
                previous is { } prior && (HistoryBucket(prior) >= HistoryBucket(point.CapturedUtc) || point.ComparedWithUtc != prior))
                throw new InvalidResponseException();
            previous = point.CapturedUtc;
        }
        return new RiskHistoryView(endpointId, periodHours, generated, start, points);
    }

    private static RiskHistoryPoint ParseRiskHistoryPoint(JsonElement element, bool organization)
    {
        var fields = ReadProperties(element, ["capturedUtc", "score", "rawScore", "policyVersion", "policyFingerprint", "comparedWithUtc",
            "causes", "principalRuleIds", "endpointCount", "governingEndpointId"]);
        var captured = RiskDate(RiskRequired(fields, "capturedUtc"));
        var score = (int)RiskInteger(fields, "score", 0, 100);
        var rawScore = RiskDecimal(fields, "rawScore", 0, decimal.MaxValue);
        var policyVersion = RiskText(fields, "policyVersion", RiskHistoryContract.MaximumPolicyVersionLength);
        var fingerprint = RiskText(fields, "policyFingerprint", 64);
        if (fingerprint.Length != 64 || fingerprint.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            score != decimal.Round(Math.Min(rawScore, 100m), 0, MidpointRounding.AwayFromZero))
            throw new InvalidResponseException();

        var compared = RiskOptionalDate(RiskRequired(fields, "comparedWithUtc"));
        var causes = RiskArray(RiskRequired(fields, "causes"), RiskHistoryContract.CauseCodes.Count, value => RiskString(value, 32));
        var rules = RiskArray(RiskRequired(fields, "principalRuleIds"), RiskHistoryContract.MaximumRuleIds,
            value => RiskString(value, RiskHistoryContract.MaximumRuleIdLength));
        if (causes.Any(cause => !RiskHistoryContract.CauseCodes.Contains(cause, StringComparer.Ordinal)) ||
            causes.Distinct(StringComparer.Ordinal).Count() != causes.Count ||
            (compared is null ? causes.Count != 1 || causes[0] != "firstCapture" : causes.Contains("firstCapture", StringComparer.Ordinal)) ||
            !organization && causes.Any(cause => cause is "fleetChanged" or "governingEndpointChanged") ||
            rules.Any(rule => rule.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-'))) ||
            rules.Distinct(StringComparer.Ordinal).Count() != rules.Count)
            throw new InvalidResponseException();

        int? count = RiskRequired(fields, "endpointCount").ValueKind == JsonValueKind.Null ? null :
            (int)RiskInteger(fields, "endpointCount", 0, RiskHistoryContract.MaximumEndpointPoints);
        var governingEndpoint = RiskHistoryIdentity(RiskRequired(fields, "governingEndpointId"));
        if (organization != count.HasValue || (count > 0) != governingEndpoint.HasValue || count == 0 && (score != 0 || rawScore != 0 || rules.Count != 0))
            throw new InvalidResponseException();
        return new RiskHistoryPoint(captured, score, rawScore, policyVersion, fingerprint, compared, causes, rules, count, governingEndpoint);
    }

    private static long HistoryBucket(DateTimeOffset capture) => capture.UtcTicks / TimeSpan.FromHours(RiskHistoryContract.CaptureIntervalHours).Ticks;
    private static Guid? RiskHistoryIdentity(JsonElement element) => element.ValueKind == JsonValueKind.Null ? null : RiskIdentity(element);
}
