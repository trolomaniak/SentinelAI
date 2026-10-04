using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Scoring;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IRiskClient
{
    private const int MaximumRiskPageBytes = 2 * 1024 * 1024;
    private const int MaximumRiskDetailBytes = 1024 * 1024;
    private const int MaximumRiskAlerts = 64;
    private const int MaximumRiskPolicyRules = 1024;
    private const decimal MaximumRiskPoints = 650_000m;

    public Task<RiskReadResult<RiskPage>> GetRiskPageAsync(int offset, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (offset < 0 || limit is < 1 or > 200) return InvalidRiskRequest<RiskPage>();
        return ReadRiskResourceAsync("api/admin/risk?offset=" + offset.ToString(CultureInfo.InvariantCulture) + "&limit=" + limit.ToString(CultureInfo.InvariantCulture),
            MaximumRiskPageBytes, root => ParseRiskPage(root, offset, limit), allowNotFound: false, cancellationToken);
    }

    public Task<RiskReadResult<EndpointRiskDetail>> GetEndpointRiskDetailAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return endpointId == Guid.Empty ? InvalidRiskRequest<EndpointRiskDetail>() : ReadRiskResourceAsync("api/admin/devices/" + endpointId.ToString("D") + "/risk",
            MaximumRiskDetailBytes, root => ParseEndpointRiskDetail(root, endpointId), allowNotFound: true, cancellationToken);
    }

    private Task<RiskReadResult<T>> InvalidRiskRequest<T>()
    {
        lock (_gate)
        {
            if (_disposed || _token is null) return Task.FromResult(new RiskReadResult<T>(RiskReadOutcome.Unauthenticated));
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return Task.FromResult(new RiskReadResult<T>(RiskReadOutcome.Unauthenticated));
            }
            return Task.FromResult(new RiskReadResult<T>(RiskReadOutcome.InvalidResponse));
        }
    }

    private async Task<RiskReadResult<T>> ReadRiskResourceAsync<T>(string path, int maximumBytes, Func<JsonElement, T> parse,
        bool allowNotFound, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(RiskReadOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(RiskReadOutcome.Unauthenticated);
            }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(10));
            RiskReadResult<T> result;
            try { result = await RequestRiskResourceAsync(path, maximumBytes, parse, allowNotFound, token, operation.Token).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(RiskReadOutcome.Unavailable);
            }
            catch (RiskResponseTooLargeException) { result = new(RiskReadOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(RiskReadOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(RiskReadOutcome.Unavailable);
            }
            finally { CryptographicOperations.ZeroMemory(token); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(RiskReadOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(RiskReadOutcome.Unauthenticated);
                }
                if (result.Outcome is RiskReadOutcome.Unauthenticated or RiskReadOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
    }

    private async Task<RiskReadResult<T>> RequestRiskResourceAsync<T>(string path, int maximumBytes, Func<JsonElement, T> parse,
        bool allowNotFound, byte[] token, CancellationToken cancellationToken)
    {
        if (!await _trust.IsTrustedAsync(_origin, cancellationToken).ConfigureAwait(false)) return new(RiskReadOutcome.UntrustedConnection);
        cancellationToken.ThrowIfCancellationRequested();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, path));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (response.StatusCode == HttpStatusCode.Unauthorized) return new(RiskReadOutcome.Unauthenticated);
            if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound) return new(RiskReadOutcome.NotFound);
            if (response.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity) return new(RiskReadOutcome.TooLarge);
            if (response.StatusCode != HttpStatusCode.OK) return new(RiskReadOutcome.Unavailable);
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) throw new InvalidResponseException();
            if (response.Content.Headers.ContentLength > maximumBytes) throw new RiskResponseTooLargeException();
            var buffer = new byte[maximumBytes + 1];
            try
            {
                using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var length = 0;
                while (length < buffer.Length)
                {
                    var count = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
                    if (count == 0) break;
                    length += count;
                }
                cancellationToken.ThrowIfCancellationRequested();
                if (length > maximumBytes) throw new RiskResponseTooLargeException();
                using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 6 });
                var value = parse(json.RootElement);
                cancellationToken.ThrowIfCancellationRequested();
                return new(RiskReadOutcome.Success, value);
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        finally { request.Headers.Authorization = null; }
    }

    private static RiskPage ParseRiskPage(JsonElement root, int offset, int limit)
    {
        var fields = ReadProperties(root, ["organization", "endpoints", "total", "offset", "limit", "policy", "inventoryFreshForHours"]);
        var total = RiskInteger(fields, "total", 0, int.MaxValue);
        if (RiskInteger(fields, "offset", 0, int.MaxValue) != offset || RiskInteger(fields, "limit", 1, 200) != limit) throw new InvalidResponseException();
        var organization = ParseOrganizationRisk(RiskRequired(fields, "organization"));
        var endpoints = RiskArray(RiskRequired(fields, "endpoints"), limit, ParseEndpointRiskSummary);
        if (organization.EndpointCount != total || endpoints.Count > total || endpoints.Count > 0 && (long)offset + endpoints.Count > total) throw new InvalidResponseException();
        var identities = new HashSet<Guid>();
        foreach (var endpoint in endpoints)
        {
            if (!identities.Add(endpoint.EndpointId) || endpoint.Score > organization.Score || endpoint.EvaluatedUtc != organization.EvaluatedUtc) throw new InvalidResponseException();
        }
        return new RiskPage(organization, endpoints, total, offset, limit, ParseRiskPolicy(RiskRequired(fields, "policy")),
            (int)RiskInteger(fields, "inventoryFreshForHours", 1, 8760));
    }

    private static OrganizationRiskView ParseOrganizationRisk(JsonElement root)
    {
        var fields = ReadProperties(root, ["score", "endpointCount", "highestRiskEndpointIds", "highestRiskEndpointCount", "highestRiskEndpointIdsTruncated", "method", "explanation", "evaluatedUtc", "observedEndpointCount", "missingInventoryCount", "unknownSignalCount", "partialSignalCount", "staleInventoryCount", "alertStatusCounts"]);
        var endpointCount = (int)RiskInteger(fields, "endpointCount", 0, int.MaxValue);
        var highestCount = (int)RiskInteger(fields, "highestRiskEndpointCount", 0, endpointCount);
        var ids = RiskArray(RiskRequired(fields, "highestRiskEndpointIds"), 1, RiskIdentity);
        var truncated = RiskBoolean(fields, "highestRiskEndpointIdsTruncated");
        var observed = (int)RiskInteger(fields, "observedEndpointCount", 0, endpointCount);
        var missing = (int)RiskInteger(fields, "missingInventoryCount", 0, endpointCount);
        var unknown = (int)RiskInteger(fields, "unknownSignalCount", 0, endpointCount);
        var partial = (int)RiskInteger(fields, "partialSignalCount", 0, endpointCount);
        var stale = (int)RiskInteger(fields, "staleInventoryCount", 0, observed);
        var score = (int)RiskInteger(fields, "score", 0, 100);
        if ((long)observed + missing != endpointCount || unknown < missing || (long)unknown + partial > endpointCount ||
            ids.Count != (endpointCount == 0 ? 0 : 1) || highestCount < ids.Count || truncated != (highestCount > ids.Count) || endpointCount == 0 && score != 0) throw new InvalidResponseException();
        var method = RiskText(fields, "method", 100);
        if (method != "maximumEndpointScore") throw new InvalidResponseException();
        var counts = ReadProperties(RiskRequired(fields, "alertStatusCounts"), ["open", "investigating", "accepted", "resolved"]);
        var statuses = new RiskAlertStatusCounts((int)RiskInteger(counts, "open", 0, int.MaxValue), (int)RiskInteger(counts, "investigating", 0, int.MaxValue),
            (int)RiskInteger(counts, "accepted", 0, int.MaxValue), (int)RiskInteger(counts, "resolved", 0, int.MaxValue));
        if ((long)statuses.Open + statuses.Investigating + statuses.Accepted + statuses.Resolved > (long)endpointCount * MaximumRiskAlerts) throw new InvalidResponseException();
        return new OrganizationRiskView(score, endpointCount, ids, highestCount, truncated, method, RiskText(fields, "explanation", 4096, allowWhitespace: true),
            RiskDate(RiskRequired(fields, "evaluatedUtc")), observed, missing, unknown, partial, stale, statuses);
    }

    private static EndpointRiskSummary ParseEndpointRiskSummary(JsonElement root)
    {
        var fields = ReadProperties(root, ["endpointId", "endpointName", "inventoryCollectedUtc", "score", "rawScore", "coverage", "unresolvedAlertCount", "highestContributorReason", "evaluatedUtc"]);
        var inventory = RiskOptionalDate(RiskRequired(fields, "inventoryCollectedUtc"));
        var coverage = ParseRiskCoverage(RiskRequired(fields, "coverage"), inventory);
        return new EndpointRiskSummary(RiskIdentity(RiskRequired(fields, "endpointId")), RiskText(fields, "endpointName", 256), inventory,
            (int)RiskInteger(fields, "score", 0, 100), RiskDecimal(fields, "rawScore", 0, MaximumRiskPoints), coverage,
            (int)RiskInteger(fields, "unresolvedAlertCount", 0, MaximumRiskAlerts), RiskText(fields, "highestContributorReason", 4096, allowWhitespace: true),
            RiskDate(RiskRequired(fields, "evaluatedUtc")));
    }

    private static EndpointRiskDetail ParseEndpointRiskDetail(JsonElement root, Guid expectedEndpointId)
    {
        var fields = ReadProperties(root, ["endpointId", "endpointName", "inventoryCollectedUtc", "risk", "coverage", "alerts", "policy", "inventoryFreshForHours"]);
        var endpointId = RiskIdentity(RiskRequired(fields, "endpointId"));
        if (endpointId != expectedEndpointId) throw new InvalidResponseException();
        var inventory = RiskOptionalDate(RiskRequired(fields, "inventoryCollectedUtc"));
        var risk = ParseEndpointRiskScore(RiskRequired(fields, "risk"), endpointId, inventory);
        var alerts = RiskArray(RiskRequired(fields, "alerts"), MaximumRiskAlerts, ParseRiskAlert);
        var identities = new HashSet<Guid>();
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var contributions = risk.Contributions.ToDictionary(contribution => contribution.AlertId);
        if (alerts.Count != contributions.Count) throw new InvalidResponseException();
        foreach (var alert in alerts)
        {
            if (!identities.Add(alert.AlertId) || !rules.Add(alert.RuleId) || !contributions.TryGetValue(alert.AlertId, out var contribution) ||
                alert.RuleId != contribution.RuleId || alert.Status != contribution.Status || alert.Severity != contribution.Severity || alert.LastObservedUtc != contribution.LastObservedUtc) throw new InvalidResponseException();
        }
        return new EndpointRiskDetail(endpointId, RiskText(fields, "endpointName", 256), inventory, risk, ParseRiskCoverage(RiskRequired(fields, "coverage"), inventory),
            alerts, ParseRiskPolicy(RiskRequired(fields, "policy")), (int)RiskInteger(fields, "inventoryFreshForHours", 1, 8760));
    }

    private static EndpointRiskScore ParseEndpointRiskScore(JsonElement root, Guid endpointId, DateTimeOffset? inventory)
    {
        var fields = ReadProperties(root, ["endpointId", "score", "rawScore", "saturated", "calculatedUtc", "context", "assetCriticalityMultiplier", "exposureMultiplier", "contributions", "correlatedGroups", "correlationBaseBonus", "correlationBonus", "explanation"]);
        if (RiskIdentity(RiskRequired(fields, "endpointId")) != endpointId) throw new InvalidResponseException();
        var contextFields = ReadProperties(RiskRequired(fields, "context"), ["assetCriticality", "exposure", "latestInventoryUtc", "assetCriticalitySource", "exposureSource"]);
        var asset = RiskLabel(contextFields, "assetCriticality", ["low", "standard", "high", "critical"]);
        var exposure = RiskLabel(contextFields, "exposure", ["isolated", "internal", "internet", "unknown"]);
        var latest = RiskOptionalDate(RiskRequired(contextFields, "latestInventoryUtc"));
        if (latest != inventory) throw new InvalidResponseException();
        var context = new EndpointScoringContext(asset, exposure, latest, RiskLabel(contextFields, "assetCriticalitySource", ["policyDefault", "userDeclared"]),
            RiskLabel(contextFields, "exposureSource", ["policyDefault", "userDeclared"]));
        var contributions = RiskArray(RiskRequired(fields, "contributions"), MaximumRiskAlerts, ParseRiskContribution);
        if (contributions.Select(value => value.AlertId).Distinct().Count() != contributions.Count || contributions.Select(value => value.RuleId).Distinct(StringComparer.Ordinal).Count() != contributions.Count) throw new InvalidResponseException();
        var groups = RiskArray(RiskRequired(fields, "correlatedGroups"), MaximumRiskAlerts, element => RiskString(element, 100));
        if (groups.Distinct(StringComparer.Ordinal).Count() != groups.Count) throw new InvalidResponseException();
        return new EndpointRiskScore(endpointId, (int)RiskInteger(fields, "score", 0, 100), RiskDecimal(fields, "rawScore", 0, MaximumRiskPoints), RiskBoolean(fields, "saturated"),
            RiskDate(RiskRequired(fields, "calculatedUtc")), context, RiskDecimal(fields, "assetCriticalityMultiplier", 0, 10, exclusiveMinimum: true),
            RiskDecimal(fields, "exposureMultiplier", 0, 10, exclusiveMinimum: true), contributions, groups, RiskDecimal(fields, "correlationBaseBonus", 0, 100),
            RiskDecimal(fields, "correlationBonus", 0, 10_000), RiskText(fields, "explanation", 4096, allowWhitespace: true));
    }

    private static AlertRiskContribution ParseRiskContribution(JsonElement root)
    {
        var fields = ReadProperties(root, ["alertId", "ruleId", "severity", "status", "lastObservedUtc", "ageDays", "ageBand", "futureTimestampClamped", "severityPoints", "detectionConfidence", "confidenceSource", "assetCriticalityMultiplier", "exposureMultiplier", "ageMultiplier", "remainingRiskMultiplier", "pointsBeforeMitigation", "mitigationReduction", "contribution", "correlationGroup", "latestSnapshotConfirmed", "correlationEligible"]);
        var groupElement = RiskRequired(fields, "correlationGroup");
        var group = groupElement.ValueKind == JsonValueKind.Null ? null : RiskString(groupElement, 100);
        return new AlertRiskContribution(RiskIdentity(RiskRequired(fields, "alertId")), RiskText(fields, "ruleId", 128),
            RiskLabel(fields, "severity", ["info", "low", "medium", "high", "critical"]), RiskLabel(fields, "status", ["open", "investigating", "accepted", "resolved"]),
            RiskDate(RiskRequired(fields, "lastObservedUtc")), RiskDecimal(fields, "ageDays", 0, 3_652_059), RiskLabel(fields, "ageBand", ["fresh", "aging", "old"]),
            RiskBoolean(fields, "futureTimestampClamped"), RiskDecimal(fields, "severityPoints", 0, 100, exclusiveMinimum: true), RiskDecimal(fields, "detectionConfidence", 0, 1),
            RiskLabel(fields, "confidenceSource", ["policyDefault", "rulePolicyOverride"]), RiskDecimal(fields, "assetCriticalityMultiplier", 0, 10, exclusiveMinimum: true),
            RiskDecimal(fields, "exposureMultiplier", 0, 10, exclusiveMinimum: true), RiskDecimal(fields, "ageMultiplier", 0, 1, exclusiveMinimum: true),
            RiskDecimal(fields, "remainingRiskMultiplier", 0, 1), RiskDecimal(fields, "pointsBeforeMitigation", 0, 10_000), RiskDecimal(fields, "mitigationReduction", 0, 10_000),
            RiskDecimal(fields, "contribution", 0, 10_000), group, RiskBoolean(fields, "latestSnapshotConfirmed"), RiskBoolean(fields, "correlationEligible"));
    }

    private static RiskAlertView ParseRiskAlert(JsonElement root)
    {
        var fields = ReadProperties(root, ["alertId", "ruleId", "title", "severity", "status", "lastObservedUtc", "reason"]);
        return new RiskAlertView(RiskIdentity(RiskRequired(fields, "alertId")), RiskText(fields, "ruleId", 128), RiskText(fields, "title", 512),
            RiskLabel(fields, "severity", ["info", "low", "medium", "high", "critical"]), RiskLabel(fields, "status", ["open", "investigating", "accepted", "resolved"]),
            RiskDate(RiskRequired(fields, "lastObservedUtc")), RiskText(fields, "reason", 4096, allowWhitespace: true));
    }

    private static RiskCoverage ParseRiskCoverage(JsonElement root, DateTimeOffset? inventory)
    {
        var fields = ReadProperties(root, ["inventoryState", "signalCoverage", "knownRuleSignals", "totalRuleSignals", "caution"]);
        var state = RiskLabel(fields, "inventoryState", ["missing", "current", "stale", "future"]);
        var signal = RiskLabel(fields, "signalCoverage", ["unknown", "partial", "complete"]);
        var known = (int)RiskInteger(fields, "knownRuleSignals", 0, 13);
        if (RiskInteger(fields, "totalRuleSignals", 13, 13) != 13 || (state == "missing") != (inventory is null) ||
            signal != (known == 0 ? "unknown" : known == 13 ? "complete" : "partial") || state == "missing" && known != 0) throw new InvalidResponseException();
        return new RiskCoverage(state, signal, known, 13, RiskText(fields, "caution", 4096, allowWhitespace: true));
    }

    private static ScoringPolicySnapshot ParseRiskPolicy(JsonElement root)
    {
        var fields = ReadProperties(root, ["version", "severityPoints", "defaultConfidence", "confidenceByRule", "assetMultipliers", "exposureMultipliers", "remainingRiskByStatus", "freshForDays", "agingForDays", "agingMultiplier", "oldMultiplier", "correlationPointsPerExtraGroup", "maximumCorrelationBaseBonus", "correlationGroupsByRule", "maximumScore"]);
        var severity = RiskDecimalMap(RiskRequired(fields, "severityPoints"), ["info", "low", "medium", "high", "critical"], 0, 100, exclusiveMinimum: true);
        var assets = RiskDecimalMap(RiskRequired(fields, "assetMultipliers"), ["low", "standard", "high", "critical"], 0, 10, exclusiveMinimum: true);
        var exposure = RiskDecimalMap(RiskRequired(fields, "exposureMultipliers"), ["isolated", "internal", "internet", "unknown"], 0, 10, exclusiveMinimum: true);
        var statuses = RiskDecimalMap(RiskRequired(fields, "remainingRiskByStatus"), ["open", "investigating", "accepted", "resolved"], 0, 1);
        var fresh = (int)RiskInteger(fields, "freshForDays", 1, 3650);
        var aging = (int)RiskInteger(fields, "agingForDays", 1, 3650);
        var agingMultiplier = RiskDecimal(fields, "agingMultiplier", 0, 1, exclusiveMinimum: true);
        var oldMultiplier = RiskDecimal(fields, "oldMultiplier", 0, agingMultiplier, exclusiveMinimum: true);
        if (fresh >= aging || RiskInteger(fields, "maximumScore", 100, 100) != 100 || statuses["open"] != 1 || statuses["investigating"] != 1 ||
            statuses["accepted"] != 1 || statuses["resolved"] != 0 || severity["info"] > severity["low"] || severity["low"] > severity["medium"] ||
            severity["medium"] > severity["high"] || severity["high"] > severity["critical"] || assets["low"] > assets["standard"] ||
            assets["standard"] > assets["high"] || assets["high"] > assets["critical"] || exposure["isolated"] > exposure["internal"] || exposure["internal"] > exposure["internet"]) throw new InvalidResponseException();
        return new ScoringPolicySnapshot(RiskText(fields, "version", 100), severity, RiskDecimal(fields, "defaultConfidence", 0, 1, exclusiveMinimum: true),
            RiskDecimalMap(RiskRequired(fields, "confidenceByRule"), null, 0, 1), assets, exposure, statuses, fresh, aging, agingMultiplier, oldMultiplier,
            RiskDecimal(fields, "correlationPointsPerExtraGroup", 0, 100), RiskDecimal(fields, "maximumCorrelationBaseBonus", 0, 100),
            RiskStringMap(RiskRequired(fields, "correlationGroupsByRule")), 100);
    }

    private static IReadOnlyDictionary<string, decimal> RiskDecimalMap(JsonElement root, string[]? requiredKeys, decimal minimum, decimal maximum, bool exclusiveMinimum = false)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidResponseException();
        var values = new Dictionary<string, decimal>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (values.Count >= MaximumRiskPolicyRules) throw new RiskResponseTooLargeException();
            RiskValidateString(property.Name, 100);
            if (requiredKeys is not null && !requiredKeys.Contains(property.Name, StringComparer.Ordinal) ||
                !values.TryAdd(property.Name, RiskDecimalValue(property.Value, minimum, maximum, exclusiveMinimum))) throw new InvalidResponseException();
        }
        if (requiredKeys is not null && values.Count != requiredKeys.Length) throw new InvalidResponseException();
        return new ReadOnlyDictionary<string, decimal>(values);
    }

    private static IReadOnlyDictionary<string, string> RiskStringMap(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidResponseException();
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (values.Count >= MaximumRiskPolicyRules) throw new RiskResponseTooLargeException();
            RiskValidateString(property.Name, 100);
            if (!values.TryAdd(property.Name, RiskString(property.Value, 100))) throw new InvalidResponseException();
        }
        return new ReadOnlyDictionary<string, string>(values);
    }

    private static IReadOnlyList<T> RiskArray<T>(JsonElement root, int maximum, Func<JsonElement, T> parse)
    {
        if (root.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (root.GetArrayLength() > maximum) throw new RiskResponseTooLargeException();
        return Array.AsReadOnly(root.EnumerateArray().Select(parse).ToArray());
    }

    private static JsonElement RiskRequired(Dictionary<string, JsonElement> fields, string name) => fields.TryGetValue(name, out var element) ? element : throw new InvalidResponseException();
    private static string RiskText(Dictionary<string, JsonElement> fields, string name, int maximum, bool allowWhitespace = false) => RiskString(RiskRequired(fields, name), maximum, allowWhitespace);
    private static string RiskString(JsonElement element, int maximum, bool allowWhitespace = false)
    {
        if (element.ValueKind != JsonValueKind.String) throw new InvalidResponseException();
        var value = element.GetString()!; RiskValidateString(value, maximum, allowWhitespace); return value;
    }
    private static void RiskValidateString(string value, int maximum, bool allowWhitespace = false)
    {
        if (value.Length > maximum) throw new RiskResponseTooLargeException();
        if (string.IsNullOrWhiteSpace(value) || value.Any(character => char.IsControl(character) && !(allowWhitespace && character is '\r' or '\n' or '\t'))) throw new InvalidResponseException();
    }
    private static string RiskLabel(Dictionary<string, JsonElement> fields, string name, string[] allowed)
    {
        var value = RiskText(fields, name, 100);
        return allowed.Contains(value, StringComparer.Ordinal) ? value : throw new InvalidResponseException();
    }
    private static long RiskInteger(Dictionary<string, JsonElement> fields, string name, long minimum, long maximum)
    {
        var element = RiskRequired(fields, name);
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value) || value < minimum || value > maximum) throw new InvalidResponseException();
        return value;
    }
    private static decimal RiskDecimal(Dictionary<string, JsonElement> fields, string name, decimal minimum, decimal maximum, bool exclusiveMinimum = false) =>
        RiskDecimalValue(RiskRequired(fields, name), minimum, maximum, exclusiveMinimum);
    private static decimal RiskDecimalValue(JsonElement element, decimal minimum, decimal maximum, bool exclusiveMinimum = false)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetDecimal(out var value) || value < minimum || value > maximum || exclusiveMinimum && value == minimum) throw new InvalidResponseException();
        return value;
    }
    private static bool RiskBoolean(Dictionary<string, JsonElement> fields, string name)
    {
        var element = RiskRequired(fields, name);
        return element.ValueKind is JsonValueKind.True or JsonValueKind.False ? element.GetBoolean() : throw new InvalidResponseException();
    }
    private static Guid RiskIdentity(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String || !Guid.TryParseExact(element.GetString(), "D", out var identity) || identity == Guid.Empty) throw new InvalidResponseException();
        return identity;
    }
    private static DateTimeOffset? RiskOptionalDate(JsonElement element) => element.ValueKind == JsonValueKind.Null ? null : RiskDate(element);
    private static DateTimeOffset RiskDate(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String || !(element.GetString()!.EndsWith('Z') || element.GetString()!.EndsWith("+00:00", StringComparison.Ordinal)) ||
            !element.TryGetDateTimeOffset(out var value) || value.Offset != TimeSpan.Zero) throw new InvalidResponseException();
        return value;
    }
    private sealed class RiskResponseTooLargeException : Exception;
}
