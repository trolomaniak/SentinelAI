using System.Text.Json;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IMonitoringCoverageClient
{
    private const string MonitoringPath = "api/admin/monitoring-coverage";

    public Task<DeviceReadResult<MonitoringEndpointPage>> GetMonitoringEndpointsAsync(int offset, int limit, bool issuesOnly,
        CancellationToken cancellationToken) => ReadDeviceResourceAsync(
        MonitoringPath + CoveragePageQuery(offset, limit) + (issuesOnly ? "&issuesOnly=true" : "&issuesOnly=false"),
        MonitoringCoverageContract.MaximumResponseBytes, root => ParseMonitoringEndpoints(root, offset, limit, issuesOnly),
        allowNotFound: false, cancellationToken);

    public Task<DeviceReadResult<MonitoringEndpointDetail>> GetMonitoringEndpointAsync(Guid endpointId, CancellationToken cancellationToken) =>
        ReadDeviceResourceAsync(CoverageEndpointPath(endpointId), MonitoringCoverageContract.MaximumResponseBytes,
            root => ParseMonitoringEndpoint(root, endpointId), allowNotFound: true, cancellationToken);

    public Task<DeviceReadResult<MonitoringGapPage>> GetMonitoringGapsAsync(Guid endpointId, int offset, int limit,
        CancellationToken cancellationToken) => ReadDeviceResourceAsync(
        CoverageEndpointPath(endpointId) + "/gaps" + CoveragePageQuery(offset, limit), MonitoringCoverageContract.MaximumResponseBytes,
        root => ParseMonitoringGaps(root, endpointId, offset, limit), allowNotFound: true, cancellationToken);

    private static string CoverageEndpointPath(Guid endpointId) => endpointId != Guid.Empty
        ? $"{MonitoringPath}/{endpointId:D}" : throw new ArgumentException("An enrolled endpoint is required.", nameof(endpointId));

    private static string CoveragePageQuery(int offset, int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, MonitoringCoverageContract.MaximumOffset);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, MonitoringCoverageContract.MaximumPageSize);
        return FormattableString.Invariant($"?offset={offset}&limit={limit}");
    }

    private static MonitoringEndpointPage ParseMonitoringEndpoints(JsonElement root, int offset, int limit, bool issuesOnly)
    {
        var fields = CoverageFields(root, "generatedUtc", "total", "matching", "offset", "limit", "inventoryFreshHours", "items");
        var total = CoverageNumber(fields, "total", 0, int.MaxValue);
        var matching = CoverageNumber(fields, "matching", 0, total);
        if (!issuesOnly && matching != total) throw new InvalidResponseException();
        var items = CoveragePageItems(fields, matching, offset, limit).Select(ParseMonitoringSummary).ToArray();
        if (items.Select(item => item.EndpointId).Distinct().Count() != items.Length || issuesOnly && items.Any(item => !item.HasIssue))
            throw new InvalidResponseException();
        return new(CoverageDate(fields, "generatedUtc"), total, matching, offset, limit,
            CoverageNumber(fields, "inventoryFreshHours", 1, 8760), items);
    }

    private static MonitoringEndpointSummary ParseMonitoringSummary(JsonElement root)
    {
        var fields = CoverageFields(root, "endpointId", "name", "heartbeatState", "lastHeartbeatUtc", "inventoryFreshness",
            "inventoryCollectedUtc", "telemetryFreshness", "telemetryCollectedUtc", "telemetryReceivedUtc", "currentTelemetrySources",
            "currentEventChannels", "hasRetainedGaps", "hasIssue");
        var name = OptionalDeviceText(fields, "name", 128);
        if (!SecurityEventContract.IsBoundedText(name, 128)) throw new InvalidResponseException();
        return new(CoverageId(fields), name!,
            CoverageChoice(fields, "heartbeatState", "healthy", "warning", "offline", "unknown", "future"),
            OptionalDeviceDate(fields, "lastHeartbeatUtc"), CoverageFreshness(fields, "inventoryFreshness"),
            OptionalDeviceDate(fields, "inventoryCollectedUtc"), CoverageFreshness(fields, "telemetryFreshness"),
            OptionalDeviceDate(fields, "telemetryCollectedUtc"), OptionalDeviceDate(fields, "telemetryReceivedUtc"),
            CoverageNumber(fields, "currentTelemetrySources", 0, MonitoringCoverageContract.TelemetrySourceIds.Count),
            CoverageNumber(fields, "currentEventChannels", 0, SecurityEventChannels.All.Count),
            CoverageBoolean(fields, "hasRetainedGaps"), CoverageBoolean(fields, "hasIssue"));
    }

    private static MonitoringEndpointDetail ParseMonitoringEndpoint(JsonElement root, Guid endpointId)
    {
        var fields = CoverageFields(root, "generatedUtc", "endpoint", "inventoryFreshHours", "gapRetentionDays", "telemetry", "eventChannels");
        var endpoint = ParseMonitoringSummary(fields["endpoint"]);
        if (endpoint.EndpointId != endpointId) throw new InvalidResponseException();
        var telemetry = CoverageArray(fields["telemetry"], MonitoringCoverageContract.TelemetrySourceIds.Count).Select(ParseCoverageTelemetry).ToArray();
        var channels = CoverageArray(fields["eventChannels"], SecurityEventChannels.All.Count).Select(ParseCoverageChannel).ToArray();
        if (telemetry.Select(item => item.SourceId).Distinct().Count() != telemetry.Length ||
            channels.Select(item => item.Channel).Distinct().Count() != channels.Length) throw new InvalidResponseException();
        return new(CoverageDate(fields, "generatedUtc"), endpoint, CoverageNumber(fields, "inventoryFreshHours", 1, 8760),
            CoverageNumber(fields, "gapRetentionDays", 1, int.MaxValue), telemetry, channels);
    }

    private static MonitoringTelemetrySource ParseCoverageTelemetry(JsonElement root)
    {
        var fields = CoverageFields(root, "sourceId", "state", "freshness");
        return new(CoverageChoice(fields, "sourceId", [.. MonitoringCoverageContract.TelemetrySourceIds]),
            CoverageChoice(fields, "state", [.. TelemetryAvailability.All, "unknown"]), CoverageFreshness(fields, "freshness"));
    }

    private static MonitoringEventChannel ParseCoverageChannel(JsonElement root)
    {
        var fields = CoverageFields(root, "channel", "state", "freshness", "reportedUtc", "lastReadUtc", "firstCheckpointUtc",
            "checkpointRecordId", "countersSinceUtc", "reportedGaps", "skippedRecords", "droppedUnparsed", "droppedOversize");
        return new(CoverageChoice(fields, "channel", [.. SecurityEventChannels.All]),
            CoverageChoice(fields, "state", [.. SecurityEventSourceStates.All, "unknown"]), CoverageFreshness(fields, "freshness"),
            OptionalDeviceDate(fields, "reportedUtc"), OptionalDeviceDate(fields, "lastReadUtc"), OptionalDeviceDate(fields, "firstCheckpointUtc"),
            CoverageCounter(fields, "checkpointRecordId"), OptionalDeviceDate(fields, "countersSinceUtc"), CoverageCounter(fields, "reportedGaps"),
            CoverageCounter(fields, "skippedRecords"), CoverageCounter(fields, "droppedUnparsed"), CoverageCounter(fields, "droppedOversize"));
    }

    private static MonitoringGapPage ParseMonitoringGaps(JsonElement root, Guid endpointId, int offset, int limit)
    {
        var fields = CoverageFields(root, "generatedUtc", "endpointId", "total", "offset", "limit", "retentionDays", "items");
        if (CoverageId(fields) != endpointId) throw new InvalidResponseException();
        var total = CoverageNumber(fields, "total", 0, int.MaxValue);
        var items = CoveragePageItems(fields, total, offset, limit).Select(ParseCoverageGap).ToArray();
        return new(CoverageDate(fields, "generatedUtc"), endpointId, total, offset, limit,
            CoverageNumber(fields, "retentionDays", 1, int.MaxValue), items);
    }

    private static MonitoringCoverageGap ParseCoverageGap(JsonElement root)
    {
        var fields = CoverageFields(root, "channel", "reason", "cause", "firstRecordId", "lastRecordId", "detectedUtc", "receivedUtc", "coverageRestart");
        var firstRecordId = OptionalDeviceInteger(fields, "firstRecordId", 1, long.MaxValue) ?? throw new InvalidResponseException();
        var reason = CoverageChoice(fields, "reason", [.. SecurityEventGapReasons.AgentReasons, SecurityEventGapReasons.Rejected]);
        var cause = fields["cause"].ValueKind == JsonValueKind.Null ? null :
            CoverageChoice(fields, "cause", [.. SecurityEventCoverageCauses.All]);
        var restart = CoverageBoolean(fields, "coverageRestart");
        if (reason != SecurityEventGapReasons.CoverageStarted && (cause is not null || restart)) throw new InvalidResponseException();
        return new(CoverageChoice(fields, "channel", [.. SecurityEventChannels.All]), reason, cause, firstRecordId,
            OptionalDeviceInteger(fields, "lastRecordId", firstRecordId, long.MaxValue), CoverageDate(fields, "detectedUtc"),
            CoverageDate(fields, "receivedUtc"), restart);
    }

    private static Dictionary<string, JsonElement> CoverageFields(JsonElement root, params string[] names)
    {
        var fields = ReadProperties(root, names);
        if (fields.Count != names.Length) throw new InvalidResponseException();
        return fields;
    }

    private static JsonElement.ArrayEnumerator CoveragePageItems(Dictionary<string, JsonElement> fields, int total, int offset, int limit)
    {
        if (CoverageNumber(fields, "offset", 0, MonitoringCoverageContract.MaximumOffset) != offset ||
            CoverageNumber(fields, "limit", 1, MonitoringCoverageContract.MaximumPageSize) != limit) throw new InvalidResponseException();
        return CoverageArray(fields["items"], Math.Min(limit, Math.Max(0, total - offset)));
    }

    private static JsonElement.ArrayEnumerator CoverageArray(JsonElement element, int count) =>
        element.ValueKind == JsonValueKind.Array && element.GetArrayLength() == count ? element.EnumerateArray() : throw new InvalidResponseException();

    private static string CoverageFreshness(Dictionary<string, JsonElement> fields, string name) =>
        CoverageChoice(fields, name, "current", "stale", "future", "missing");

    private static string CoverageChoice(Dictionary<string, JsonElement> fields, string name, params string[] choices) =>
        fields[name].ValueKind == JsonValueKind.String && fields[name].GetString() is { } value && choices.Contains(value, StringComparer.Ordinal)
            ? value : throw new InvalidResponseException();

    private static Guid CoverageId(Dictionary<string, JsonElement> fields) => fields["endpointId"].ValueKind == JsonValueKind.String &&
        fields["endpointId"].TryGetGuid(out var id) && id != Guid.Empty ? id : throw new InvalidResponseException();

    private static DateTimeOffset CoverageDate(Dictionary<string, JsonElement> fields, string name) =>
        OptionalDeviceDate(fields, name) ?? throw new InvalidResponseException();

    private static int CoverageNumber(Dictionary<string, JsonElement> fields, string name, int minimum, int maximum) =>
        (int)(OptionalDeviceInteger(fields, name, minimum, maximum) ?? throw new InvalidResponseException());

    private static long? CoverageCounter(Dictionary<string, JsonElement> fields, string name) => OptionalDeviceInteger(fields, name, 0, long.MaxValue);

    private static bool CoverageBoolean(Dictionary<string, JsonElement> fields, string name) =>
        OptionalDeviceBoolean(fields, name) ?? throw new InvalidResponseException();
}
