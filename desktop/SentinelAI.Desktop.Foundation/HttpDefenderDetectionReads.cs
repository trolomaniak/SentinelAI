using System.Globalization;
using System.Text.Json;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IDefenderDetectionsClient
{
    private const int MaximumDefenderHistoryBytes = 256 * 1024;

    public Task<DeviceReadResult<DefenderDetectionsView>> GetDefenderDetectionsAsync(Guid endpointId, int offset, int limit,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(offset, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, 10_000);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 100);
        if (endpointId == Guid.Empty) throw new ArgumentException("An enrolled endpoint is required.", nameof(endpointId));
        return ReadDeviceResourceAsync("api/admin/devices/" + endpointId.ToString("D") + "/defender-detections?offset=" +
            offset.ToString(CultureInfo.InvariantCulture) + "&limit=" + limit.ToString(CultureInfo.InvariantCulture), MaximumDefenderHistoryBytes,
            root => ParseDefenderHistory(root, endpointId, offset, limit), allowNotFound: true, cancellationToken);
    }

    private static DefenderDetectionsView ParseDefenderHistory(JsonElement root, Guid endpointId, int offset, int limit)
    {
        var fields = ReadProperties(root, ["endpointId", "generatedUtc", "sourceState", "sourceReportedUtc", "lastReadUtc", "retentionDays",
            "offset", "limit", "totalCount", "detections"]);
        if (fields.Count != 10 || fields["endpointId"].ValueKind != JsonValueKind.String || !fields["endpointId"].TryGetGuid(out var actualId) ||
            actualId != endpointId || fields["sourceState"].ValueKind != JsonValueKind.String ||
            fields["sourceState"].GetString() is not ("collecting" or "disabled" or "accessDenied" or "notFound" or "error" or "notReported") ||
            fields["detections"].ValueKind != JsonValueKind.Array || fields["detections"].GetArrayLength() > limit ||
            DefenderNumber(fields["offset"], 0, 10_000) != offset || DefenderNumber(fields["limit"], 1, 100) != limit)
            throw new InvalidResponseException();
        var total = (int)DefenderNumber(fields["totalCount"], 0, 10_000);
        var count = fields["detections"].GetArrayLength();
        if (count != Math.Min(limit, Math.Max(0, total - offset))) throw new InvalidResponseException();
        var sourceReported = OptionalDeviceDate(fields, "sourceReportedUtc");
        var lastRead = OptionalDeviceDate(fields, "lastReadUtc");
        var sourceState = fields["sourceState"].GetString()!;
        if ((sourceState == "notReported") != (sourceReported is null) || sourceState == "notReported" && lastRead is not null)
            throw new InvalidResponseException();
        var detections = fields["detections"].EnumerateArray().Select(ParseDefenderDetection).ToArray();
        return new DefenderDetectionsView(endpointId, OptionalDeviceDate(fields, "generatedUtc") ?? throw new InvalidResponseException(),
            sourceState, sourceReported, lastRead, (int)DefenderNumber(fields["retentionDays"], 1, 3650), offset, limit, total, detections);
    }

    private static DefenderDetection ParseDefenderDetection(JsonElement element)
    {
        var fields = ReadProperties(element, ["timeCreatedUtc", "receivedUtc", "eventId", "kind", "detectionId", "threatId", "threatName",
            "severityId", "categoryId", "actionId", "errorCode"]);
        if (fields.Count != 11 || fields["kind"].ValueKind != JsonValueKind.String) throw new InvalidResponseException();
        var kind = fields["kind"].GetString()!;
        var eventId = (int)DefenderNumber(fields["eventId"], 1116, 1119);
        if (!(eventId == 1116 && kind == SecurityEventKinds.MalwareDetected ||
              eventId == 1117 && kind == SecurityEventKinds.MalwareActionTaken ||
              eventId is 1118 or 1119 && kind == SecurityEventKinds.MalwareActionFailed)) throw new InvalidResponseException();
        Guid? detectionId = fields["detectionId"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String when fields["detectionId"].TryGetGuid(out var value) => value,
            _ => throw new InvalidResponseException()
        };
        var threatName = fields["threatName"].ValueKind == JsonValueKind.Null ? null :
            fields["threatName"].ValueKind == JsonValueKind.String && SecurityEventContract.IsBoundedText(fields["threatName"].GetString(), 256)
                ? fields["threatName"].GetString() : throw new InvalidResponseException();
        if (eventId == 1116 && (fields["actionId"].ValueKind != JsonValueKind.Null || fields["errorCode"].ValueKind != JsonValueKind.Null) ||
            eventId == 1117 && fields["errorCode"].ValueKind != JsonValueKind.Null) throw new InvalidResponseException();
        return new DefenderDetection(OptionalDeviceDate(fields, "timeCreatedUtc") ?? throw new InvalidResponseException(),
            OptionalDeviceDate(fields, "receivedUtc") ?? throw new InvalidResponseException(), eventId, kind, detectionId,
            OptionalDeviceInteger(fields, "threatId", 0, long.MaxValue), threatName,
            (int?)OptionalDeviceInteger(fields, "severityId", 0, 255), (int?)OptionalDeviceInteger(fields, "categoryId", 0, 255),
            (int?)OptionalDeviceInteger(fields, "actionId", 0, 255), OptionalDeviceInteger(fields, "errorCode", 0, uint.MaxValue));
    }

    private static long DefenderNumber(JsonElement element, long minimum, long maximum) =>
        element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out var value) && value >= minimum && value <= maximum
            ? value : throw new InvalidResponseException();
}
