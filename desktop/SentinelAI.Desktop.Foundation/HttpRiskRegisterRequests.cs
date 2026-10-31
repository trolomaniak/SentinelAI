using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IRiskRegisterClient
{
    private const int MaximumRiskRegisterPageBytes = 1024 * 1024;
    // 200 history entries of the longest texts, with non-ASCII letters escaped as Core's JSON writes them.
    private const int MaximumRiskRecordBytes = 16 * 1024 * 1024;
    private static readonly string[] RiskStatuses = ["open", "monitoring", "closed"];
    private static readonly string[] RiskTreatments = ["avoid", "mitigate", "transfer", "accept"];
    private static readonly string[] RiskLevels = ["low", "medium", "high", "critical"];
    private static readonly string[] RiskActions = ["created", "updated", "reviewed"];
    private static readonly string[] RiskAlertStatuses = ["open", "investigating", "accepted", "resolved"];
    private static readonly string[] RiskAlertSeverities = ["critical", "high", "medium", "low", "info"];

    private sealed record RiskWrite(RiskRegisterDetail? Detail, IReadOnlyList<RiskRegisterError>? Errors);

    public async Task<RiskRegisterResult<RiskRegisterPage>> GetRiskRegisterAsync(RiskRegisterQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var parameters = new List<string>();
        if (query.Status is { } status) parameters.Add("status=" + Uri.EscapeDataString(status));
        if (query.Treatment is { } treatment) parameters.Add("treatment=" + Uri.EscapeDataString(treatment));
        if (query.Level is { } level) parameters.Add("level=" + Uri.EscapeDataString(level));
        if (query.AttentionOnly) parameters.Add("attention=true");
        if (query.EndpointId is { } endpointId) parameters.Add("endpointId=" + endpointId.ToString("D"));
        if (query.AlertId is { } alertId) parameters.Add("alertId=" + alertId.ToString("D"));
        parameters.Add("offset=" + query.Offset.ToString(CultureInfo.InvariantCulture));
        parameters.Add("limit=" + query.Limit.ToString(CultureInfo.InvariantCulture));
        var result = await SendEnrollmentAsync(HttpMethod.Get, "api/admin/risk-register?" + string.Join('&', parameters), null,
            MaximumRiskRegisterPageBytes, ParseRiskRegisterPage, cancellationToken, maximumDepth: 5).ConfigureAwait(false);
        return new RiskRegisterResult<RiskRegisterPage>(MapRisk(result.Outcome), result.Value);
    }

    public async Task<RiskRegisterResult<RiskRegisterDetail>> GetRiskRecordAsync(Guid riskId, CancellationToken cancellationToken) =>
        MapRiskWrite(await SendEnrollmentAsync(HttpMethod.Get, $"api/admin/risk-register/{riskId:D}", null, MaximumRiskRecordBytes, ParseRiskWrite,
            cancellationToken, maximumDepth: 6).ConfigureAwait(false));

    public async Task<RiskRegisterResult<RiskRegisterDetail>> CreateRiskRecordAsync(RiskRegisterDraft draft, CancellationToken cancellationToken) =>
        MapRiskWrite(await SendEnrollmentAsync(HttpMethod.Post, "api/admin/risk-register", RiskDraftBody(draft, null), MaximumRiskRecordBytes,
            ParseRiskWrite, cancellationToken, maximumDepth: 6, parseRejected: ParseRiskErrors).ConfigureAwait(false));

    public async Task<RiskRegisterResult<RiskRegisterDetail>> UpdateRiskRecordAsync(Guid riskId, long expectedVersion, RiskRegisterDraft draft,
        CancellationToken cancellationToken) =>
        MapRiskWrite(await SendEnrollmentAsync(HttpMethod.Put, $"api/admin/risk-register/{riskId:D}", RiskDraftBody(draft, expectedVersion),
            MaximumRiskRecordBytes, ParseRiskWrite, cancellationToken, maximumDepth: 6, parseRejected: ParseRiskErrors).ConfigureAwait(false));

    public async Task<RiskRegisterResult<RiskRegisterDetail>> ReviewRiskRecordAsync(Guid riskId, long expectedVersion, string nextReviewDate, string? note,
        CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteNumber("expectedVersion", expectedVersion);
            writer.WriteString("nextReviewDate", nextReviewDate);
            if (note is null) writer.WriteNull("note");
            else writer.WriteString("note", note);
            writer.WriteEndObject();
        }

        return MapRiskWrite(await SendEnrollmentAsync(HttpMethod.Post, $"api/admin/risk-register/{riskId:D}/review", body.ToArray(), MaximumRiskRecordBytes,
            ParseRiskWrite, cancellationToken, maximumDepth: 6, parseRejected: ParseRiskErrors).ConfigureAwait(false));
    }

    private static RiskRegisterOutcome MapRisk(ComputerEnrollmentOutcome outcome) => outcome switch
    {
        ComputerEnrollmentOutcome.Success => RiskRegisterOutcome.Success,
        ComputerEnrollmentOutcome.Unauthenticated => RiskRegisterOutcome.Unauthenticated,
        ComputerEnrollmentOutcome.UntrustedConnection => RiskRegisterOutcome.UntrustedConnection,
        ComputerEnrollmentOutcome.InvalidResponse => RiskRegisterOutcome.InvalidResponse,
        ComputerEnrollmentOutcome.TooLarge => RiskRegisterOutcome.TooLarge,
        ComputerEnrollmentOutcome.NotFound => RiskRegisterOutcome.NotFound,
        ComputerEnrollmentOutcome.Conflict => RiskRegisterOutcome.Conflict,
        ComputerEnrollmentOutcome.Rejected => RiskRegisterOutcome.Rejected,
        _ => RiskRegisterOutcome.Unavailable
    };

    private static RiskRegisterResult<RiskRegisterDetail> MapRiskWrite(ComputerEnrollmentResult<RiskWrite> result) =>
        new(MapRisk(result.Outcome), result.Outcome == ComputerEnrollmentOutcome.Success ? result.Value?.Detail : null, result.Value?.Errors);

    private static byte[] RiskDraftBody(RiskRegisterDraft draft, long? expectedVersion)
    {
        ArgumentNullException.ThrowIfNull(draft);
        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            void Text(string name, string? value)
            {
                if (value is null) writer.WriteNull(name);
                else writer.WriteString(name, value);
            }

            writer.WriteStartObject();
            if (expectedVersion is { } version)
            {
                writer.WriteNumber("expectedVersion", version);
                writer.WriteStartObject("record");
            }

            Text("title", draft.Title);
            Text("description", draft.Description);
            Text("owner", draft.Owner);
            writer.WriteNumber("likelihood", draft.Likelihood);
            writer.WriteNumber("impact", draft.Impact);
            Text("controls", draft.Controls);
            writer.WriteNumber("residualLikelihood", draft.ResidualLikelihood);
            writer.WriteNumber("residualImpact", draft.ResidualImpact);
            Text("treatment", draft.Treatment);
            Text("acceptanceRationale", draft.AcceptanceRationale);
            Text("acceptanceExpiresOn", draft.AcceptanceExpiresOn);
            Text("targetDate", draft.TargetDate);
            Text("reviewDate", draft.ReviewDate);
            Text("status", draft.Status);
            writer.WriteStartArray("endpointIds");
            foreach (var id in draft.EndpointIds) writer.WriteStringValue(id.ToString("D"));
            writer.WriteEndArray();
            writer.WriteStartArray("alertIds");
            foreach (var id in draft.AlertIds) writer.WriteStringValue(id.ToString("D"));
            writer.WriteEndArray();
            writer.WriteStartArray("tickets");
            foreach (var ticket in draft.Tickets) writer.WriteStringValue(ticket);
            writer.WriteEndArray();
            Text("note", draft.Note);
            if (expectedVersion is not null) writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return body.ToArray();
    }

    private static RiskRegisterPage ParseRiskRegisterPage(JsonElement root)
    {
        var fields = ReadProperties(root, ["records", "total", "offset", "limit", "counts", "today"]);
        if (fields.Count != 6 || fields["records"].ValueKind != JsonValueKind.Array || fields["records"].GetArrayLength() > 200 ||
            !fields["total"].TryGetInt64(out var total) || total is < 0 or > 100_000 || !fields["offset"].TryGetInt32(out var offset) || offset < 0 ||
            !fields["limit"].TryGetInt32(out var limit) || limit is < 1 or > 200 || fields["records"].GetArrayLength() > limit)
            throw new InvalidResponseException();
        var counts = ReadProperties(fields["counts"], ["open", "monitoring", "closed", "needsAttention"]);
        if (counts.Count != 4) throw new InvalidResponseException();
        return new RiskRegisterPage(fields["records"].EnumerateArray().Select(ParseRiskSummary).ToArray(), total, offset, limit,
            new RiskRegisterCounts(RiskCount(counts["open"]), RiskCount(counts["monitoring"]), RiskCount(counts["closed"]), RiskCount(counts["needsAttention"])),
            RiskDay(fields["today"]) ?? throw new InvalidResponseException());
    }

    private static RiskRegisterSummary ParseRiskSummary(JsonElement element)
    {
        var fields = ReadProperties(element, ["riskId", "reference", "title", "status", "treatment", "owner", "inherent", "residual", "reviewDate",
            "targetDate", "acceptanceExpiresOn", "flags", "endpointCount", "alertCount", "version", "updatedUtc"]);
        if (fields.Count != 16) throw new InvalidResponseException();
        return new RiskRegisterSummary(RiskId(fields["riskId"]), RiskReference(fields["reference"]), RiskText(fields["title"], 200, false),
            RiskChoice(fields["status"], RiskStatuses), RiskOptionalChoice(fields["treatment"], RiskTreatments), RiskOptionalText(fields["owner"], 128, false),
            RiskRating(fields["inherent"]), RiskRating(fields["residual"]), RiskDay(fields["reviewDate"]), RiskDay(fields["targetDate"]),
            RiskDay(fields["acceptanceExpiresOn"]), RiskFlags(fields["flags"]), RiskLinkCount(fields["endpointCount"], 32), RiskLinkCount(fields["alertCount"], 64),
            RiskVersion(fields["version"]), LicenseDate(fields["updatedUtc"]));
    }

    private static RiskWrite ParseRiskWrite(JsonElement root)
    {
        var fields = ReadProperties(root, ["riskId", "reference", "title", "description", "owner", "inherent", "controls", "residual", "treatment",
            "acceptanceRationale", "acceptanceExpiresOn", "targetDate", "reviewDate", "status", "flags", "endpoints", "alerts", "tickets", "createdUtc",
            "createdBy", "updatedUtc", "updatedBy", "lastReviewedUtc", "lastReviewedBy", "version", "history", "today"]);
        if (fields.Count != 27 || fields["endpoints"].ValueKind != JsonValueKind.Array || fields["endpoints"].GetArrayLength() > 32 ||
            fields["alerts"].ValueKind != JsonValueKind.Array || fields["alerts"].GetArrayLength() > 64 ||
            fields["tickets"].ValueKind != JsonValueKind.Array || fields["tickets"].GetArrayLength() > 16 ||
            fields["history"].ValueKind != JsonValueKind.Array || fields["history"].GetArrayLength() is < 1 or > 200)
            throw new InvalidResponseException();
        var endpoints = fields["endpoints"].EnumerateArray().Select(endpoint =>
        {
            var parts = ReadProperties(endpoint, ["endpointId", "name", "enrolled"]);
            if (parts.Count != 3) throw new InvalidResponseException();
            var enrolled = RiskBoolean(parts["enrolled"]);
            var name = RiskOptionalText(parts["name"], 256, false);
            if (enrolled != (name is not null)) throw new InvalidResponseException();
            return new RiskRegisterLinkedEndpoint(RiskId(parts["endpointId"]), name, enrolled);
        }).ToArray();
        var alerts = fields["alerts"].EnumerateArray().Select(alert =>
        {
            var parts = ReadProperties(alert, ["alertId", "exists", "endpointId", "endpointName", "ruleId", "title", "severity", "status"]);
            if (parts.Count != 8) throw new InvalidResponseException();
            var exists = RiskBoolean(parts["exists"]);
            if (!exists)
            {
                if (new[] { "endpointId", "endpointName", "ruleId", "title", "severity", "status" }.Any(name => parts[name].ValueKind != JsonValueKind.Null))
                    throw new InvalidResponseException();
                return new RiskRegisterLinkedAlert(RiskId(parts["alertId"]), false, null, null, null, null, null, null);
            }

            return new RiskRegisterLinkedAlert(RiskId(parts["alertId"]), true, RiskId(parts["endpointId"]), RiskText(parts["endpointName"], 256, false),
                RiskText(parts["ruleId"], 64, false), RiskText(parts["title"], 256, false), RiskChoice(parts["severity"], RiskAlertSeverities),
                RiskChoice(parts["status"], RiskAlertStatuses));
        }).ToArray();
        var tickets = fields["tickets"].EnumerateArray().Select(ticket => RiskText(ticket, 64, false)).ToArray();
        var history = fields["history"].EnumerateArray().Select(entry =>
        {
            var parts = ReadProperties(entry, ["version", "changedUtc", "changedBy", "action", "changes", "note"]);
            if (parts.Count != 6 || parts["changes"].ValueKind != JsonValueKind.Array || parts["changes"].GetArrayLength() > 17)
                throw new InvalidResponseException();
            var changes = parts["changes"].EnumerateArray().Select(change =>
            {
                var values = ReadProperties(change, ["field", "from", "to"]);
                if (values.Count != 3) throw new InvalidResponseException();
                return new RiskRegisterFieldChange(RiskText(values["field"], 32, false), RiskOptionalText(values["from"], 4096, true),
                    RiskOptionalText(values["to"], 4096, true));
            }).ToArray();
            return new RiskRegisterHistoryEntry(RiskVersion(parts["version"]), LicenseDate(parts["changedUtc"]), RiskText(parts["changedBy"], 256, false),
                RiskChoice(parts["action"], RiskActions), changes, RiskOptionalText(parts["note"], 2000, true));
        }).ToArray();
        var version = RiskVersion(fields["version"]);
        var detail = new RiskRegisterDetail(RiskId(fields["riskId"]), RiskReference(fields["reference"]), RiskText(fields["title"], 200, false),
            RiskOptionalText(fields["description"], 2000, true), RiskOptionalText(fields["owner"], 128, false), RiskRating(fields["inherent"]),
            RiskOptionalText(fields["controls"], 2000, true), RiskRating(fields["residual"]), RiskOptionalChoice(fields["treatment"], RiskTreatments),
            RiskOptionalText(fields["acceptanceRationale"], 2000, true), RiskDay(fields["acceptanceExpiresOn"]), RiskDay(fields["targetDate"]),
            RiskDay(fields["reviewDate"]), RiskChoice(fields["status"], RiskStatuses), RiskFlags(fields["flags"]), endpoints, alerts, tickets,
            LicenseDate(fields["createdUtc"]), RiskText(fields["createdBy"], 256, false), LicenseDate(fields["updatedUtc"]),
            RiskText(fields["updatedBy"], 256, false), fields["lastReviewedUtc"].ValueKind == JsonValueKind.Null ? null : LicenseDate(fields["lastReviewedUtc"]),
            RiskOptionalText(fields["lastReviewedBy"], 256, false), version, history, RiskDay(fields["today"]) ?? throw new InvalidResponseException());
        // The history is complete and newest first: one entry per version.
        if (history.Length != version || history.Select(entry => entry.Version).Where((value, index) => value != version - index).Any() ||
            (detail.LastReviewedUtc is null) != (detail.LastReviewedBy is null) || (detail.Treatment == "accept") != (detail.AcceptanceExpiresOn is not null))
            throw new InvalidResponseException();
        return new RiskWrite(detail, null);
    }

    private static RiskWrite ParseRiskErrors(JsonElement root)
    {
        var fields = ReadProperties(root, ["errors"]);
        if (fields.Count != 1 || fields["errors"].ValueKind != JsonValueKind.Array || fields["errors"].GetArrayLength() is < 1 or > 64)
            throw new InvalidResponseException();
        return new RiskWrite(null, fields["errors"].EnumerateArray().Select(error =>
        {
            var parts = ReadProperties(error, ["field", "code"]);
            if (parts.Count != 2 || RiskText(parts["field"], 32, false) is not { } field || !RiskWord().IsMatch(field) ||
                RiskText(parts["code"], 32, false) is not { } code || !RiskWord().IsMatch(code)) throw new InvalidResponseException();
            return new RiskRegisterError(field, code);
        }).ToArray());
    }

    private static RiskRegisterRating RiskRating(JsonElement element)
    {
        var fields = ReadProperties(element, ["likelihood", "impact", "score", "level"]);
        if (fields.Count != 4 || !fields["likelihood"].TryGetInt32(out var likelihood) || likelihood is < 1 or > 5 ||
            !fields["impact"].TryGetInt32(out var impact) || impact is < 1 or > 5 || !fields["score"].TryGetInt32(out var score) || score != likelihood * impact)
            throw new InvalidResponseException();
        var level = RiskChoice(fields["level"], RiskLevels);
        if (level != (score <= 4 ? "low" : score <= 9 ? "medium" : score <= 16 ? "high" : "critical")) throw new InvalidResponseException();
        return new RiskRegisterRating(likelihood, impact, score, level);
    }

    private static RiskRegisterFlags RiskFlags(JsonElement element)
    {
        var fields = ReadProperties(element, ["reviewOverdue", "acceptanceExpired", "targetDatePassed", "needsAttention"]);
        if (fields.Count != 4) throw new InvalidResponseException();
        var flags = new RiskRegisterFlags(RiskBoolean(fields["reviewOverdue"]), RiskBoolean(fields["acceptanceExpired"]),
            RiskBoolean(fields["targetDatePassed"]), RiskBoolean(fields["needsAttention"]));
        if (flags.NeedsAttention != (flags.ReviewOverdue || flags.AcceptanceExpired || flags.TargetDatePassed)) throw new InvalidResponseException();
        return flags;
    }

    private static Guid RiskId(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && Guid.TryParseExact(value.GetString(), "D", out var id) && id != Guid.Empty ? id : throw new InvalidResponseException();

    private static string RiskReference(JsonElement value) =>
        RiskText(value, 16, false) is var reference && RiskReferencePattern().IsMatch(reference) ? reference : throw new InvalidResponseException();

    private static string RiskChoice(JsonElement value, string[] allowed) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { } text && allowed.Contains(text, StringComparer.Ordinal) ? text : throw new InvalidResponseException();

    private static string? RiskOptionalChoice(JsonElement value, string[] allowed) => value.ValueKind == JsonValueKind.Null ? null : RiskChoice(value, allowed);

    private static string RiskText(JsonElement value, int maximum, bool multiline) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text && text.Length <= maximum &&
        !text.Any(character => char.IsControl(character) && !(multiline && character is '\r' or '\n' or '\t'))
            ? text
            : throw new InvalidResponseException();

    private static string? RiskOptionalText(JsonElement value, int maximum, bool multiline) =>
        value.ValueKind == JsonValueKind.Null ? null : RiskText(value, maximum, multiline);

    private static string? RiskDay(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.String when value.GetString() is { Length: 10 } text &&
                                  DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _) => text,
        _ => throw new InvalidResponseException()
    };

    private static bool RiskBoolean(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException()
    };

    private static int RiskCount(JsonElement value) => value.TryGetInt32(out var count) && count is >= 0 and <= 100_000 ? count : throw new InvalidResponseException();

    private static int RiskLinkCount(JsonElement value, int maximum) =>
        value.TryGetInt32(out var count) && count >= 0 && count <= maximum ? count : throw new InvalidResponseException();

    private static long RiskVersion(JsonElement value) =>
        value.TryGetInt64(out var version) && version is >= 1 and <= 1_000 ? version : throw new InvalidResponseException();

    [GeneratedRegex(@"\AR-[0-9]{4,6}\z", RegexOptions.CultureInvariant)]
    private static partial Regex RiskReferencePattern();

    [GeneratedRegex(@"\A[A-Za-z]{1,32}\z", RegexOptions.CultureInvariant)]
    private static partial Regex RiskWord();
}
