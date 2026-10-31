using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

/// <summary>
/// TASK-032: the operational Risk Register. A record is an administrator's business judgement (likelihood and impact on
/// a 5 × 5 scale before and after existing controls, a treatment, an owner and dates) linked to endpoints and tracked
/// alerts. It is kept apart from the calculated technical endpoint score: saving, accepting or closing a record never
/// changes an alert, a detection rule or a score.
/// </summary>
public static class RiskRegisterPolicy
{
    public const int MaximumRecords = 2_000;
    /// <summary>Each save adds one history entry; a record with this many entries takes no further changes.</summary>
    public const int MaximumHistoryEntries = 200;
    public const int MaximumEndpoints = 32;
    public const int MaximumAlerts = 64;
    public const int MaximumTickets = 16;
    /// <summary>An acceptance expires at most this many days after it is recorded, so that it is reconsidered.</summary>
    public const int MaximumAcceptanceDays = 366;
    public const int MaximumTitleLength = 200;
    public const int MaximumOwnerLength = 128;
    public const int MaximumTextLength = 2_000;
    public const int MaximumTicketLength = 64;
    public static IReadOnlyList<string> Statuses { get; } = ["open", "monitoring", "closed"];
    public static IReadOnlyList<string> Treatments { get; } = ["avoid", "mitigate", "transfer", "accept"];
    public static IReadOnlyList<string> Levels { get; } = ["low", "medium", "high", "critical"];

    /// <summary>Likelihood × impact: 1–4 low, 5–9 medium, 10–16 high, 20–25 critical.</summary>
    public static string Level(int score) => score switch { <= 4 => "low", <= 9 => "medium", <= 16 => "high", _ => "critical" };
}

/// <summary>A record as an administrator saves it. Dates are <c>yyyy-MM-dd</c>; empty text means none.</summary>
public sealed record RiskRecordInput(
    string? Title,
    string? Description,
    string? Owner,
    int Likelihood,
    int Impact,
    string? Controls,
    int ResidualLikelihood,
    int ResidualImpact,
    string? Treatment,
    string? AcceptanceRationale,
    string? AcceptanceExpiresOn,
    string? TargetDate,
    string? ReviewDate,
    string? Status,
    IReadOnlyList<Guid>? EndpointIds,
    IReadOnlyList<Guid>? AlertIds,
    IReadOnlyList<string>? Tickets,
    string? Note);

public sealed record UpdateRiskRecordRequest(long ExpectedVersion, RiskRecordInput? Record);

public sealed record ReviewRiskRecordRequest(long ExpectedVersion, string? NextReviewDate, string? Note);

public sealed record RiskRating(int Likelihood, int Impact, int Score, string Level);

public sealed record RiskRecordFlags(bool ReviewOverdue, bool AcceptanceExpired, bool TargetDatePassed)
{
    public bool NeedsAttention => ReviewOverdue || AcceptanceExpired || TargetDatePassed;
}

public sealed record RiskRecordSummary(
    Guid RiskId,
    string Reference,
    string Title,
    string Status,
    string? Treatment,
    string? Owner,
    RiskRating Inherent,
    RiskRating Residual,
    string? ReviewDate,
    string? TargetDate,
    string? AcceptanceExpiresOn,
    RiskRecordFlags Flags,
    int EndpointCount,
    int AlertCount,
    long Version,
    DateTimeOffset UpdatedUtc);

public sealed record RiskRegisterCounts(int Open, int Monitoring, int Closed, int NeedsAttention);

/// <summary>A page of records; <see cref="Today"/> is the UTC date the flags were evaluated for.</summary>
public sealed record RiskRegisterPage(IReadOnlyList<RiskRecordSummary> Records, long Total, int Offset, int Limit, RiskRegisterCounts Counts,
    string Today);

public sealed record RiskLinkedEndpoint(Guid EndpointId, string? Name, bool Enrolled);

public sealed record RiskLinkedAlert(Guid AlertId, bool Exists, Guid? EndpointId, string? EndpointName, string? RuleId, string? Title,
    string? Severity, string? Status);

public sealed record RiskFieldChange(string Field, string? From, string? To);

public sealed record RiskRecordHistoryEntry(long Version, DateTimeOffset ChangedUtc, string ChangedBy, string Action,
    IReadOnlyList<RiskFieldChange> Changes, string? Note);

public sealed record RiskRecordDetail(
    Guid RiskId,
    string Reference,
    string Title,
    string? Description,
    string? Owner,
    RiskRating Inherent,
    string? Controls,
    RiskRating Residual,
    string? Treatment,
    string? AcceptanceRationale,
    string? AcceptanceExpiresOn,
    string? TargetDate,
    string? ReviewDate,
    string Status,
    RiskRecordFlags Flags,
    IReadOnlyList<RiskLinkedEndpoint> Endpoints,
    IReadOnlyList<RiskLinkedAlert> Alerts,
    IReadOnlyList<string> Tickets,
    DateTimeOffset CreatedUtc,
    string CreatedBy,
    DateTimeOffset UpdatedUtc,
    string UpdatedBy,
    DateTimeOffset? LastReviewedUtc,
    string? LastReviewedBy,
    long Version,
    IReadOnlyList<RiskRecordHistoryEntry> History,
    string Today);

public sealed record RiskValidationError(string Field, string Code);

public sealed record RiskValidationResponse(IReadOnlyList<RiskValidationError> Errors);

public enum RiskRegisterOutcome { Saved, NotFound, Conflict, Invalid }

public sealed record RiskRegisterResult(RiskRegisterOutcome Outcome, RiskRecordDetail? Record = null, IReadOnlyList<RiskValidationError>? Errors = null);

/// <summary>Filters: status <c>active</c> means not closed, treatment <c>none</c> means not decided, level is the residual level.</summary>
public sealed record RiskRegisterQuery(string? Status, string? Treatment, string? Level, bool AttentionOnly, Guid? EndpointId, Guid? AlertId,
    int Offset, int Limit);

/// <summary>The normalized record as stored.</summary>
internal sealed record StoredRiskRecord(
    string Title,
    string? Description,
    string? Owner,
    int Likelihood,
    int Impact,
    string? Controls,
    int ResidualLikelihood,
    int ResidualImpact,
    string? Treatment,
    string? AcceptanceRationale,
    string? AcceptanceExpiresOn,
    string? TargetDate,
    string? ReviewDate,
    string Status,
    Guid[] EndpointIds,
    Guid[] AlertIds,
    string[] Tickets);

internal static class RiskRegisterValidation
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string Iso(DateOnly date) => date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    public static DateOnly? ParseDate(string? value) =>
        value is { Length: 10 } && DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) &&
        date.Year is >= 2000 and <= 9998 ? date : null;

    /// <summary>
    /// A record is valid on its own and against the record it replaces: a date an administrator sets or changes may not
    /// lie in the past, and an acceptance needs an owner, a rationale and an expiry within a year.
    /// </summary>
    public static (StoredRiskRecord? Record, string? Note, List<RiskValidationError> Errors) Validate(RiskRecordInput input, StoredRiskRecord? current,
        DateOnly today)
    {
        var errors = new List<RiskValidationError>();
        bool Failed(string field) => errors.Any(error => error.Field == field);
        var title = Text(input.Title, RiskRegisterPolicy.MaximumTitleLength, "title", multiline: false, required: true, errors);
        var description = Text(input.Description, RiskRegisterPolicy.MaximumTextLength, "description", multiline: true, required: false, errors);
        var owner = Text(input.Owner, RiskRegisterPolicy.MaximumOwnerLength, "owner", multiline: false, required: false, errors);
        var controls = Text(input.Controls, RiskRegisterPolicy.MaximumTextLength, "controls", multiline: true, required: false, errors);
        foreach (var (value, field) in new[] { (input.Likelihood, "likelihood"), (input.Impact, "impact"),
                     (input.ResidualLikelihood, "residualLikelihood"), (input.ResidualImpact, "residualImpact") })
            if (value is < 1 or > 5) errors.Add(new(field, "range"));
        // Existing controls cannot make a risk greater than it is without them.
        if (!errors.Any(error => error.Code == "range") && input.ResidualLikelihood * input.ResidualImpact > input.Likelihood * input.Impact)
            errors.Add(new("residual", "exceedsInherent"));

        var status = input.Status is { } statusText && RiskRegisterPolicy.Statuses.Contains(statusText) ? statusText : null;
        if (status is null) errors.Add(new("status", "invalid"));
        string? treatment = null;
        if (!string.IsNullOrEmpty(input.Treatment))
        {
            if (RiskRegisterPolicy.Treatments.Contains(input.Treatment)) treatment = input.Treatment;
            else errors.Add(new("treatment", "invalid"));
        }

        if (status == "monitoring" && treatment is null && !Failed("treatment")) errors.Add(new("treatment", "required"));
        var rationale = Text(input.AcceptanceRationale, RiskRegisterPolicy.MaximumTextLength, "acceptanceRationale", multiline: true, required: false, errors);
        var expires = Date(input.AcceptanceExpiresOn, "acceptanceExpiresOn", errors);
        if (treatment == "accept")
        {
            // Accepting a risk is an explicit, owned and time-limited decision.
            if (owner is null && !Failed("owner")) errors.Add(new("owner", "requiredForAcceptance"));
            if (rationale is null && !Failed("acceptanceRationale")) errors.Add(new("acceptanceRationale", "required"));
            if (expires is null)
            {
                if (!Failed("acceptanceExpiresOn")) errors.Add(new("acceptanceExpiresOn", "required"));
            }
            else if (current is null || current.Treatment != "accept" || current.AcceptanceExpiresOn != Iso(expires.Value))
            {
                if (expires.Value <= today) errors.Add(new("acceptanceExpiresOn", "notFuture"));
                else if (expires.Value > today.AddDays(RiskRegisterPolicy.MaximumAcceptanceDays)) errors.Add(new("acceptanceExpiresOn", "tooFar"));
            }
        }
        else
        {
            if (rationale is not null) errors.Add(new("acceptanceRationale", "onlyForAcceptance"));
            if (expires is not null) errors.Add(new("acceptanceExpiresOn", "onlyForAcceptance"));
        }

        var target = Date(input.TargetDate, "targetDate", errors);
        var review = Date(input.ReviewDate, "reviewDate", errors);
        if (review is null && status is not null and not "closed" && !Failed("reviewDate")) errors.Add(new("reviewDate", "required"));
        if (review is { } reviewDate && reviewDate < today && current?.ReviewDate != Iso(reviewDate)) errors.Add(new("reviewDate", "past"));

        var endpoints = Ids(input.EndpointIds, RiskRegisterPolicy.MaximumEndpoints, "endpointIds", errors);
        var alerts = Ids(input.AlertIds, RiskRegisterPolicy.MaximumAlerts, "alertIds", errors);
        var tickets = Tickets(input.Tickets, errors);
        var note = Text(input.Note, RiskRegisterPolicy.MaximumTextLength, "note", multiline: true, required: false, errors);
        if (errors.Count > 0) return (null, null, errors);
        return (new StoredRiskRecord(title!, description, owner, input.Likelihood, input.Impact, controls, input.ResidualLikelihood,
            input.ResidualImpact, treatment, rationale, expires is { } accepted ? Iso(accepted) : null, target is { } targetDate ? Iso(targetDate) : null,
            review is { } next ? Iso(next) : null, status!, endpoints, alerts, tickets), note, errors);
    }

    public static string? Text(string? value, int maximum, string field, bool multiline, bool required, List<RiskValidationError> errors)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            if (required) errors.Add(new(field, "required"));
            return null;
        }

        if (text.Length > maximum)
        {
            errors.Add(new(field, "tooLong"));
            return null;
        }

        try { StrictUtf8.GetByteCount(text); }
        catch (ArgumentException)
        {
            errors.Add(new(field, "invalid"));
            return null;
        }

        // Literal text only: no control or invisible formatting characters (a note keeps its line breaks and tabs).
        if (text.Any(character => (char.IsControl(character) && !(multiline && character is '\r' or '\n' or '\t')) ||
                                  CharUnicodeInfo.GetUnicodeCategory(character) == UnicodeCategory.Format))
        {
            errors.Add(new(field, "invalid"));
            return null;
        }

        return text;
    }

    private static DateOnly? Date(string? value, string field, List<RiskValidationError> errors)
    {
        if (string.IsNullOrEmpty(value)) return null;
        if (ParseDate(value) is { } date) return date;
        errors.Add(new(field, "invalid"));
        return null;
    }

    private static Guid[] Ids(IReadOnlyList<Guid>? ids, int maximum, string field, List<RiskValidationError> errors)
    {
        if (ids is null || ids.Count == 0) return [];
        if (ids.Count > maximum) errors.Add(new(field, "tooMany"));
        else if (ids.Contains(Guid.Empty)) errors.Add(new(field, "invalid"));
        else if (ids.Distinct().Count() != ids.Count) errors.Add(new(field, "duplicate"));
        return ids.Order().ToArray();
    }

    private static string[] Tickets(IReadOnlyList<string>? tickets, List<RiskValidationError> errors)
    {
        if (tickets is null || tickets.Count == 0) return [];
        if (tickets.Count > RiskRegisterPolicy.MaximumTickets)
        {
            errors.Add(new("tickets", "tooMany"));
            return [];
        }

        var values = new List<string>();
        foreach (var ticket in tickets)
        {
            if (Text(ticket, RiskRegisterPolicy.MaximumTicketLength, "tickets", multiline: false, required: true, errors) is not { } value) return [];
            values.Add(value);
        }

        if (values.Distinct(StringComparer.Ordinal).Count() != values.Count) errors.Add(new("tickets", "duplicate"));
        return values.Order(StringComparer.Ordinal).ToArray();
    }

    /// <summary>The fields an update changed, in a fixed order, as literal text.</summary>
    public static IReadOnlyList<RiskFieldChange> Changes(StoredRiskRecord? before, StoredRiskRecord after)
    {
        var changes = new List<RiskFieldChange>();
        void Add(string field, string? from, string? to)
        {
            if (!string.Equals(from, to, StringComparison.Ordinal)) changes.Add(new RiskFieldChange(field, from, to));
        }

        static string? Number(int? value) => value?.ToString(CultureInfo.InvariantCulture);
        static string? Join<T>(IEnumerable<T>? values) => values?.Select(value => value is Guid id ? id.ToString("D") : value?.ToString()).ToArray() is
            { Length: > 0 } items ? string.Join(", ", items) : null;
        Add("title", before?.Title, after.Title);
        Add("description", before?.Description, after.Description);
        Add("owner", before?.Owner, after.Owner);
        Add("likelihood", Number(before?.Likelihood), Number(after.Likelihood));
        Add("impact", Number(before?.Impact), Number(after.Impact));
        Add("controls", before?.Controls, after.Controls);
        Add("residualLikelihood", Number(before?.ResidualLikelihood), Number(after.ResidualLikelihood));
        Add("residualImpact", Number(before?.ResidualImpact), Number(after.ResidualImpact));
        Add("treatment", before?.Treatment, after.Treatment);
        Add("acceptanceRationale", before?.AcceptanceRationale, after.AcceptanceRationale);
        Add("acceptanceExpiresOn", before?.AcceptanceExpiresOn, after.AcceptanceExpiresOn);
        Add("targetDate", before?.TargetDate, after.TargetDate);
        Add("reviewDate", before?.ReviewDate, after.ReviewDate);
        Add("status", before?.Status, after.Status);
        Add("endpointIds", Join(before?.EndpointIds), Join(after.EndpointIds));
        Add("alertIds", Join(before?.AlertIds), Join(after.AlertIds));
        Add("tickets", Join(before?.Tickets), Join(after.Tickets));
        return changes;
    }

    public static RiskRecordFlags Flags(StoredRiskRecord record, DateOnly today) => new(
        record.Status != "closed" && ParseDate(record.ReviewDate) is { } review && review < today,
        record.Status != "closed" && record.Treatment == "accept" && ParseDate(record.AcceptanceExpiresOn) is { } expires && expires < today,
        record.Status == "open" && record.Treatment is "avoid" or "mitigate" or "transfer" && ParseDate(record.TargetDate) is { } target && target < today);

    public static RiskRating Rating(int likelihood, int impact) =>
        new(likelihood, impact, likelihood * impact, RiskRegisterPolicy.Level(likelihood * impact));
}

/// <summary>Strict reading of the Risk Register list query.</summary>
internal static class RiskRegisterRequests
{
    private static readonly string[] QueryKeys = ["status", "treatment", "level", "attention", "endpointId", "alertId", "offset", "limit"];

    public static bool TryReadQuery(IQueryCollection query, out RiskRegisterQuery result)
    {
        result = new RiskRegisterQuery(null, null, null, false, null, null, 0, 50);
        if (query.Any(pair => !QueryKeys.Contains(pair.Key, StringComparer.Ordinal) || pair.Value.Count != 1)) return false;
        string? Value(string key) => query.TryGetValue(key, out var value) ? value.ToString() : null;
        var status = Value("status");
        var treatment = Value("treatment");
        var level = Value("level");
        if (status is not (null or "active" or "open" or "monitoring" or "closed") ||
            (treatment is not null && treatment != "none" && !RiskRegisterPolicy.Treatments.Contains(treatment)) ||
            (level is not null && !RiskRegisterPolicy.Levels.Contains(level))) return false;
        bool? attention = Value("attention") switch { null or "false" => false, "true" => true, _ => null };
        if (attention is null || !TryId(Value("endpointId"), out var endpointId) || !TryId(Value("alertId"), out var alertId)) return false;
        var offset = 0;
        var limit = 50;
        if ((Value("offset") is { } offsetText && (!int.TryParse(offsetText, NumberStyles.None, CultureInfo.InvariantCulture, out offset) || offset > 1_000_000)) ||
            (Value("limit") is { } limitText && (!int.TryParse(limitText, NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit is < 1 or > 200)))
            return false;
        result = new RiskRegisterQuery(status, treatment, level, attention.Value, endpointId, alertId, offset, limit);
        return true;
    }

    private static bool TryId(string? text, out Guid? id)
    {
        id = null;
        if (text is null) return true;
        if (!Guid.TryParseExact(text, "D", out var value) || value == Guid.Empty) return false;
        id = value;
        return true;
    }
}

/// <summary>
/// TASK-032: Risk Register records and their append-only history in SQLite. Every save is versioned: a write names the
/// version the administrator reviewed and is refused when the record changed since. Nothing here reads or writes alerts'
/// status, detection rules or scores; links to endpoints and alerts are references only.
/// </summary>
public sealed class RiskRegisterStore(AdminStore admins, TimeProvider time)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS RiskRegister (
                RiskId TEXT NOT NULL PRIMARY KEY,
                Number INTEGER NOT NULL UNIQUE,
                Version INTEGER NOT NULL,
                RecordJson TEXT NOT NULL,
                CreatedUtcTicks INTEGER NOT NULL,
                CreatedBy TEXT NOT NULL,
                UpdatedUtcTicks INTEGER NOT NULL,
                UpdatedBy TEXT NOT NULL,
                LastReviewedUtcTicks INTEGER NULL,
                LastReviewedBy TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS RiskRegisterHistory (
                RiskId TEXT NOT NULL REFERENCES RiskRegister(RiskId),
                Version INTEGER NOT NULL,
                ChangedUtcTicks INTEGER NOT NULL,
                ChangedBy TEXT NOT NULL,
                Action TEXT NOT NULL CHECK (Action IN ('created', 'updated', 'reviewed')),
                ChangesJson TEXT NOT NULL,
                Note TEXT NULL,
                PRIMARY KEY (RiskId, Version)
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<RiskRegisterPage> ListAsync(RiskRegisterQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        var today = Today();
        var rows = new List<(RiskRecordSummary Summary, StoredRiskRecord Record, long Number)>();
        await using (var connection = await OpenAsync(cancellationToken))
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT RiskId, Number, Version, RecordJson, UpdatedUtcTicks FROM RiskRegister;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var record = Read(reader.GetString(3));
                var number = reader.GetInt64(1);
                rows.Add((Summarize(Guid.Parse(reader.GetString(0)), number, reader.GetInt64(2), record, Utc(reader.GetInt64(4)), today), record, number));
            }
        }

        var counts = new RiskRegisterCounts(rows.Count(row => row.Record.Status == "open"), rows.Count(row => row.Record.Status == "monitoring"),
            rows.Count(row => row.Record.Status == "closed"), rows.Count(row => row.Summary.Flags.NeedsAttention));
        var matching = rows.Where(row =>
                (query.Status is null || (query.Status == "active" ? row.Record.Status != "closed" : row.Record.Status == query.Status)) &&
                (query.Treatment is null || (query.Treatment == "none" ? row.Record.Treatment is null : row.Record.Treatment == query.Treatment)) &&
                (query.Level is null || row.Summary.Residual.Level == query.Level) &&
                (!query.AttentionOnly || row.Summary.Flags.NeedsAttention) &&
                (query.EndpointId is not { } endpointId || row.Record.EndpointIds.Contains(endpointId)) &&
                (query.AlertId is not { } alertId || row.Record.AlertIds.Contains(alertId)))
            .OrderByDescending(row => row.Summary.Flags.NeedsAttention).ThenByDescending(row => row.Summary.Residual.Score)
            .ThenByDescending(row => row.Summary.Inherent.Score).ThenBy(row => row.Number)
            .Select(row => row.Summary).ToArray();
        return new RiskRegisterPage(matching.Skip(query.Offset).Take(query.Limit).ToArray(), matching.LongLength, query.Offset, query.Limit, counts,
            RiskRegisterValidation.Iso(today));
    }

    public async Task<RiskRecordDetail?> FindAsync(Guid riskId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var detail = await ReadDetailAsync(connection, transaction, riskId, Today(), cancellationToken);
        transaction.Commit();
        return detail;
    }

    public async Task<RiskRegisterResult> CreateAsync(RiskRecordInput input, string actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        var today = Today();
        var (record, note, errors) = RiskRegisterValidation.Validate(input, null, today);
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        if (record is not null) errors.AddRange(await CheckLinksAsync(connection, transaction, record, null, cancellationToken));
        if (await ScalarAsync(connection, transaction, "SELECT COUNT(*) FROM RiskRegister;", null, cancellationToken) >= RiskRegisterPolicy.MaximumRecords)
            errors.Add(new RiskValidationError("register", "full"));
        if (record is null || errors.Count > 0) return new RiskRegisterResult(RiskRegisterOutcome.Invalid, Errors: errors);

        var riskId = Guid.NewGuid();
        var number = await ScalarAsync(connection, transaction, "SELECT COALESCE(MAX(Number), 0) + 1 FROM RiskRegister;", null, cancellationToken);
        var now = time.GetUtcNow();
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO RiskRegister (RiskId, Number, Version, RecordJson, CreatedUtcTicks, CreatedBy, UpdatedUtcTicks, UpdatedBy)
                VALUES ($riskId, $number, 1, $record, $now, $actor, $now, $actor);
                """;
            insert.Parameters.AddWithValue("$riskId", riskId.ToString("D"));
            insert.Parameters.AddWithValue("$number", number);
            insert.Parameters.AddWithValue("$record", JsonSerializer.Serialize(record, Json));
            insert.Parameters.AddWithValue("$now", now.UtcTicks);
            insert.Parameters.AddWithValue("$actor", actor);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await RecordHistoryAsync(connection, transaction, riskId, 1, now, actor, "created", RiskRegisterValidation.Changes(null, record), note,
            cancellationToken);
        var detail = await ReadDetailAsync(connection, transaction, riskId, today, cancellationToken);
        transaction.Commit();
        return new RiskRegisterResult(RiskRegisterOutcome.Saved, detail);
    }

    public async Task<RiskRegisterResult> UpdateAsync(Guid riskId, long expectedVersion, RiskRecordInput input, string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        var today = Today();
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        if (await ReadStoredAsync(connection, transaction, riskId, cancellationToken) is not { } current)
            return new RiskRegisterResult(RiskRegisterOutcome.NotFound);
        if (current.Version != expectedVersion) return new RiskRegisterResult(RiskRegisterOutcome.Conflict);
        var (record, note, errors) = RiskRegisterValidation.Validate(input, current.Record, today);
        if (record is not null) errors.AddRange(await CheckLinksAsync(connection, transaction, record, current.Record, cancellationToken));
        if (record is null || errors.Count > 0) return new RiskRegisterResult(RiskRegisterOutcome.Invalid, Errors: errors);
        var changes = RiskRegisterValidation.Changes(current.Record, record);
        if (changes.Count == 0 && note is null)
        {
            var unchanged = await ReadDetailAsync(connection, transaction, riskId, today, cancellationToken);
            transaction.Commit();
            return new RiskRegisterResult(RiskRegisterOutcome.Saved, unchanged);
        }

        if (current.Version >= RiskRegisterPolicy.MaximumHistoryEntries)
            return new RiskRegisterResult(RiskRegisterOutcome.Invalid, Errors: [new RiskValidationError("history", "full")]);
        var now = time.GetUtcNow();
        await SaveAsync(connection, transaction, riskId, current.Version, record, now, actor, reviewed: false, cancellationToken);
        await RecordHistoryAsync(connection, transaction, riskId, current.Version + 1, now, actor, "updated", changes, note, cancellationToken);
        var detail = await ReadDetailAsync(connection, transaction, riskId, today, cancellationToken);
        transaction.Commit();
        return new RiskRegisterResult(RiskRegisterOutcome.Saved, detail);
    }

    /// <summary>Records that the risk was reviewed and when it is next due; a closed record is not reviewed.</summary>
    public async Task<RiskRegisterResult> ReviewAsync(Guid riskId, long expectedVersion, string? nextReviewDate, string? note, string actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        var today = Today();
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        if (await ReadStoredAsync(connection, transaction, riskId, cancellationToken) is not { } current)
            return new RiskRegisterResult(RiskRegisterOutcome.NotFound);
        if (current.Version != expectedVersion) return new RiskRegisterResult(RiskRegisterOutcome.Conflict);
        var errors = new List<RiskValidationError>();
        if (current.Record.Status == "closed") errors.Add(new RiskValidationError("status", "closed"));
        var next = RiskRegisterValidation.ParseDate(nextReviewDate);
        if (string.IsNullOrEmpty(nextReviewDate)) errors.Add(new RiskValidationError("nextReviewDate", "required"));
        else if (next is null) errors.Add(new RiskValidationError("nextReviewDate", "invalid"));
        else if (next.Value <= today) errors.Add(new RiskValidationError("nextReviewDate", "notFuture"));
        var text = RiskRegisterValidation.Text(note, RiskRegisterPolicy.MaximumTextLength, "note", multiline: true, required: false, errors);
        if (errors.Count == 0 && current.Version >= RiskRegisterPolicy.MaximumHistoryEntries) errors.Add(new RiskValidationError("history", "full"));
        if (errors.Count > 0) return new RiskRegisterResult(RiskRegisterOutcome.Invalid, Errors: errors);

        var record = current.Record with { ReviewDate = RiskRegisterValidation.Iso(next!.Value) };
        var now = time.GetUtcNow();
        await SaveAsync(connection, transaction, riskId, current.Version, record, now, actor, reviewed: true, cancellationToken);
        await RecordHistoryAsync(connection, transaction, riskId, current.Version + 1, now, actor, "reviewed",
            RiskRegisterValidation.Changes(current.Record, record), text, cancellationToken);
        var detail = await ReadDetailAsync(connection, transaction, riskId, today, cancellationToken);
        transaction.Commit();
        return new RiskRegisterResult(RiskRegisterOutcome.Saved, detail);
    }

    private DateOnly Today() => DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime);

    private static DateTimeOffset Utc(long ticks) => new(ticks, TimeSpan.Zero);

    private static string Reference(long number) => "R-" + number.ToString("0000", CultureInfo.InvariantCulture);

    private static StoredRiskRecord Read(string json) =>
        JsonSerializer.Deserialize<StoredRiskRecord>(json, Json) ?? throw new InvalidDataException("A Risk Register record is unreadable.");

    private static RiskRecordSummary Summarize(Guid riskId, long number, long version, StoredRiskRecord record, DateTimeOffset updatedUtc, DateOnly today) =>
        new(riskId, Reference(number), record.Title, record.Status, record.Treatment, record.Owner,
            RiskRegisterValidation.Rating(record.Likelihood, record.Impact), RiskRegisterValidation.Rating(record.ResidualLikelihood, record.ResidualImpact),
            record.ReviewDate, record.TargetDate, record.AcceptanceExpiresOn, RiskRegisterValidation.Flags(record, today), record.EndpointIds.Length,
            record.AlertIds.Length, version, updatedUtc);

    /// <summary>Links an administrator adds must exist now: an enrolled endpoint, a tracked alert. Existing links may outlive them.</summary>
    private static async Task<List<RiskValidationError>> CheckLinksAsync(SqliteConnection connection, SqliteTransaction transaction,
        StoredRiskRecord record, StoredRiskRecord? current, CancellationToken cancellationToken)
    {
        var errors = new List<RiskValidationError>();
        foreach (var endpointId in record.EndpointIds.Except(current?.EndpointIds ?? []))
        {
            if (await ScalarAsync(connection, transaction, "SELECT COUNT(*) FROM EndpointEnrollments WHERE EndpointId = $id AND RemovedUtcTicks IS NULL;",
                    endpointId, cancellationToken) == 0)
            {
                errors.Add(new RiskValidationError("endpointIds", "unknown"));
                break;
            }
        }

        foreach (var alertId in record.AlertIds.Except(current?.AlertIds ?? []))
        {
            if (await ScalarAsync(connection, transaction, "SELECT COUNT(*) FROM TrackedAlerts WHERE AlertId = $id;", alertId, cancellationToken) == 0)
            {
                errors.Add(new RiskValidationError("alertIds", "unknown"));
                break;
            }
        }

        return errors;
    }

    private static async Task SaveAsync(SqliteConnection connection, SqliteTransaction transaction, Guid riskId, long version, StoredRiskRecord record,
        DateTimeOffset now, string actor, bool reviewed, CancellationToken cancellationToken)
    {
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE RiskRegister SET Version = Version + 1, RecordJson = $record, UpdatedUtcTicks = $now, UpdatedBy = $actor,
                LastReviewedUtcTicks = CASE WHEN $reviewed THEN $now ELSE LastReviewedUtcTicks END,
                LastReviewedBy = CASE WHEN $reviewed THEN $actor ELSE LastReviewedBy END
            WHERE RiskId = $riskId AND Version = $version;
            """;
        update.Parameters.AddWithValue("$riskId", riskId.ToString("D"));
        update.Parameters.AddWithValue("$version", version);
        update.Parameters.AddWithValue("$record", JsonSerializer.Serialize(record, Json));
        update.Parameters.AddWithValue("$now", now.UtcTicks);
        update.Parameters.AddWithValue("$actor", actor);
        update.Parameters.AddWithValue("$reviewed", reviewed);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) throw new InvalidOperationException("The Risk Register record changed during the save.");
    }

    private static async Task RecordHistoryAsync(SqliteConnection connection, SqliteTransaction transaction, Guid riskId, long version,
        DateTimeOffset now, string actor, string action, IReadOnlyList<RiskFieldChange> changes, string? note, CancellationToken cancellationToken)
    {
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO RiskRegisterHistory (RiskId, Version, ChangedUtcTicks, ChangedBy, Action, ChangesJson, Note)
            VALUES ($riskId, $version, $now, $actor, $action, $changes, $note);
            """;
        insert.Parameters.AddWithValue("$riskId", riskId.ToString("D"));
        insert.Parameters.AddWithValue("$version", version);
        insert.Parameters.AddWithValue("$now", now.UtcTicks);
        insert.Parameters.AddWithValue("$actor", actor);
        insert.Parameters.AddWithValue("$action", action);
        insert.Parameters.AddWithValue("$changes", JsonSerializer.Serialize(changes, Json));
        insert.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private sealed record StoredRow(long Number, long Version, StoredRiskRecord Record, DateTimeOffset CreatedUtc, string CreatedBy,
        DateTimeOffset UpdatedUtc, string UpdatedBy, DateTimeOffset? LastReviewedUtc, string? LastReviewedBy);

    private static async Task<StoredRow?> ReadStoredAsync(SqliteConnection connection, SqliteTransaction transaction, Guid riskId,
        CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT Number, Version, RecordJson, CreatedUtcTicks, CreatedBy, UpdatedUtcTicks, UpdatedBy, LastReviewedUtcTicks, LastReviewedBy
            FROM RiskRegister WHERE RiskId = $riskId;
            """;
        query.Parameters.AddWithValue("$riskId", riskId.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new StoredRow(reader.GetInt64(0), reader.GetInt64(1), Read(reader.GetString(2)), Utc(reader.GetInt64(3)), reader.GetString(4),
            Utc(reader.GetInt64(5)), reader.GetString(6), reader.IsDBNull(7) ? null : Utc(reader.GetInt64(7)), reader.IsDBNull(8) ? null : reader.GetString(8));
    }

    private static async Task<RiskRecordDetail?> ReadDetailAsync(SqliteConnection connection, SqliteTransaction transaction, Guid riskId, DateOnly today,
        CancellationToken cancellationToken)
    {
        if (await ReadStoredAsync(connection, transaction, riskId, cancellationToken) is not { } stored) return null;
        var record = stored.Record;
        var endpoints = new List<RiskLinkedEndpoint>();
        foreach (var endpointId in record.EndpointIds)
        {
            var enrolled = await ScalarAsync(connection, transaction,
                "SELECT COUNT(*) FROM EndpointEnrollments WHERE EndpointId = $id AND RemovedUtcTicks IS NULL;", endpointId, cancellationToken) > 0;
            endpoints.Add(new RiskLinkedEndpoint(endpointId,
                enrolled ? await SecurityEventStore.ReadEndpointNameAsync(connection, transaction, endpointId, cancellationToken) : null, enrolled));
        }

        var alerts = new List<RiskLinkedAlert>();
        foreach (var alertId in record.AlertIds)
        {
            await using var query = connection.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = "SELECT EndpointId, EndpointName, RuleId, Title, Severity, Status FROM TrackedAlerts WHERE AlertId = $id;";
            query.Parameters.AddWithValue("$id", alertId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            alerts.Add(await reader.ReadAsync(cancellationToken)
                ? new RiskLinkedAlert(alertId, true, Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5))
                : new RiskLinkedAlert(alertId, false, null, null, null, null, null, null));
        }

        var history = new List<RiskRecordHistoryEntry>();
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT Version, ChangedUtcTicks, ChangedBy, Action, ChangesJson, Note FROM RiskRegisterHistory
                WHERE RiskId = $riskId ORDER BY Version DESC;
                """;
            query.Parameters.AddWithValue("$riskId", riskId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                history.Add(new RiskRecordHistoryEntry(reader.GetInt64(0), Utc(reader.GetInt64(1)), reader.GetString(2), reader.GetString(3),
                    JsonSerializer.Deserialize<RiskFieldChange[]>(reader.GetString(4), Json) ?? [], reader.IsDBNull(5) ? null : reader.GetString(5)));
        }

        return new RiskRecordDetail(riskId, Reference(stored.Number), record.Title, record.Description, record.Owner,
            RiskRegisterValidation.Rating(record.Likelihood, record.Impact), record.Controls,
            RiskRegisterValidation.Rating(record.ResidualLikelihood, record.ResidualImpact), record.Treatment, record.AcceptanceRationale,
            record.AcceptanceExpiresOn, record.TargetDate, record.ReviewDate, record.Status, RiskRegisterValidation.Flags(record, today), endpoints, alerts,
            record.Tickets, stored.CreatedUtc, stored.CreatedBy, stored.UpdatedUtc, stored.UpdatedBy, stored.LastReviewedUtc, stored.LastReviewedBy,
            stored.Version, history, RiskRegisterValidation.Iso(today));
    }

    private static async Task<long> ScalarAsync(SqliteConnection connection, SqliteTransaction transaction, string sql, Guid? id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        if (id is { } value) command.Parameters.AddWithValue("$id", value.ToString("D"));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 30,
            ForeignKeys = true
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
