using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.RiskHistory;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core.History;

internal sealed class RiskHistoryStore
{
    private const long BucketTicks = RiskHistoryContract.CaptureIntervalHours * TimeSpan.TicksPerHour;
    private static readonly long RetentionTicks = TimeSpan.FromDays(RiskHistoryContract.RetentionDays).Ticks;
    private readonly AdminStore _admins;
    private readonly RiskReadStore _risks;
    private readonly TimeProvider _time;
    private readonly int _maximumEndpointPoints;

    public RiskHistoryStore(AdminStore admins, RiskReadStore risks, TimeProvider time)
        : this(admins, risks, time, RiskHistoryContract.MaximumEndpointPoints) { }

    internal RiskHistoryStore(AdminStore admins, RiskReadStore risks, TimeProvider time, int maximumEndpointPoints)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumEndpointPoints, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumEndpointPoints, RiskHistoryContract.MaximumEndpointPoints);
        _admins = admins;
        _risks = risks;
        _time = time;
        _maximumEndpointPoints = maximumEndpointPoints;
    }

    internal async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS RiskHistoryPolicies (
                Fingerprint TEXT NOT NULL PRIMARY KEY, Version TEXT NOT NULL, CanonicalJson TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS RiskHistoryCaptures (
                Bucket INTEGER PRIMARY KEY, CapturedUtcTicks INTEGER NOT NULL UNIQUE,
                Score INTEGER NOT NULL CHECK(Score BETWEEN 0 AND 100), RawScore TEXT NOT NULL,
                PolicyFingerprint TEXT NOT NULL REFERENCES RiskHistoryPolicies(Fingerprint),
                ComparedWithUtcTicks INTEGER, CausesJson TEXT NOT NULL, PrincipalRuleIdsJson TEXT NOT NULL,
                EndpointCount INTEGER NOT NULL CHECK(EndpointCount >= 0),
                GoverningEndpointId TEXT, FleetFingerprint TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS RiskHistoryEndpointPoints (
                Bucket INTEGER NOT NULL REFERENCES RiskHistoryCaptures(Bucket) ON DELETE CASCADE,
                EndpointId TEXT NOT NULL,
                Score INTEGER NOT NULL CHECK(Score BETWEEN 0 AND 100), RawScore TEXT NOT NULL,
                ComparedWithUtcTicks INTEGER, CausesJson TEXT NOT NULL, PrincipalRuleIdsJson TEXT NOT NULL,
                PRIMARY KEY (Bucket, EndpointId)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS IX_RiskHistoryEndpointPoints_EndpointId_Bucket
                ON RiskHistoryEndpointPoints(EndpointId, Bucket);
            CREATE TABLE IF NOT EXISTS RiskHistoryBaselines (
                EndpointId TEXT NOT NULL PRIMARY KEY, FactorsJson TEXT NOT NULL) WITHOUT ROWID;
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
    }

    internal async Task<bool> CaptureAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var watermark = connection.CreateCommand();
        watermark.CommandText = "SELECT MAX(Bucket) FROM RiskHistoryCaptures;";
        var lastBucket = await watermark.ExecuteScalarAsync(cancellationToken);
        if (lastBucket is long recorded && _time.GetUtcNow().UtcTicks / BucketTicks <= recorded) return false;

        var fleet = await _risks.EvaluateFleetAsync(cancellationToken);
        var now = fleet.EvaluatedUtc;
        var bucket = now.UtcTicks / BucketTicks;
        if (fleet.Endpoints.Length > _maximumEndpointPoints)
            throw new InvalidDataException("The fleet exceeds the history endpoint limit.");
        var policy = RiskHistoryEvidence.DescribePolicy(fleet.Policy);
        var governing = fleet.Endpoints.OrderByDescending(point => point.RawScore).ThenBy(point => point.EndpointId).FirstOrDefault();
        var fleetFingerprint = FingerprintFleet(fleet.Endpoints.Select(point => point.EndpointId));
        var currentFactors = new Dictionary<Guid, RiskHistoryFactors>(fleet.Endpoints.Length);
        foreach (var score in fleet.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            currentFactors.Add(score.EndpointId, RiskHistoryEvidence.Build(score));
        }

        // The watermark check under the write lock is authoritative across workers and process restarts.
        using var transaction = connection.BeginTransaction(deferred: false);
        var previous = await ReadLatestAsync(connection, transaction, cancellationToken);
        if (previous is not null && (bucket <= previous.Bucket || now.UtcTicks <= previous.CapturedUtcTicks)) return false;
        var baselines = await ReadBaselinesAsync(connection, transaction, previous?.EndpointCount ?? 0, cancellationToken);
        var policyChanged = previous is not null && previous.PolicyFingerprint != policy.Fingerprint;
        var governingFactors = governing is null ? null : currentFactors[governing.EndpointId];
        IReadOnlyList<string> governingCauses = governing is null ? [] : RiskHistoryEvidence.Compare(
            baselines.GetValueOrDefault(governing.EndpointId), governingFactors!, policyChanged);
        var organizationCauses = OrganizationCauses(previous, governing?.EndpointId, fleetFingerprint,
            governing?.RawScore ?? 0m, policyChanged, governingCauses);

        await using (var write = connection.CreateCommand())
        {
            write.Transaction = transaction;
            write.CommandText = """
                INSERT INTO RiskHistoryPolicies(Fingerprint, Version, CanonicalJson) VALUES($policy, $version, $canonical)
                    ON CONFLICT(Fingerprint) DO NOTHING;
                INSERT INTO RiskHistoryCaptures(Bucket, CapturedUtcTicks, Score, RawScore, PolicyFingerprint,
                    ComparedWithUtcTicks, CausesJson, PrincipalRuleIdsJson, EndpointCount, GoverningEndpointId, FleetFingerprint)
                VALUES($bucket, $captured, $score, $raw, $policy, $compared, $causes, $rules, $count, $governing, $fleet);
                DELETE FROM RiskHistoryBaselines;
                """;
            write.Parameters.AddWithValue("$policy", policy.Fingerprint);
            write.Parameters.AddWithValue("$version", policy.Version);
            write.Parameters.AddWithValue("$canonical", policy.Json);
            write.Parameters.AddWithValue("$bucket", bucket);
            write.Parameters.AddWithValue("$captured", now.UtcTicks);
            write.Parameters.AddWithValue("$count", fleet.Organization.EndpointCount);
            write.Parameters.AddWithValue("$governing", (object?)governing?.EndpointId.ToString("D") ?? DBNull.Value);
            write.Parameters.AddWithValue("$fleet", fleetFingerprint);
            AddPointParameters(write);
            SetPointParameters(write, fleet.Organization.Score, governing?.RawScore ?? 0m,
                previous?.CapturedUtcTicks, organizationCauses, governingFactors?.RuleIds ?? []);
            await write.ExecuteNonQueryAsync(cancellationToken);
        }

        await PruneAsync(connection, transaction, now.UtcTicks, cancellationToken);
        await using (var write = connection.CreateCommand())
        {
            write.Transaction = transaction;
            write.CommandText = """
                INSERT INTO RiskHistoryEndpointPoints(Bucket, EndpointId, Score, RawScore,
                    ComparedWithUtcTicks, CausesJson, PrincipalRuleIdsJson)
                VALUES($bucket, $endpoint, $score, $raw, $compared, $causes, $rules);
                INSERT INTO RiskHistoryBaselines(EndpointId, FactorsJson) VALUES($endpoint, $factors);
                """;
            write.Parameters.AddWithValue("$bucket", bucket);
            var endpoint = write.Parameters.Add("$endpoint", SqliteType.Text);
            var baseline = write.Parameters.Add("$factors", SqliteType.Text);
            AddPointParameters(write);
            write.Prepare();
            foreach (var score in fleet.Endpoints)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var prior = baselines.GetValueOrDefault(score.EndpointId);
                var factors = currentFactors[score.EndpointId];
                var causes = score.EndpointId == governing?.EndpointId ? governingCauses : RiskHistoryEvidence.Compare(prior, factors, policyChanged);
                endpoint.Value = score.EndpointId.ToString("D");
                baseline.Value = JsonSerializer.Serialize(factors with { RuleIds = [] });
                SetPointParameters(write, score.Score, score.RawScore, prior is null ? null : previous!.CapturedUtcTicks, causes, factors.RuleIds);
                await write.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
        return true;
    }

    internal async Task<RiskHistoryView> ReadAsync(Guid? endpointId, int periodHours, CancellationToken cancellationToken)
    {
        if (endpointId == Guid.Empty || !RiskHistoryContract.PeriodHours.Contains(periodHours)) throw new ArgumentException("Invalid history scope.");
        var now = _time.GetUtcNow().ToUniversalTime();
        var start = new DateTimeOffset(Math.Max(0, now.UtcTicks - periodHours * TimeSpan.TicksPerHour), TimeSpan.Zero);
        await using var connection = CreateConnection(SqliteOpenMode.ReadOnly);
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var points = await ReadPointsAsync(connection, transaction, endpointId, start.UtcTicks, now.UtcTicks + 1, cancellationToken);
        transaction.Commit();
        return new RiskHistoryView(endpointId, periodHours, now, start, points);
    }

    internal static Task<IReadOnlyList<RiskHistoryPoint>> ReadReportPointsAsync(SqliteConnection connection,
        SqliteTransaction transaction, DateTimeOffset startUtc, DateTimeOffset endExclusiveUtc, DateTimeOffset generatedUtc,
        CancellationToken cancellationToken) => ReadPointsAsync(connection, transaction, null,
            Math.Max(startUtc.UtcTicks, generatedUtc.UtcTicks - RetentionTicks),
            Math.Min(endExclusiveUtc.UtcTicks, generatedUtc.UtcTicks + 1), cancellationToken);

    private static async Task<IReadOnlyList<RiskHistoryPoint>> ReadPointsAsync(SqliteConnection connection,
        SqliteTransaction transaction, Guid? endpointId, long startTicks, long endExclusiveTicks, CancellationToken cancellationToken)
    {
        if (startTicks >= endExclusiveTicks) return [];
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = endpointId is null ? """
            SELECT c.CapturedUtcTicks, c.Score, c.RawScore, p.Version, c.PolicyFingerprint,
                c.ComparedWithUtcTicks, c.CausesJson, c.PrincipalRuleIdsJson, c.EndpointCount, c.GoverningEndpointId
            FROM RiskHistoryCaptures AS c JOIN RiskHistoryPolicies AS p ON c.PolicyFingerprint = p.Fingerprint
            WHERE c.CapturedUtcTicks >= $start AND c.CapturedUtcTicks < $end
            ORDER BY c.CapturedUtcTicks LIMIT $maximum;
            """ : """
            SELECT c.CapturedUtcTicks, e.Score, e.RawScore, p.Version, c.PolicyFingerprint,
                e.ComparedWithUtcTicks, e.CausesJson, e.PrincipalRuleIdsJson, NULL, NULL
            FROM RiskHistoryEndpointPoints AS e JOIN RiskHistoryCaptures AS c ON e.Bucket = c.Bucket
                JOIN RiskHistoryPolicies AS p ON c.PolicyFingerprint = p.Fingerprint
            WHERE e.EndpointId = $endpoint AND e.Bucket >= $firstBucket AND e.Bucket <= $lastBucket
                AND c.CapturedUtcTicks >= $start AND c.CapturedUtcTicks < $end
            ORDER BY c.CapturedUtcTicks LIMIT $maximum;
            """;
        query.Parameters.AddWithValue("$start", startTicks);
        query.Parameters.AddWithValue("$end", endExclusiveTicks);
        query.Parameters.AddWithValue("$maximum", RiskHistoryContract.MaximumPoints + 1);
        if (endpointId is Guid endpoint)
        {
            query.Parameters.AddWithValue("$endpoint", endpoint.ToString("D"));
            query.Parameters.AddWithValue("$firstBucket", startTicks / BucketTicks);
            query.Parameters.AddWithValue("$lastBucket", (endExclusiveTicks - 1) / BucketTicks);
        }
        var points = new List<RiskHistoryPoint>();
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var point = ReadPoint(reader);
            if (points.Count == RiskHistoryContract.MaximumPoints || (points.Count > 0 &&
                point.CapturedUtc.UtcTicks / BucketTicks <= points[^1].CapturedUtc.UtcTicks / BucketTicks))
                throw InvalidHistory();
            points.Add(point);
        }
        return points.AsReadOnly();
    }

    private static RiskHistoryPoint ReadPoint(SqliteDataReader reader)
    {
        var captured = reader.GetInt64(0);
        var score = reader.GetInt32(1);
        var raw = ReadRawScore(reader, 2);
        var version = reader.GetString(3);
        var fingerprint = reader.GetString(4);
        var compared = reader.IsDBNull(5) ? (long?)null : reader.GetInt64(5);
        var causes = ReadLabels(reader, 6, RiskHistoryContract.CauseCodes.Count,
            label => RiskHistoryContract.CauseCodes.Contains(label));
        var rules = ReadLabels(reader, 7, RiskHistoryContract.MaximumRuleIds, label =>
            label is { Length: > 0 and <= RiskHistoryContract.MaximumRuleIdLength } &&
            label.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-'));
        var endpointCount = reader.IsDBNull(8) ? (int?)null : reader.GetInt32(8);
        var governing = reader.IsDBNull(9) ? (Guid?)null : ReadEndpointId(reader, 9);
        if (score != decimal.Round(Math.Min(100m, raw), 0, MidpointRounding.AwayFromZero) ||
            string.IsNullOrWhiteSpace(version) || version.Length > RiskHistoryContract.MaximumPolicyVersionLength ||
            fingerprint.Length != 64 || fingerprint.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            compared >= captured || (compared is null ? causes.Count != 1 || causes[0] != "firstCapture" : causes.Contains("firstCapture")) ||
            endpointCount is < 0 or > RiskHistoryContract.MaximumEndpointPoints || ((endpointCount > 0) != governing.HasValue) ||
            (endpointCount == 0 && (raw != 0m || rules.Count > 0)))
            throw InvalidHistory();
        return new RiskHistoryPoint(new DateTimeOffset(captured, TimeSpan.Zero), score, raw, version, fingerprint,
            compared is long ticks ? new DateTimeOffset(ticks, TimeSpan.Zero) : null, causes, rules, endpointCount, governing);
    }

    private static IReadOnlyList<string> ReadLabels(SqliteDataReader reader, int ordinal, int limit, Func<string, bool> isAllowed)
    {
        var json = reader.GetString(ordinal);
        if (json.Length > 512) throw InvalidHistory();
        var labels = JsonSerializer.Deserialize<string[]>(json);
        if (labels is null || labels.Length > limit || labels.Any(label => label is null || !isAllowed(label)) ||
            labels.Distinct(StringComparer.Ordinal).Count() != labels.Length)
            throw InvalidHistory();
        return Array.AsReadOnly(labels);
    }

    private static decimal ReadRawScore(SqliteDataReader reader, int ordinal) =>
        decimal.TryParse(reader.GetString(ordinal), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var raw) && raw >= 0m
            ? raw : throw InvalidHistory();

    private static Guid ReadEndpointId(SqliteDataReader reader, int ordinal) =>
        Guid.TryParseExact(reader.GetString(ordinal), "D", out var id) && id != Guid.Empty ? id : throw InvalidHistory();

    private static async Task<PreviousCapture?> ReadLatestAsync(SqliteConnection connection, SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT Bucket, CapturedUtcTicks, RawScore, PolicyFingerprint, EndpointCount, GoverningEndpointId, FleetFingerprint
            FROM RiskHistoryCaptures ORDER BY Bucket DESC LIMIT 1;
            """;
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        return !await reader.ReadAsync(cancellationToken) ? null : new PreviousCapture(reader.GetInt64(0), reader.GetInt64(1),
            ReadRawScore(reader, 2), reader.GetString(3), reader.GetInt32(4),
            reader.IsDBNull(5) ? null : ReadEndpointId(reader, 5), reader.GetString(6));
    }

    private static async Task<Dictionary<Guid, RiskHistoryFactors>> ReadBaselinesAsync(SqliteConnection connection,
        SqliteTransaction transaction, int expectedCount, CancellationToken cancellationToken)
    {
        if (expectedCount is < 0 or > RiskHistoryContract.MaximumEndpointPoints) throw InvalidHistory();
        var baselines = new Dictionary<Guid, RiskHistoryFactors>(expectedCount);
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = "SELECT EndpointId, FactorsJson FROM RiskHistoryBaselines;";
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (baselines.Count == expectedCount) throw InvalidHistory();
            var raw = reader.GetString(1);
            if (raw.Length > 2048) throw InvalidHistory();
            var factors = JsonSerializer.Deserialize<RiskHistoryFactors>(raw) ?? throw InvalidHistory();
            baselines.Add(ReadEndpointId(reader, 0), factors);
        }
        if (baselines.Count != expectedCount) throw InvalidHistory();
        return baselines;
    }

    private async Task PruneAsync(SqliteConnection connection, SqliteTransaction transaction, long nowTicks,
        CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        // The newest prefix under the row budget is retained. Cascades remove each expired capture as a whole.
        delete.CommandText = """
            DELETE FROM RiskHistoryCaptures
            WHERE Bucket IN (
                SELECT Bucket FROM (
                    SELECT Bucket, CapturedUtcTicks, SUM(EndpointCount) OVER (ORDER BY Bucket DESC ROWS UNBOUNDED PRECEDING) AS RetainedPoints
                    FROM RiskHistoryCaptures)
                WHERE CapturedUtcTicks < $cutoff OR RetainedPoints > $maximum);
            DELETE FROM RiskHistoryPolicies WHERE NOT EXISTS (
                SELECT 1 FROM RiskHistoryCaptures WHERE PolicyFingerprint = RiskHistoryPolicies.Fingerprint);
            """;
        delete.Parameters.AddWithValue("$cutoff", nowTicks - RetentionTicks);
        delete.Parameters.AddWithValue("$maximum", _maximumEndpointPoints);
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static IReadOnlyList<string> OrganizationCauses(PreviousCapture? previous, Guid? governingEndpoint,
        string fleetFingerprint, decimal rawScore, bool policyChanged, IReadOnlyList<string> endpointCauses)
    {
        if (previous is null) return ["firstCapture"];
        var causes = new HashSet<string>(StringComparer.Ordinal);
        if (policyChanged) causes.Add("policyChanged");
        if (fleetFingerprint != previous.FleetFingerprint) causes.Add("fleetChanged");
        if (governingEndpoint != previous.GoverningEndpointId) causes.Add("governingEndpointChanged");
        else causes.UnionWith(endpointCauses.Where(cause => cause is not ("firstCapture" or "unclassified")));
        if (causes.Count == 0 && rawScore != previous.RawScore) causes.Add("unclassified");
        return RiskHistoryContract.CauseCodes.Where(causes.Contains).ToArray();
    }

    private static string FingerprintFleet(IEnumerable<Guid> endpoints)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> id = stackalloc byte[16];
        foreach (var endpoint in endpoints.Order())
        {
            endpoint.TryWriteBytes(id);
            hash.AppendData(id);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AddPointParameters(SqliteCommand command)
    {
        command.Parameters.Add("$score", SqliteType.Integer);
        command.Parameters.Add("$raw", SqliteType.Text);
        command.Parameters.Add("$compared", SqliteType.Integer);
        command.Parameters.Add("$causes", SqliteType.Text);
        command.Parameters.Add("$rules", SqliteType.Text);
    }

    private static void SetPointParameters(SqliteCommand command, int score, decimal raw, long? compared,
        IReadOnlyList<string> causes, IReadOnlyList<string> rules)
    {
        command.Parameters["$score"].Value = score;
        command.Parameters["$raw"].Value = raw.ToString(CultureInfo.InvariantCulture);
        command.Parameters["$compared"].Value = (object?)compared ?? DBNull.Value;
        command.Parameters["$causes"].Value = JsonSerializer.Serialize(causes);
        command.Parameters["$rules"].Value = JsonSerializer.Serialize(rules);
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode = SqliteOpenMode.ReadWrite) => new(new SqliteConnectionStringBuilder
    {
        DataSource = _admins.DatabasePath, Mode = mode, DefaultTimeout = 5, ForeignKeys = true
    }.ToString());

    private static InvalidDataException InvalidHistory() => new("Stored risk history is invalid.");

    private sealed record PreviousCapture(long Bucket, long CapturedUtcTicks, decimal RawScore, string PolicyFingerprint,
        int EndpointCount, Guid? GoverningEndpointId, string FleetFingerprint);
}
