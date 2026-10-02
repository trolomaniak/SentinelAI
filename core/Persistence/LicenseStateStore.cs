using Microsoft.Data.Sqlite;
using SentinelAI.Licensing;

namespace SentinelAI.Core.Persistence;

public sealed record LicenseStoredState(
    string? Lease,
    DateTimeOffset? LastSuccessfulValidationUtc,
    DateTimeOffset HighWaterUtc,
    bool LastAttemptSucceeded,
    bool ClockRollbackDetected)
{
    public override string ToString() => nameof(LicenseStoredState);
}

/// <summary>License state shares Core's private, local SQLite storage.</summary>
public sealed class LicenseStateStore(AdminStore admins)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS LicenseState (
                Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1),
                Lease TEXT,
                LastSuccessfulValidationUtcTicks INTEGER,
                HighWaterUtcTicks INTEGER NOT NULL,
                LastAttemptSucceeded INTEGER NOT NULL CHECK (LastAttemptSucceeded IN (0, 1)),
                ClockRollbackDetected INTEGER NOT NULL CHECK (ClockRollbackDetected IN (0, 1))
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<LicenseStoredState?> LoadAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        // Bound the value fetched even if the local row has been manually damaged.
        query.CommandText = """
            SELECT CASE WHEN typeof(Lease) = 'text' AND length(CAST(Lease AS BLOB)) BETWEEN 1 AND $maximum
                        THEN Lease ELSE NULL END,
                   CASE WHEN Lease IS NOT NULL AND
                        (typeof(Lease) != 'text' OR length(CAST(Lease AS BLOB)) NOT BETWEEN 1 AND $maximum)
                        THEN 1 ELSE 0 END,
                   LastSuccessfulValidationUtcTicks, HighWaterUtcTicks,
                   LastAttemptSucceeded, ClockRollbackDetected
            FROM LicenseState WHERE Singleton = 1;
            """;
        query.Parameters.AddWithValue("$maximum", LeaseTokenFormat.MaxTokenLength);
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;

        var lease = reader.IsDBNull(0) ? null : reader.GetString(0);
        var valid = reader.GetInt64(1) == 0;
        DateTimeOffset? validated = null;
        if (!reader.IsDBNull(2))
        {
            valid &= TryReadUtc(reader.GetValue(2), out var value);
            validated = value;
        }
        valid &= TryReadUtc(reader.GetValue(3), out var highWater);
        valid &= TryReadBoolean(reader.GetValue(4), out var succeeded);
        valid &= TryReadBoolean(reader.GetValue(5), out var rollback);
        if (!valid) return new(null, null, highWater, false, true);
        return new(lease, validated, highWater, succeeded, rollback);
    }

    public async Task SaveAsync(LicenseStoredState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Lease is { } lease && (lease.Length == 0 || lease.Length > LeaseTokenFormat.MaxTokenLength))
        {
            throw new ArgumentException("The persisted lease must respect the lease size limit.", nameof(state));
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var save = connection.CreateCommand();
        save.CommandText = """
            INSERT INTO LicenseState
                (Singleton, Lease, LastSuccessfulValidationUtcTicks, HighWaterUtcTicks,
                 LastAttemptSucceeded, ClockRollbackDetected)
            VALUES (1, $lease, $validated, $highWater, $succeeded, $rollback)
            ON CONFLICT(Singleton) DO UPDATE SET
                Lease = excluded.Lease,
                LastSuccessfulValidationUtcTicks = excluded.LastSuccessfulValidationUtcTicks,
                HighWaterUtcTicks = CASE
                    WHEN typeof(LicenseState.HighWaterUtcTicks) = 'integer' AND
                         LicenseState.HighWaterUtcTicks BETWEEN 0 AND $maximumTicks
                    THEN MAX(LicenseState.HighWaterUtcTicks, excluded.HighWaterUtcTicks)
                    ELSE excluded.HighWaterUtcTicks END,
                LastAttemptSucceeded = excluded.LastAttemptSucceeded,
                ClockRollbackDetected = excluded.ClockRollbackDetected;
            """;
        save.Parameters.AddWithValue("$lease", (object?)state.Lease ?? DBNull.Value);
        save.Parameters.AddWithValue("$validated", state.LastSuccessfulValidationUtc is { } validated
            ? validated.UtcDateTime.Ticks : DBNull.Value);
        save.Parameters.AddWithValue("$highWater", state.HighWaterUtc.UtcDateTime.Ticks);
        save.Parameters.AddWithValue("$maximumTicks", DateTime.MaxValue.Ticks);
        save.Parameters.AddWithValue("$succeeded", state.LastAttemptSucceeded ? 1 : 0);
        save.Parameters.AddWithValue("$rollback", state.ClockRollbackDetected ? 1 : 0);
        await save.ExecuteNonQueryAsync(cancellationToken);
    }

    private static bool TryReadUtc(object value, out DateTimeOffset utc)
    {
        utc = DateTimeOffset.MinValue;
        if (value is not long ticks || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
            return false;
        utc = new DateTimeOffset(ticks, TimeSpan.Zero);
        return true;
    }

    private static bool TryReadBoolean(object value, out bool result)
    {
        result = value is long number && number == 1;
        return value is long valid && valid is 0 or 1;
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath,
        Mode = SqliteOpenMode.ReadWrite,
        DefaultTimeout = 30
    }.ToString());
}
