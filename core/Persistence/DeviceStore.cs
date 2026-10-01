using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Heartbeat;

namespace SentinelAI.Core.Persistence;

public sealed record DeviceRecord(
    Guid InstallationId,
    DateTimeOffset LastSeenUtc,
    string HealthStatus,
    string EnrollmentStatus);

public static class DeviceEnrollmentStatus
{
    // Legacy loopback heartbeats do not prove secure enrollment.
    public const string Unverified = "unverified";
    public const string Enrolled = "enrolled";
}

public sealed class DeviceStore(AdminStore admins)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS Devices (
                InstallationId TEXT NOT NULL PRIMARY KEY,
                LastSeenUtcTicks INTEGER NOT NULL,
                HealthStatus TEXT NOT NULL,
                EnrollmentStatus TEXT NOT NULL
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<DeviceRecord?> RecordHeartbeatAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        if (installationId == Guid.Empty)
        {
            throw new ArgumentException("An installation ID is required.", nameof(installationId));
        }

        var utcTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var upsert = connection.CreateCommand();
        upsert.CommandText = """
            INSERT INTO Devices (InstallationId, LastSeenUtcTicks, HealthStatus, EnrollmentStatus)
            SELECT $installationId, $lastSeenUtcTicks, $healthStatus, $enrollmentStatus
            WHERE NOT EXISTS (
                SELECT 1 FROM EndpointEnrollments WHERE InstallationId = $installationId
            )
            ON CONFLICT (InstallationId) DO UPDATE SET
                LastSeenUtcTicks = MAX(LastSeenUtcTicks, excluded.LastSeenUtcTicks),
                HealthStatus = excluded.HealthStatus
            WHERE Devices.EnrollmentStatus = $enrollmentStatus
              AND NOT EXISTS (
                  SELECT 1 FROM EndpointEnrollments WHERE InstallationId = $installationId
              )
            RETURNING LastSeenUtcTicks, HealthStatus, EnrollmentStatus;
            """;
        upsert.Parameters.AddWithValue("$installationId", installationId.ToString("D"));
        upsert.Parameters.AddWithValue("$lastSeenUtcTicks", utcTicks);
        upsert.Parameters.AddWithValue("$healthStatus", DeviceHealthStatus.Reporting);
        upsert.Parameters.AddWithValue("$enrollmentStatus", DeviceEnrollmentStatus.Unverified);

        await using var reader = await upsert.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new DeviceRecord(
            installationId,
            new DateTimeOffset(reader.GetInt64(0), TimeSpan.Zero),
            reader.GetString(1),
            reader.GetString(2));
    }

    public async Task<DeviceRecord> RecordEnrolledHeartbeatAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        if (installationId == Guid.Empty)
        {
            throw new ArgumentException("An installation ID is required.", nameof(installationId));
        }

        var utcTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var upsert = connection.CreateCommand();
        upsert.CommandText = """
            INSERT INTO Devices (InstallationId, LastSeenUtcTicks, HealthStatus, EnrollmentStatus)
            VALUES ($installationId, $lastSeenUtcTicks, $healthStatus, $enrollmentStatus)
            ON CONFLICT (InstallationId) DO UPDATE SET
                LastSeenUtcTicks = MAX(LastSeenUtcTicks, excluded.LastSeenUtcTicks),
                HealthStatus = excluded.HealthStatus,
                EnrollmentStatus = excluded.EnrollmentStatus
            RETURNING LastSeenUtcTicks, HealthStatus, EnrollmentStatus;
            """;
        upsert.Parameters.AddWithValue("$installationId", installationId.ToString("D"));
        upsert.Parameters.AddWithValue("$lastSeenUtcTicks", utcTicks);
        upsert.Parameters.AddWithValue("$healthStatus", DeviceHealthStatus.Reporting);
        upsert.Parameters.AddWithValue("$enrollmentStatus", DeviceEnrollmentStatus.Enrolled);
        await using var reader = await upsert.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("The enrolled heartbeat was not persisted.");
        }

        return new DeviceRecord(installationId,
            new DateTimeOffset(reader.GetInt64(0), TimeSpan.Zero),
            reader.GetString(1), reader.GetString(2));
    }

    public async Task<DeviceRecord?> FindByInstallationIdAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        if (installationId == Guid.Empty)
        {
            return null;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT LastSeenUtcTicks, HealthStatus, EnrollmentStatus
            FROM Devices
            WHERE InstallationId = $installationId
            LIMIT 1;
            """;
        query.Parameters.AddWithValue("$installationId", installationId.ToString("D"));

        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new DeviceRecord(
            installationId,
            new DateTimeOffset(reader.GetInt64(0), TimeSpan.Zero),
            reader.GetString(1),
            reader.GetString(2));
    }

    public async Task<long> CountAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM Devices;";
        return (long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L);
    }

    private SqliteConnection CreateConnection()
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 30
        };
        return new SqliteConnection(connectionString.ToString());
    }
}
