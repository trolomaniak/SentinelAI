using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Enrollment;

namespace SentinelAI.Core.Persistence;

public sealed record CoreIdentity(Guid CoreInstallationId, Guid OrganizationId);

public sealed record EndpointEnrollment(
    Guid InstallationId,
    Guid EndpointId,
    Guid CoreInstallationId,
    Guid OrganizationId);

public enum EnrollmentOutcome
{
    Enrolled,
    InvalidCredential,
    AlreadyEnrolled
}

public sealed record EnrollmentAttempt(EnrollmentOutcome Outcome, EnrollmentResponse? Response)
{
    public override string ToString() => nameof(EnrollmentAttempt);
}

public sealed class EnrollmentStore(AdminStore admins)
{
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(10);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var schema = connection.CreateCommand();
        schema.Transaction = transaction;
        schema.CommandText = """
            CREATE TABLE IF NOT EXISTS CoreIdentity (
                Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1),
                CoreInstallationId TEXT NOT NULL,
                OrganizationId TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS EnrollmentTokens (
                TokenHash BLOB PRIMARY KEY,
                ExpiresUtcTicks INTEGER NOT NULL,
                ConsumedUtcTicks INTEGER,
                CoreInstallationId TEXT NOT NULL,
                OrganizationId TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS EndpointEnrollments (
                InstallationId TEXT PRIMARY KEY,
                EndpointId TEXT NOT NULL UNIQUE,
                CoreInstallationId TEXT NOT NULL,
                OrganizationId TEXT NOT NULL,
                CredentialHash BLOB NOT NULL
            );
            INSERT OR IGNORE INTO CoreIdentity (Singleton, CoreInstallationId, OrganizationId)
            VALUES (1, $coreInstallationId, $organizationId);
            """;
        schema.Parameters.AddWithValue("$coreInstallationId", Guid.NewGuid().ToString("D"));
        schema.Parameters.AddWithValue("$organizationId", Guid.NewGuid().ToString("D"));
        await schema.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
    }

    public async Task<CoreIdentity> GetCoreIdentityAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT CoreInstallationId, OrganizationId FROM CoreIdentity WHERE Singleton = 1;";
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("Core installation identity has not been initialized.");
        }

        return new CoreIdentity(Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)));
    }

    public async Task<EnrollmentTokenResponse> IssueTokenAsync(
        TimeSpan? lifetime = null,
        CancellationToken cancellationToken = default)
    {
        var duration = lifetime ?? TokenLifetime;
        if (duration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        var identity = await GetCoreIdentityAsync(cancellationToken);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var expires = DateTimeOffset.UtcNow.Add(duration);
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT INTO EnrollmentTokens
                (TokenHash, ExpiresUtcTicks, CoreInstallationId, OrganizationId)
            VALUES ($hash, $expires, $coreInstallationId, $organizationId);
            """;
        insert.Parameters.AddWithValue("$hash", SHA256.HashData(Convert.FromHexString(token)));
        insert.Parameters.AddWithValue("$expires", expires.UtcDateTime.Ticks);
        insert.Parameters.AddWithValue("$coreInstallationId", identity.CoreInstallationId.ToString("D"));
        insert.Parameters.AddWithValue("$organizationId", identity.OrganizationId.ToString("D"));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        return new EnrollmentTokenResponse(token, expires, identity.CoreInstallationId, identity.OrganizationId);
    }

    public async Task<EnrollmentAttempt> TryEnrollAsync(
        EnrollmentRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.InstallationId == Guid.Empty || !TryDecodeSecret(request.EnrollmentToken, out var tokenBytes))
        {
            return new EnrollmentAttempt(EnrollmentOutcome.InvalidCredential, null);
        }

        var tokenHash = SHA256.HashData(tokenBytes);
        var nowTicks = DateTimeOffset.UtcNow.UtcDateTime.Ticks;
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);

        long expiresTicks;
        string coreInstallationId;
        string organizationId;
        await using (var tokenQuery = connection.CreateCommand())
        {
            tokenQuery.Transaction = transaction;
            tokenQuery.CommandText = """
                SELECT ExpiresUtcTicks, CoreInstallationId, OrganizationId
                FROM EnrollmentTokens
                WHERE TokenHash = $hash AND ConsumedUtcTicks IS NULL;
                """;
            tokenQuery.Parameters.AddWithValue("$hash", tokenHash);
            await using var reader = await tokenQuery.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return new EnrollmentAttempt(EnrollmentOutcome.InvalidCredential, null);
            }

            expiresTicks = reader.GetInt64(0);
            coreInstallationId = reader.GetString(1);
            organizationId = reader.GetString(2);
        }

        if (expiresTicks <= nowTicks)
        {
            return new EnrollmentAttempt(EnrollmentOutcome.InvalidCredential, null);
        }

        var installationId = request.InstallationId.ToString("D");
        await using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText = "SELECT 1 FROM EndpointEnrollments WHERE InstallationId = $installationId;";
            existing.Parameters.AddWithValue("$installationId", installationId);
            if (await existing.ExecuteScalarAsync(cancellationToken) is not null)
            {
                return new EnrollmentAttempt(EnrollmentOutcome.AlreadyEnrolled, null);
            }
        }

        var endpointId = Guid.NewGuid();
        var credential = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await using (var enrollmentInsert = connection.CreateCommand())
        {
            enrollmentInsert.Transaction = transaction;
            enrollmentInsert.CommandText = """
                INSERT INTO EndpointEnrollments
                    (InstallationId, EndpointId, CoreInstallationId, OrganizationId, CredentialHash)
                VALUES ($installationId, $endpointId, $coreInstallationId, $organizationId, $credentialHash);
                """;
            enrollmentInsert.Parameters.AddWithValue("$installationId", installationId);
            enrollmentInsert.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
            enrollmentInsert.Parameters.AddWithValue("$coreInstallationId", coreInstallationId);
            enrollmentInsert.Parameters.AddWithValue("$organizationId", organizationId);
            enrollmentInsert.Parameters.AddWithValue("$credentialHash", SHA256.HashData(Convert.FromHexString(credential)));
            await enrollmentInsert.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var deviceUpdate = connection.CreateCommand())
        {
            deviceUpdate.Transaction = transaction;
            deviceUpdate.CommandText = """
                UPDATE Devices SET EnrollmentStatus = $enrolled
                WHERE InstallationId = $installationId;
                """;
            deviceUpdate.Parameters.AddWithValue("$installationId", installationId);
            deviceUpdate.Parameters.AddWithValue("$enrolled", DeviceEnrollmentStatus.Enrolled);
            await deviceUpdate.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var consume = connection.CreateCommand())
        {
            consume.Transaction = transaction;
            consume.CommandText = """
                UPDATE EnrollmentTokens SET ConsumedUtcTicks = $now
                WHERE TokenHash = $hash AND ConsumedUtcTicks IS NULL;
                """;
            consume.Parameters.AddWithValue("$now", nowTicks);
            consume.Parameters.AddWithValue("$hash", tokenHash);
            if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("The enrollment credential could not be consumed.");
            }
        }

        transaction.Commit();
        return new EnrollmentAttempt(EnrollmentOutcome.Enrolled,
            new EnrollmentResponse(request.InstallationId, endpointId,
                Guid.Parse(coreInstallationId), Guid.Parse(organizationId), credential));
    }

    public async Task<EndpointEnrollment?> FindByInstallationIdAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT EndpointId, CoreInstallationId, OrganizationId
            FROM EndpointEnrollments WHERE InstallationId = $installationId;
            """;
        query.Parameters.AddWithValue("$installationId", installationId.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new EndpointEnrollment(installationId, Guid.Parse(reader.GetString(0)),
            Guid.Parse(reader.GetString(1)), Guid.Parse(reader.GetString(2)));
    }

    public async Task<bool> AuthenticateAsync(
        Guid installationId,
        Guid endpointId,
        string credential,
        CancellationToken cancellationToken = default)
    {
        if (installationId == Guid.Empty || endpointId == Guid.Empty ||
            !TryDecodeSecret(credential, out var credentialBytes))
        {
            return false;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT CredentialHash FROM EndpointEnrollments
            WHERE InstallationId = $installationId AND EndpointId = $endpointId;
            """;
        query.Parameters.AddWithValue("$installationId", installationId.ToString("D"));
        query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        var storedHash = await query.ExecuteScalarAsync(cancellationToken) as byte[];
        return storedHash is { Length: 32 } && CryptographicOperations.FixedTimeEquals(
            storedHash, SHA256.HashData(credentialBytes));
    }

    public async Task<bool> AuthenticateEndpointAsync(
        Guid endpointId,
        string credential,
        CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty || !TryDecodeSecret(credential, out var credentialBytes))
        {
            return false;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT CredentialHash FROM EndpointEnrollments
            WHERE EndpointId = $endpointId;
            """;
        query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        var storedHash = await query.ExecuteScalarAsync(cancellationToken) as byte[];
        return storedHash is { Length: 32 } && CryptographicOperations.FixedTimeEquals(
            storedHash, SHA256.HashData(credentialBytes));
    }

    private static bool TryDecodeSecret(string? text, out byte[] bytes)
    {
        bytes = [];
        if (text is not { Length: 64 })
        {
            return false;
        }

        try
        {
            bytes = Convert.FromHexString(text);
            return bytes.Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
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
