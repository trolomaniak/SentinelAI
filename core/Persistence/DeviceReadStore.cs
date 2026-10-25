using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Core.Persistence;

public sealed class DeviceReadStore(AdminStore admins)
{
    private const string SelectDevices = """
        SELECT e.EndpointId, d.LastSeenUtcTicks, i.ReportJson
        FROM EndpointEnrollments AS e
        LEFT JOIN Devices AS d ON d.InstallationId = e.InstallationId
        LEFT JOIN EndpointInventories AS i ON i.EndpointId = e.EndpointId
        WHERE e.RemovedUtcTicks IS NULL
        """;

    public async Task<IReadOnlyList<DeviceListItem>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = SelectDevices + " ORDER BY d.LastSeenUtcTicks DESC, e.EndpointId;";

        var now = DateTimeOffset.UtcNow;
        var devices = new List<DeviceListItem>();
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            devices.Add(ReadDetail(reader, now).Device);
        }

        return devices;
    }

    public async Task<DeviceDetail?> FindAsync(
        Guid endpointId,
        CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty)
        {
            return null;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        // One read snapshot for the device and its telemetry.
        using var transaction = connection.BeginTransaction(deferred: true);
        DeviceDetail? detail;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = SelectDevices + " AND e.EndpointId = $endpointId LIMIT 1;";
            query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            detail = await reader.ReadAsync(cancellationToken) ? ReadDetail(reader, DateTimeOffset.UtcNow) : null;
        }

        if (detail is not null)
        {
            await using var query = connection.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = """
                SELECT ReportJson, ReceivedUtcTicks FROM EndpointSecurityTelemetry WHERE EndpointId = $endpointId;
                """;
            query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken) &&
                EndpointTelemetryStore.Parse(reader.GetString(0), reader.GetInt64(1)) is { } stored)
            {
                detail = detail with { SecurityTelemetry = EndpointTelemetryView.From(stored.Report, stored.ReceivedUtc) };
            }
        }

        transaction.Commit();
        return detail;
    }

    private static DeviceDetail ReadDetail(SqliteDataReader reader, DateTimeOffset now)
    {
        var endpointId = Guid.Parse(reader.GetString(0));
        DateTimeOffset? lastSeen = reader.IsDBNull(1)
            ? null
            : new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero);
        var inventory = reader.IsDBNull(2)
            ? null
            : JsonSerializer.Deserialize<InventoryReport>(reader.GetString(2));
        var summary = new DeviceListItem(
            endpointId,
            inventory?.Hostname ?? $"Endpoint {endpointId.ToString("N")[..8]}",
            inventory is null ? null : JoinOperatingSystemParts(inventory.OsName, inventory.OsDisplayVersion,
                string.Equals(inventory.OsInstallationType, "Client", StringComparison.OrdinalIgnoreCase)
                    ? null : inventory.OsInstallationType, inventory.OsVersion),
            HealthState(lastSeen, now),
            lastSeen,
            inventory?.AgentVersion,
            SummarizeSecurityPosture(inventory?.SecurityPosture),
            inventory?.CollectedUtc);
        return new DeviceDetail(
            summary,
            inventory?.CollectedUtc,
            inventory is null ? null : JoinOperatingSystemParts(inventory.OsDisplayVersion, inventory.OsVersion),
            inventory?.Architecture,
            inventory?.Cpu,
            inventory?.InstalledRamBytes,
            inventory?.Disks ?? [],
            inventory?.SecurityPosture,
            inventory?.OsName);
    }

    private static string JoinOperatingSystemParts(params string?[] parts) =>
        string.Join(" ", parts.Where(part => !string.IsNullOrWhiteSpace(part)));

    private static string HealthState(DateTimeOffset? lastSeen, DateTimeOffset now)
    {
        if (lastSeen is null)
        {
            return "unknown";
        }

        var age = now - lastSeen.Value;
        return age <= TimeSpan.FromMinutes(2)
            ? "healthy"
            : age <= TimeSpan.FromMinutes(5) ? "warning" : "offline";
    }

    private static string SummarizeSecurityPosture(SecurityPostureInventory? posture)
    {
        if (posture is null)
        {
            return "Firewall status unknown";
        }

        var profiles = new[]
        {
            posture.DomainFirewallEnabled,
            posture.PrivateFirewallEnabled,
            posture.PublicFirewallEnabled
        };
        if (profiles.Any(enabled => enabled == false))
        {
            return "Firewall disabled on one or more profiles";
        }

        return profiles.All(enabled => enabled == true)
            ? "Firewall enabled on all profiles"
            : "Firewall status unknown";
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
