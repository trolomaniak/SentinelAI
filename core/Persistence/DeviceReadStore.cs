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
        await using var query = connection.CreateCommand();
        query.CommandText = SelectDevices + " WHERE e.EndpointId = $endpointId LIMIT 1;";
        query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? ReadDetail(reader, DateTimeOffset.UtcNow)
            : null;
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
            inventory is null ? null : $"{inventory.OsName} {inventory.OsVersion}",
            HealthState(lastSeen, now),
            lastSeen,
            inventory?.AgentVersion,
            SummarizeSecurityPosture(inventory?.SecurityPosture));
        return new DeviceDetail(
            summary,
            inventory?.CollectedUtc,
            inventory?.OsVersion,
            inventory?.Architecture,
            inventory?.Cpu,
            inventory?.InstalledRamBytes,
            inventory?.Disks ?? [],
            inventory?.SecurityPosture);
    }

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
