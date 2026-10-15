using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Core;

public sealed record DeviceListItem(
    Guid EndpointId,
    string Name,
    string? OperatingSystem,
    string HealthState,
    DateTimeOffset? LastSeenUtc,
    string? AgentVersion,
    string SecurityPostureSummary,
    DateTimeOffset? InventoryCollectedUtc = null);

public sealed record DeviceDetail(
    DeviceListItem Device,
    DateTimeOffset? InventoryCollectedUtc,
    string? OsVersion,
    string? Architecture,
    CpuInventory? Cpu,
    long? InstalledRamBytes,
    IReadOnlyList<DiskInventory> Disks,
    SecurityPostureInventory? SecurityPosture,
    string? OsName = null,
    EndpointTelemetryView? SecurityTelemetry = null);

/// <summary>
/// The newest accepted endpoint telemetry for administrators. Installed applications are summarized; their list is
/// kept for vulnerability management and is not part of the device view.
/// </summary>
public sealed record EndpointTelemetryView(
    int SchemaVersion,
    DateTimeOffset CollectedUtc,
    DateTimeOffset ReceivedUtc,
    BitLockerTelemetry BitLocker,
    AntivirusTelemetry Antivirus,
    DefenderTelemetry Defender,
    LocalAdministratorsTelemetry LocalAdministrators,
    WindowsUpdateTelemetry WindowsUpdate,
    PendingRebootTelemetry PendingReboot,
    SecurityServicesTelemetry Services,
    InstalledSoftwareSummary Software)
{
    public static EndpointTelemetryView From(EndpointTelemetryReport report, DateTimeOffset receivedUtc) => new(
        report.SchemaVersion, report.CollectedUtc, receivedUtc, report.BitLocker, report.Antivirus, report.Defender,
        report.LocalAdministrators, report.WindowsUpdate, report.PendingReboot, report.Services,
        new InstalledSoftwareSummary(report.Software.Availability, report.Software.TotalCount,
            report.Software.Items?.Count, report.Software.Truncated, report.Software.SkippedCount));
}

public sealed record InstalledSoftwareSummary(
    string Availability, int? TotalCount, int? ReportedCount, bool Truncated, int SkippedCount);
