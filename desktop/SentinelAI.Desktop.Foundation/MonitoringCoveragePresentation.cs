using System.Globalization;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record MonitoringEndpointRow(Guid EndpointId, string Name, string Heartbeat, string Inventory, string Telemetry, string Coverage);
public sealed record MonitoringSourceRow(string Name, string Availability);
public sealed record MonitoringEventChannelRow(string Name, string Availability, string Report, string Checkpoint, string Counters, string Drops);
public sealed record MonitoringGapRow(string Title, string? Cause, string Records, string Times);
public sealed record MonitoringDetailView(MonitoringEndpointRow Endpoint, string TelemetryReport,
    IReadOnlyList<MonitoringSourceRow> Telemetry, IReadOnlyList<MonitoringEventChannelRow> EventChannels);

internal static class MonitoringCoveragePresentation
{
    public static MonitoringEndpointRow Endpoint(MonitoringEndpointSummary value, DateTimeOffset now) => new(
        value.EndpointId, value.Name,
        F("Heartbeat · {0} · {1}", Heartbeat(value.HeartbeatState), DateAge(value.LastHeartbeatUtc, now)),
        F("Inventory · {0} · {1}", Freshness(value.InventoryFreshness), DateAge(value.InventoryCollectedUtc, now)),
        F("Telemetry · {0} · {1}", Freshness(value.TelemetryFreshness), DateAge(value.TelemetryCollectedUtc, now)),
        F("Current collection · {0}/{1} telemetry sections · {2}/{3} event channels", value.CurrentTelemetrySources,
            MonitoringCoverageContract.TelemetrySourceIds.Count, value.CurrentEventChannels, SecurityEventChannels.All.Count) +
        (value.HasRetainedGaps ? " · " + T("Retained continuity notices") : string.Empty));

    public static MonitoringDetailView Detail(MonitoringEndpointDetail value) => new(Endpoint(value.Endpoint, value.GeneratedUtc),
        F("Telemetry collected · {0} · received by Core · {1}", DateAge(value.Endpoint.TelemetryCollectedUtc, value.GeneratedUtc),
            DateAge(value.Endpoint.TelemetryReceivedUtc, value.GeneratedUtc)),
        value.Telemetry.Select(item => new MonitoringSourceRow(TelemetryName(item.SourceId), Availability(item.State, item.Freshness))).ToArray(),
        value.EventChannels.Select(item => new MonitoringEventChannelRow(ChannelName(item.Channel), Availability(item.State, item.Freshness),
            F("Report received by Core · {0} · last log read · {1}", DateAge(item.ReportedUtc, value.GeneratedUtc), DateAge(item.LastReadUtc, value.GeneratedUtc)),
            F("Checkpoint record ID · {0} · first checkpoint · {1}", Number(item.CheckpointRecordId), DateAge(item.FirstCheckpointUtc, value.GeneratedUtc)),
            F("Counts since · {0} · reported gaps · {1} · skipped records · {2}", DateAge(item.CountersSinceUtc, value.GeneratedUtc), Number(item.ReportedGaps), Number(item.SkippedRecords)),
            F("Dropped records · {0} unparsed · {1} oversized", Number(item.DroppedUnparsed), Number(item.DroppedOversize)))).ToArray());

    public static MonitoringGapRow Gap(MonitoringCoverageGap value, DateTimeOffset now) => new(
        F("{0} · {1}", ChannelName(value.Channel), value.Reason switch
        {
            SecurityEventGapReasons.CoverageStarted when value.CoverageRestart => T("Coverage restarted"),
            SecurityEventGapReasons.CoverageStarted => T("First coverage baseline"),
            SecurityEventGapReasons.Overwritten => T("Records overwritten"),
            SecurityEventGapReasons.LogReset => T("Event log reset"),
            SecurityEventGapReasons.Dropped => T("Records dropped by Agent"),
            SecurityEventGapReasons.Rejected => T("Records rejected by Core"),
            _ => T("Unknown")
        }),
        value.Cause switch
        {
            SecurityEventCoverageCauses.NoCheckpoint => T("No checkpoint was available."),
            SecurityEventCoverageCauses.CheckpointInvalid => T("The checkpoint was invalid."),
            SecurityEventCoverageCauses.EndpointChanged => T("The endpoint identity changed."),
            _ => null
        }, F("First record ID · {0} · last record ID · {1}", Number(value.FirstRecordId), Number(value.LastRecordId)),
        F("Detected · {0} · received by Core · {1}", DateAge(value.DetectedUtc, now), DateAge(value.ReceivedUtc, now)));

    public static string DateAge(DateTimeOffset? value, DateTimeOffset now)
    {
        if (value is not { } date) return T("Unknown");
        var age = now - date;
        var ageText = age switch
        {
            _ when age < TimeSpan.Zero => T("in the future"),
            { Days: > 0 } => F("{0} d {1} h ago", age.Days, age.Hours),
            { Hours: > 0 } => F("{0} h {1} min ago", age.Hours, age.Minutes),
            { Minutes: > 0 } => F("{0} min ago", age.Minutes),
            _ => T("less than 1 min ago")
        };
        return F("{0} ({1})", date.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture), ageText);
    }

    private static string Number(long? value) => value?.ToString(CultureInfo.InvariantCulture) ?? T("Unknown");

    internal static string Heartbeat(string value) => value switch
    {
        "healthy" => T("Healthy"), "warning" => T("Warning"), "offline" => T("Offline"),
        "future" => T("Future timestamp"), _ => T("Unknown")
    };

    internal static string Freshness(string value) => value switch
    {
        "current" => T("Current"), "stale" => T("Stale"), "future" => T("Future timestamp"), _ => T("Missing")
    };

    private static string Availability(string state, string freshness) => F("Last reported state · {0} · freshness · {1}", state switch
    {
        TelemetryAvailability.Collected => T("Collected"), TelemetryAvailability.Unsupported => T("Unsupported"),
        TelemetryAvailability.AccessDenied => T("Access denied"), TelemetryAvailability.Unavailable => T("Unavailable"),
        SecurityEventSourceStates.Collecting => T("Collecting"), SecurityEventSourceStates.Disabled => T("Disabled"),
        SecurityEventSourceStates.NotFound => T("Log not found"), SecurityEventSourceStates.Error => T("Read error"),
        _ => T("Unknown")
    }, Freshness(freshness));

    private static string TelemetryName(string value) => value switch
    {
        "bitLocker" => T("BitLocker"), "antivirus" => T("Antivirus (Windows Security Center)"),
        "defender" => T("Microsoft Defender Antivirus status"), "localAdministrators" => T("Local administrators"),
        "windowsUpdatePolicy" => T("Windows Update policy"), "windowsUpdateResults" => T("Windows Update results"),
        "pendingReboot" => T("Pending restart"), "services" => T("Security services"),
        "software" => T("Installed software"), _ => T("Unknown")
    };

    private static string ChannelName(string value) => value switch
    {
        SecurityEventChannels.Security => T("Security event log"), SecurityEventChannels.System => T("System event log"),
        SecurityEventChannels.PowerShell => T("PowerShell Operational event log"),
        SecurityEventChannels.Defender => T("Microsoft Defender Operational event log"), _ => T("Unknown")
    };
}
