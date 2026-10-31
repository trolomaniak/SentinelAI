using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal sealed class AdminInitializationService(
    AdminStore admins,
    DeviceStore devices,
    EnrollmentStore enrollments,
    InventoryStore inventories,
    SecurityEventStore securityEvents,
    AlertStore alerts,
    EndpointTelemetryStore telemetry,
    LicenseStateStore licenses,
    CentralUpdateStore centralUpdates,
    VulnerabilityService vulnerabilities,
    CoreHostingMode hostingMode) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await admins.InitializeAsync(allowBootstrap: !hostingMode.IsWindowsService, cancellationToken);
        await devices.InitializeAsync(cancellationToken);
        await enrollments.InitializeAsync(cancellationToken);
        await inventories.InitializeAsync(cancellationToken);
        await securityEvents.InitializeAsync(cancellationToken);
        await alerts.InitializeAsync(cancellationToken);
        await telemetry.InitializeAsync(cancellationToken);
        await inventories.BackfillAlertsAsync(cancellationToken);
        await licenses.InitializeAsync(cancellationToken);
        await centralUpdates.InitializeAsync(cancellationToken);
        await vulnerabilities.InitializeAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
