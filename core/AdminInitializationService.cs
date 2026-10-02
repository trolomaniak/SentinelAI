using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal sealed class AdminInitializationService(
    AdminStore admins,
    DeviceStore devices,
    EnrollmentStore enrollments,
    InventoryStore inventories,
    AlertStore alerts) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await admins.InitializeAsync(cancellationToken);
        await devices.InitializeAsync(cancellationToken);
        await enrollments.InitializeAsync(cancellationToken);
        await inventories.InitializeAsync(cancellationToken);
        await alerts.InitializeAsync(cancellationToken);
        await inventories.BackfillAlertsAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
