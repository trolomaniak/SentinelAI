using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal sealed class AdminInitializationService(
    AdminStore admins,
    DeviceStore devices,
    EnrollmentStore enrollments,
    InventoryStore inventories) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await admins.InitializeAsync(cancellationToken);
        await devices.InitializeAsync(cancellationToken);
        await enrollments.InitializeAsync(cancellationToken);
        await inventories.InitializeAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
