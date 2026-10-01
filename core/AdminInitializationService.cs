using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal sealed class AdminInitializationService(AdminStore admins, DeviceStore devices) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await admins.InitializeAsync(cancellationToken);
        await devices.InitializeAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
