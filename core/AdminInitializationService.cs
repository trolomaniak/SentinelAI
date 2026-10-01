using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal sealed class AdminInitializationService(AdminStore admins) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) =>
        admins.InitializeAsync(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
