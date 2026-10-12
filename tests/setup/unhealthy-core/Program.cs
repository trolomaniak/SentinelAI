using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Test payload only: a genuine SCM-managed Core service with no HTTP listener.
// CI substitutes this assembly before signing its deliberately unhealthy update.
// Production Core has no failure switch and the fresh-install bundle is untouched.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "SentinelAICore");
builder.Services.AddHostedService<NoHealthService>();
await builder.Build().RunAsync();

sealed class NoHealthService : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
}
