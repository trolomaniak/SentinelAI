using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SentinelAI.Agent;

public static class AgentHost
{
    public static HostApplicationBuilder CreateBuilder(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "SentinelAIAgent");

        builder.Services.AddSingleton(provider =>
            AgentOptions.FromConfiguration(provider.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>()));
        builder.Services.AddSingleton<InstallationIdentityStore>();
        builder.Services.AddSingleton(_ => new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false
        })
        {
            Timeout = TimeSpan.FromSeconds(10)
        });
        builder.Services.AddHostedService<HeartbeatWorker>();

        return builder;
    }

    public static IHost Build(string[] args) => CreateBuilder(args).Build();
}
