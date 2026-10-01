using Microsoft.Extensions.Hosting;

namespace SentinelAI.Agent;

public static class Program
{
    public static async Task Main(string[] args)
    {
        using var host = AgentHost.Build(args);
        await host.RunAsync();
    }
}
