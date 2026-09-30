namespace SentinelAI.Core;

public static class CoreHost
{
    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        return builder.Build();
    }
}
