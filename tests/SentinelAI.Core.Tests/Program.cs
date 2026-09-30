using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Core;

var coreAssembly = typeof(CoreHost).Assembly;
if (coreAssembly.GetName().Name != "SentinelAI.Core")
{
    throw new Exception("The Core project did not produce the expected assembly.");
}

if (coreAssembly.EntryPoint is null)
{
    throw new Exception("The Core assembly must be executable.");
}

await using var app = CoreHost.Build([]);
if (app.Services.GetService<IServer>() is null)
{
    throw new Exception("The Core scaffold did not register a web server.");
}

Console.WriteLine("Core scaffold tests passed.");
