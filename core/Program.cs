using SentinelAI.Core;
using Microsoft.Extensions.Hosting.WindowsServices;

if (AdministratorSetupCommand.IsSetupCommand(args))
{
    Environment.ExitCode = await AdministratorSetupCommand.RunAsync(args, Console.OpenStandardInput(),
        Console.Out, WindowsServiceHelpers.IsWindowsService(), Console.IsInputRedirected);
    return;
}

CoreHost.Build(args).Run();
