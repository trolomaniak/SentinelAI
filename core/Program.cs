using SentinelAI.Core;
using Microsoft.Extensions.Hosting.WindowsServices;
using SentinelAI.Core.Recovery;

if (BackupRestoreCommand.IsRecoveryCommand(args))
{
    Environment.ExitCode = await BackupRestoreCommand.RunAsync(args, Console.OpenStandardInput(),
        Console.Out, WindowsServiceHelpers.IsWindowsService(), Console.IsInputRedirected);
    return;
}

if (AdministratorSetupCommand.IsSetupCommand(args))
{
    Environment.ExitCode = await AdministratorSetupCommand.RunAsync(args, Console.OpenStandardInput(),
        Console.Out, WindowsServiceHelpers.IsWindowsService(), Console.IsInputRedirected);
    return;
}

BackupRestoreCommand.AssertHostStartupAllowed(args);
CoreHost.Build(args).Run();
