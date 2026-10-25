using SentinelAI.PilotLicense;

return await PilotLicenseCommand.RunAsync(args, Console.Out, Console.Error, TimeProvider.System);
