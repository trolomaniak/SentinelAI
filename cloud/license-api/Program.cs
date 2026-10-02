using SentinelAI.LicenseApi;

if (args.Length > 0 && args[0] == "--generate-development-keys")
{
    if (args.Length != 2)
    {
        Console.Error.WriteLine("Usage: --generate-development-keys <new-output-directory>");
        return 1;
    }

    try
    {
        foreach (var path in DevelopmentKeyGenerator.Generate(args[1]))
        {
            Console.WriteLine(path);
        }
        return 0;
    }
    catch (Exception exception) when (exception is ArgumentException or IOException
        or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
    {
        Console.Error.WriteLine("Development key generation failed. Use a new writable output directory.");
        return 1;
    }
}

var app = LicenseApiHost.Build(args);
app.Run();
return 0;
