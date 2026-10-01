using System.Text;

namespace SentinelAI.Agent;

public sealed class InstallationIdentityStore(AgentOptions options)
{
    public string IdentityPath => Path.Combine(options.DataDirectory, "installation-id");

    public async Task<Guid> LoadOrCreateAsync(CancellationToken cancellationToken = default)
    {
        if (File.Exists(IdentityPath))
        {
            return await ReadAsync(cancellationToken);
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(options.DataDirectory);
        }
        else
        {
            Directory.CreateDirectory(options.DataDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(options.DataDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var temporaryPath = Path.Combine(options.DataDirectory, $".installation-id.{Guid.NewGuid():N}.tmp");
        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous
            };
            if (!OperatingSystem.IsWindows())
            {
                streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            var installationId = Guid.NewGuid();
            await using (var stream = new FileStream(temporaryPath, streamOptions))
            {
                var bytes = Encoding.ASCII.GetBytes(installationId.ToString("D"));
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            try
            {
                File.Move(temporaryPath, IdentityPath);
                return installationId;
            }
            catch (IOException) when (File.Exists(IdentityPath))
            {
                return await ReadAsync(cancellationToken);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private async Task<Guid> ReadAsync(CancellationToken cancellationToken)
    {
        var text = await File.ReadAllTextAsync(IdentityPath, cancellationToken);
        if (!Guid.TryParseExact(text, "D", out var installationId) || installationId == Guid.Empty)
        {
            throw new InvalidDataException($"Agent installation identity is invalid: {IdentityPath}");
        }

        return installationId;
    }
}
