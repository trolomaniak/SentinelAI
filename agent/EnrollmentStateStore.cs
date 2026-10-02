using System.Security.Cryptography;
using System.Text.Json;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Hosting;

namespace SentinelAI.Agent;

public sealed record EnrollmentState(
    Guid InstallationId,
    Guid EndpointId,
    Guid CoreInstallationId,
    Guid OrganizationId,
    string AgentCredential,
    string CoreOrigin,
    string? CoreCertificateSha256)
{
    public override string ToString() => nameof(EnrollmentState);
}

public sealed class EnrollmentStateStore(AgentOptions options)
{
    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode StateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public string StatePath => Path.Combine(options.DataDirectory, "enrollment-state");

    public async Task WriteEndpointReceiptAsync(EnrollmentState state, CancellationToken cancellationToken = default)
    {
        // The receipt is nonsecret; derive it from authenticated persisted state rather than caller claims.
        var persisted = await LoadAsync(state.InstallationId, cancellationToken);
        if (persisted is null || persisted.EndpointId != state.EndpointId)
            throw new InvalidDataException("An endpoint receipt requires validated persistent enrollment state.");
        var receiptPath = Path.Combine(options.DataDirectory, "endpoint-id");
        PilotHostConfiguration.RejectLinks(receiptPath);
        var temporaryPath = Path.Combine(options.DataDirectory, $".endpoint-id.{Guid.NewGuid():N}.tmp");
        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.Asynchronous
            };
            if (!OperatingSystem.IsWindows()) streamOptions.UnixCreateMode = StateFileMode;
            await using (var stream = new FileStream(temporaryPath, streamOptions))
            {
                await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(persisted.EndpointId.ToString("D")), cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, receiptPath, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    public async Task<EnrollmentState?> LoadAsync(
        Guid installationId,
        CancellationToken cancellationToken = default)
    {
        EnsurePrivateDirectory();
        if (!File.Exists(StatePath))
        {
            return null;
        }

        if (new FileInfo(StatePath).LinkTarget is not null)
        {
            throw new InvalidDataException("The Agent enrollment state cannot be a symbolic link.");
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(StatePath, StateFileMode);
        }

        var bytes = await File.ReadAllBytesAsync(StatePath, cancellationToken);
        if (OperatingSystem.IsWindows())
        {
            bytes = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
        }

        EnrollmentState? state;
        try
        {
            state = JsonSerializer.Deserialize<EnrollmentState>(bytes);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The Agent enrollment state is invalid.", exception);
        }

        if (state is null || state.InstallationId != installationId ||
            state.EndpointId == Guid.Empty || state.CoreInstallationId == Guid.Empty ||
            state.OrganizationId == Guid.Empty ||
            state.AgentCredential is not { Length: 64 } ||
            !IsHex(state.AgentCredential) ||
            !string.Equals(state.CoreOrigin, options.CoreUrl.AbsoluteUri, StringComparison.Ordinal) ||
            !string.Equals(state.CoreCertificateSha256, options.CoreCertificateSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The Agent enrollment state does not match this installation or Core.");
        }

        return state;
    }

    public async Task<EnrollmentState> SaveAsync(
        EnrollmentResponse response,
        CancellationToken cancellationToken = default)
    {
        var state = new EnrollmentState(
            response.InstallationId,
            response.EndpointId,
            response.CoreInstallationId,
            response.OrganizationId,
            response.AgentCredential,
            options.CoreUrl.AbsoluteUri,
            options.CoreCertificateSha256);
        if (state.InstallationId == Guid.Empty || state.EndpointId == Guid.Empty ||
            state.CoreInstallationId == Guid.Empty || state.OrganizationId == Guid.Empty ||
            state.AgentCredential is not { Length: 64 } || !IsHex(state.AgentCredential))
        {
            throw new InvalidDataException("Core returned an invalid enrollment identity.");
        }

        EnsurePrivateDirectory();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        if (OperatingSystem.IsWindows())
        {
            bytes = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        }

        var temporaryPath = Path.Combine(options.DataDirectory, $".enrollment-state.{Guid.NewGuid():N}.tmp");
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
                streamOptions.UnixCreateMode = StateFileMode;
            }

            await using (var stream = new FileStream(temporaryPath, streamOptions))
            {
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            File.Move(temporaryPath, StatePath);
            return state;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void EnsurePrivateDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(options.DataDirectory);
            return;
        }

        Directory.CreateDirectory(options.DataDirectory, DirectoryMode);
        if (new DirectoryInfo(options.DataDirectory).LinkTarget is not null)
        {
            throw new InvalidDataException("The Agent data directory cannot be a symbolic link.");
        }

        File.SetUnixFileMode(options.DataDirectory, DirectoryMode);
    }

    private static bool IsHex(string value)
    {
        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}
