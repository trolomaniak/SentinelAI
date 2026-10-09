using System.Text.Json;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Setup.Foundation;

public interface ISetupWorker
{
    Task PrepareCoreAsync(CancellationToken token);
    Task StartCoreAsync(CancellationToken token);
    Task CompleteAsync(ReadOnlyMemory<char> enrollmentToken, CancellationToken token);
}

public interface ISetupEnrollmentIssuer
{
    Task<string> IssueAsync(string username, ReadOnlyMemory<char> password, CancellationToken token);
}

public static class SetupWorkflow
{
    public static bool ValidCredentials(string username, ReadOnlySpan<char> password, ReadOnlySpan<char> confirmation) =>
        !string.IsNullOrWhiteSpace(username) && username.Trim().Length <= 128 && !username.Any(char.IsControl) &&
        password.Length is >= 12 and <= 1024 && password.SequenceEqual(confirmation);

    public static bool ValidEnrollmentToken(ReadOnlySpan<char> enrollmentToken)
    {
        if (enrollmentToken.Length != 64) return false;
        foreach (var character in enrollmentToken)
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')) return false;
        return true;
    }

    public static async Task InstallAsync(ISetupWorker worker, IAdministratorSetupClient administrator, ISetupEnrollmentIssuer issuer,
        string username, ReadOnlyMemory<char> password, IProgress<string> progress, CancellationToken token)
    {
        if (!ValidCredentials(username, password.Span, password.Span)) throw new InvalidDataException("Invalid setup credentials.");
        token.ThrowIfCancellationRequested();
        progress.Report("Preparing Core...");
        await worker.PrepareCoreAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        progress.Report("Creating the local administrator...");
        if (await administrator.GetStateAsync(token).ConfigureAwait(false) != AdministratorSetupState.Required)
            throw new InvalidDataException("Local administrator setup unavailable.");
        token.ThrowIfCancellationRequested();
        if (await administrator.InitializeAsync(username.Trim(), password, token).ConfigureAwait(false) != AdministratorSetupResult.Created)
            throw new InvalidDataException("Local administrator setup unavailable.");
        token.ThrowIfCancellationRequested();
        progress.Report("Starting Core...");
        await worker.StartCoreAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        progress.Report("Enrolling Agent...");
        var issued = await issuer.IssueAsync(username.Trim(), password, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (!ValidEnrollmentToken(issued.AsSpan())) throw new InvalidDataException("Agent enrollment unavailable.");
        var enrollmentToken = issued.ToCharArray();
        try
        {
            token.ThrowIfCancellationRequested();
            progress.Report("Installing Windows services and Desktop...");
            await worker.CompleteAsync(enrollmentToken, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
        }
        finally { Array.Clear(enrollmentToken); }
    }

    /// <summary>Caller owns and wipes the fixed buffer immediately after the private pipe write.</summary>
    public static int WriteWorkerRequest(byte[] buffer, string action, string workDirectory, SetupMetadata metadata,
        ReadOnlySpan<char> enrollmentToken)
    {
        if (buffer.Length < 8192 || action is not ("prepare-core" or "start-core" or "complete") || workDirectory.Length is <= 0 or > 260 ||
            metadata.KeyId.Length is <= 0 or > 64 || metadata.Channel is not ("stable" or "pilot" or "beta") ||
            action != "complete" && enrollmentToken.Length != 0 ||
            action == "complete" && !ValidEnrollmentToken(enrollmentToken))
            throw new InvalidDataException("Invalid setup request.");
        using var stream = new MemoryStream(buffer, 0, 8192, writable: true, publiclyVisible: true);
        stream.SetLength(0);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject(); writer.WriteString("action", action); writer.WriteString("workDirectory", workDirectory);
            writer.WriteString("keyId", metadata.KeyId); writer.WriteString("channel", metadata.Channel);
            if (action == "complete") writer.WriteString("enrollmentToken", enrollmentToken);
            else writer.WriteNull("enrollmentToken");
            writer.WriteEndObject(); writer.Flush();
        }
        if (stream.Length >= 8192) throw new InvalidDataException("Setup request is too large.");
        stream.WriteByte((byte)'\n');
        return checked((int)stream.Length);
    }

    public static string? ProgressFor(string marker) => marker switch
    {
        "PROGRESS|validate" => "Validating installation files...",
        "PROGRESS|core" => "Preparing Core...",
        "PROGRESS|services" => "Starting Windows services...",
        "PROGRESS|agent" => "Installing and enrolling Agent...",
        "PROGRESS|desktop" => "Installing Desktop and Updater...",
        "PROGRESS|shortcut" => "Creating Start Menu shortcuts...",
        _ => null
    };
}
