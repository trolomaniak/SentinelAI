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

public enum SetupInstallationKind { Fresh, Installed, Retained, Foreign, RecoveryPending }
public sealed record SetupInstallation(SetupInstallationKind Kind, string? Version = null);
public enum SetupLifecycleAction { Repair, Upgrade, Uninstall }
public sealed record SetupLifecycleResult(bool Success, bool RolledBack = false, string? FailureCode = null);

public interface ISetupLifecycleBackend
{
    Task<SetupInstallation> InspectAsync(CancellationToken token);
    Task<SetupLifecycleResult> ExecuteAsync(SetupLifecycleAction action, bool preserveData, CancellationToken token);
}

public static class SetupWorkflow
{
    public static int CompareVersions(string candidate, string installed)
    {
        if (!TryVersion(candidate, out var next) || !TryVersion(installed, out var current))
            throw new InvalidDataException("Unsupported setup version.");
        for (var index = 0; index < 3; index++)
            if (next[index] != current[index]) return next[index].CompareTo(current[index]);
        return 0;
    }

    public static IReadOnlyList<SetupLifecycleAction> AllowedLifecycleActions(SetupInstallation installation, string candidateVersion)
    {
        if (installation.Kind == SetupInstallationKind.RecoveryPending) return [SetupLifecycleAction.Repair];
        if (installation.Kind is not (SetupInstallationKind.Installed or SetupInstallationKind.Retained) || installation.Version is null)
            return [];
        var comparison = CompareVersions(candidateVersion, installation.Version);
        return comparison switch
        {
            0 => [SetupLifecycleAction.Repair, SetupLifecycleAction.Uninstall],
            > 0 => [SetupLifecycleAction.Upgrade, SetupLifecycleAction.Uninstall],
            _ => [SetupLifecycleAction.Uninstall]
        };
    }

    public static bool CanExecuteLifecycle(SetupInstallation installation, string candidateVersion, SetupLifecycleAction action,
        bool preserveData, string removalConfirmation) =>
        AllowedLifecycleActions(installation, candidateVersion).Contains(action) &&
        (action == SetupLifecycleAction.Uninstall ? preserveData || removalConfirmation == "DELETE" : preserveData);

    public static async Task<SetupLifecycleResult> ExecuteLifecycleAsync(ISetupLifecycleBackend backend, SetupInstallation installation,
        string candidateVersion, SetupLifecycleAction action, bool preserveData, string removalConfirmation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!CanExecuteLifecycle(installation, candidateVersion, action, preserveData, removalConfirmation))
            throw new InvalidDataException("Installation operation unavailable.");
        var result = await backend.ExecuteAsync(action, preserveData, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return result;
    }

    public static SetupInstallation ParseInstallationState(string marker)
    {
        if (marker.Length > 128) throw new InvalidDataException("Invalid setup state.");
        var fields = marker.Split('|');
        if (fields.Length != 3 || fields[0] != "STATE" ||
            !Enum.TryParse<SetupInstallationKind>(fields[1], ignoreCase: false, out var kind) || !Enum.IsDefined(kind) || fields[1] != kind.ToString() ||
            kind is SetupInstallationKind.Fresh or SetupInstallationKind.Foreign && fields[2].Length != 0 ||
            kind is SetupInstallationKind.Installed or SetupInstallationKind.Retained && !TryVersion(fields[2], out _) ||
            kind == SetupInstallationKind.RecoveryPending && fields[2].Length != 0 && !TryVersion(fields[2], out _))
            throw new InvalidDataException("Invalid setup state.");
        return new(kind, fields[2].Length == 0 ? null : fields[2]);
    }

    private static bool TryVersion(string? value, out int[] components)
    {
        components = new int[3];
        if (value is not { Length: >= 5 and <= 17 }) return false;
        var fields = value.Split('.');
        if (fields.Length != 3) return false;
        for (var index = 0; index < 3; index++)
            if (fields[index].Length is <= 0 or > 5 || fields[index].Length > 1 && fields[index][0] == '0' ||
                fields[index].Any(character => character is < '0' or > '9') ||
                !int.TryParse(fields[index], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out components[index]) || components[index] > 65_535) return false;
        return true;
    }

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
        ReadOnlySpan<char> enrollmentToken, bool preserveData = true)
    {
        if (buffer.Length < 8192 || action is not ("prepare-core" or "start-core" or "complete" or "inspect" or "lifecycle-stop" or "lifecycle-start" or "lifecycle-health" or "lifecycle-context" or "lifecycle-cleanup" or "uninstall" or "lifecycle-reconcile") || workDirectory.Length is <= 0 or > 260 ||
            metadata.KeyId.Length is <= 0 or > 64 || metadata.Channel is not ("stable" or "pilot" or "beta") || !TryVersion(metadata.Version, out _) ||
            action != "complete" && enrollmentToken.Length != 0 ||
            action == "complete" && !ValidEnrollmentToken(enrollmentToken) || action != "uninstall" && !preserveData)
            throw new InvalidDataException("Invalid setup request.");
        using var stream = new MemoryStream(buffer, 0, 8192, writable: true, publiclyVisible: true);
        stream.SetLength(0);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject(); writer.WriteString("action", action); writer.WriteString("workDirectory", workDirectory);
            writer.WriteString("keyId", metadata.KeyId); writer.WriteString("channel", metadata.Channel);
            // The existing strict installer JSON grammar accepts strings/objects.
            // A credential-free phase carries an exact empty string, never null.
            writer.WriteString("enrollmentToken", enrollmentToken);
            writer.WriteString("version", metadata.Version); writer.WriteString("preserveData", preserveData ? "true" : "false");
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
        "PROGRESS|inspect" => "Checking the installed deployment...",
        "PROGRESS|replace" => "Replacing verified program files...",
        "PROGRESS|health" => "Verifying installation health...",
        "PROGRESS|rollback" => "Restoring the previous working version...",
        "PROGRESS|uninstall" => "Removing the owned installation...",
        _ => null
    };
}
