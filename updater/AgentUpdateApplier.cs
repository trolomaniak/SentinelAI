using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updater;

public enum AgentUpdateOutcome { NoUpdate, Installed, Rejected, RolledBack, NotRetried, RollbackFailed }

/// <summary>An Agent Setup installation (MVP-2): code, the protected Setup data and the Agent's own staging.</summary>
public sealed record AgentUpdateLayout(string CodeRoot, string DataRoot)
{
    public static AgentUpdateLayout Default { get; } = new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SentinelAI Agent"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI Agent"));

    public string AgentCode => Path.Combine(CodeRoot, "Agent");
    public string AgentData => Path.Combine(DataRoot, "Agent");
    public string Receipt => Path.Combine(DataRoot, "Setup", "agent-setup-installation.json");
    public string PublicKey => Path.Combine(DataRoot, "Setup", "public-key.pem");
    /// <summary>SHA-256 of the last manifest whose installation was rolled back and how often; written only by the SYSTEM updater.</summary>
    public string RolledBack => Path.Combine(DataRoot, "Setup", "agent-update-rolled-back.txt");
    public string StagedManifest => Path.Combine(AgentData, "update", "agent-update.manifest.json");
    public string StagedPackage => Path.Combine(AgentData, "update", "agent-update.zip");
}

/// <summary>
/// MVP-7: installs a newer signed Agent package that the Agent fetched from Core into its own data directory. The
/// staged files are untrusted input: the manifest must verify against the public key and policy Agent Setup pinned
/// in its protected data, the package is copied privately and checked against the signed hash, and the version must
/// be newer than the installed one. The transactional updater replaces the code and rolls back on a failed start or
/// health check; a release that was rolled back three times is not retried, so a broken release cannot restart the
/// Agent every hour, while a one-off failure is. Nothing is ever written to or deleted from the Agent's data directory; the Agent removes the staged copy once
/// it runs the new version.
/// </summary>
public sealed class AgentUpdateApplier(
    AgentUpdateLayout layout,
    IServiceUpdateLifecycle service,
    TransactionalUpdater updater,
    Action<string>? installed = null)
{
    public const string ArtifactId = "sentinelai-agent-win-x64";
    private const int MaximumReceiptBytes = 4096;
    private const int MaximumPublicKeyBytes = 16 * 1024;
    internal const int MaximumAttempts = 3;
    private static readonly string[] ReceiptFields = ["format", "version", "keyId", "environment", "channel", "coreUrl"];

    public async Task<AgentUpdateOutcome> ApplyAsync(CancellationToken cancellationToken)
    {
        var receipt = await ReadReceiptAsync(cancellationToken);
        var publicKey = System.Text.Encoding.ASCII.GetString(await ReadBoundedAsync(layout.PublicKey, MaximumPublicKeyBytes, cancellationToken));
        var policy = new UpdateVerificationPolicy(receipt["environment"], receipt["channel"], ArtifactId, receipt["version"],
            new Dictionary<string, string>(StringComparer.Ordinal) { [receipt["keyId"]] = publicKey });

        // An interrupted earlier transaction is finished or undone before anything new is considered.
        var recovered = await updater.RecoverAsync(layout.AgentCode, policy, service, cancellationToken);
        if (recovered.Status == UpdateInstallStatus.RollbackFailed) return AgentUpdateOutcome.RollbackFailed;
        var current = Parse(receipt["version"]);
        if ((await updater.ReadInstalledReceiptAsync(layout.AgentCode, policy, cancellationToken))?.Manifest.Version is { } committed &&
            Parse(committed) > current)
        {
            // A committed update whose receipt write was interrupted.
            await RecordAsync(committed, cancellationToken);
            current = Parse(committed);
        }

        if (!File.Exists(layout.StagedManifest) || !File.Exists(layout.StagedPackage)) return AgentUpdateOutcome.NoUpdate;
        byte[] manifest;
        try
        {
            manifest = await ReadBoundedAsync(layout.StagedManifest, UpdateManifestFormat.MaximumDocumentBytes, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return AgentUpdateOutcome.Rejected;
        }

        // A cheap filter only; installation authenticates the manifest under the pinned policy.
        if (UpdateManifestFormat.ReadUnauthenticated(manifest) is not { } offered ||
            !UpdateManifestFormat.TryParseVersion(offered.Version, out var version) || version <= current)
            return AgentUpdateOutcome.NoUpdate;
        var fingerprint = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(manifest));
        var failures = await ReadRollbacksAsync(fingerprint, cancellationToken);
        if (failures >= MaximumAttempts) return AgentUpdateOutcome.NotRetried;

        UpdateInstallResult result;
        try
        {
            result = await updater.InstallAsync(manifest, layout.StagedPackage, policy, layout.AgentCode, service, cancellationToken);
        }
        catch (Exception exception) when (exception is UpdateValidationException or InvalidDataException or IOException or
                                              UnauthorizedAccessException or ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            // Unsigned, tampered, foreign or not newer: the running Agent was never stopped.
            return AgentUpdateOutcome.Rejected;
        }

        switch (result.Status)
        {
            case UpdateInstallStatus.Installed:
                RejectLink(layout.RolledBack);
                File.Delete(layout.RolledBack);
                await RecordAsync(result.Version!, cancellationToken);
                return AgentUpdateOutcome.Installed;
            case UpdateInstallStatus.RolledBack:
                RejectLink(layout.RolledBack);
                await File.WriteAllTextAsync(layout.RolledBack, fingerprint + " " + (failures + 1), System.Text.Encoding.ASCII, cancellationToken);
                return AgentUpdateOutcome.RolledBack;
            default:
                return AgentUpdateOutcome.RollbackFailed;
        }
    }

    private async Task RecordAsync(string version, CancellationToken cancellationToken)
    {
        await WriteReceiptVersionAsync(version, cancellationToken);
        installed?.Invoke(version);
    }

    /// <summary>Agent Setup's receipt: exactly its six string fields, written by Setup into its protected data.</summary>
    private async Task<Dictionary<string, string>> ReadReceiptAsync(CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedAsync(layout.Receipt, MaximumReceiptBytes, cancellationToken);
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        using (var json = JsonDocument.Parse(bytes))
        {
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid Agent Setup receipt.");
            foreach (var property in json.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String || !fields.TryAdd(property.Name, property.Value.GetString()!))
                    throw new InvalidDataException("Invalid Agent Setup receipt.");
            }
        }

        if (fields.Count != ReceiptFields.Length || ReceiptFields.Any(field => !fields.ContainsKey(field)) ||
            fields["format"] != "sentinelai-agent-setup-v1" || fields["environment"] != "development" ||
            !UpdateManifestFormat.TryParseVersion(fields["version"], out _))
            throw new InvalidDataException("Invalid Agent Setup receipt.");
        return fields;
    }

    /// <summary>Rewrites only the version, in place, so the receipt keeps Setup's protected access control.</summary>
    private async Task WriteReceiptVersionAsync(string version, CancellationToken cancellationToken)
    {
        var fields = await ReadReceiptAsync(cancellationToken);
        fields["version"] = version;
        var ordered = ReceiptFields.ToDictionary(field => field, field => fields[field], StringComparer.Ordinal);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(ordered);
        RejectLink(layout.Receipt);
        await using var stream = new FileStream(layout.Receipt, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.SetLength(0);
        await stream.WriteAsync(bytes, cancellationToken);
        stream.Flush(flushToDisk: true);
    }

    /// <summary>How often this exact manifest was rolled back; an unreadable record counts as none.</summary>
    private async Task<int> ReadRollbacksAsync(string fingerprint, CancellationToken cancellationToken)
    {
        if (!File.Exists(layout.RolledBack)) return 0;
        string[] parts;
        try { parts = System.Text.Encoding.ASCII.GetString(await ReadBoundedAsync(layout.RolledBack, 80, cancellationToken)).Split(' '); }
        catch (InvalidDataException) { return 0; } // For example emptied by a power loss while it was written.
        return parts.Length == 2 && parts[0] == fingerprint && int.TryParse(parts[1], System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var count) ? count : 0;
    }

    private static Version Parse(string version) =>
        UpdateManifestFormat.TryParseVersion(version, out var parsed) ? parsed : throw new InvalidDataException("Invalid version.");

    private static async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken cancellationToken)
    {
        RejectLink(path);
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (input.Length <= 0 || input.Length > maximum) throw new InvalidDataException("The document exceeds its bounded size.");
        var bytes = new byte[input.Length];
        await input.ReadExactlyAsync(bytes, cancellationToken);
        if (input.ReadByte() != -1) throw new InvalidDataException("The document grew while it was read.");
        return bytes;
    }

    private static void RejectLink(string path)
    {
        for (var current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Links and reparse points are not followed.");
        }
    }
}
