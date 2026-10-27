using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updater;

public enum CentralUpdateOutcome { NoUpdate, NotScheduled, Started, Rejected, GivenUp }

/// <summary>The full Setup's central installation (protected Setup data, Core's data) and the update task's own folder.</summary>
public sealed record CentralUpdateLayout(string ProgramData, string ProgramFiles)
{
    public static CentralUpdateLayout Default { get; } = new(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));

    public string Receipt => Path.Combine(ProgramData, "SentinelAI", "Setup", "setup-installation.json");
    public string PublicKey => Path.Combine(ProgramData, "SentinelAI", "Setup", "public-key.pem");
    public string CoreReceipt => Path.Combine(ProgramData, "SentinelAI", "Core", "pilot-installation.json");
    /// <summary>Where Core, which can write there, downloads the Setup: untrusted input.</summary>
    public string Staging => Path.Combine(ProgramData, "SentinelAI", "Core", "central-update");
    public string StagedManifest => Path.Combine(Staging, "SentinelAI-Setup.manifest.json");
    public string StagedPackage => Path.Combine(Staging, "SentinelAI-Setup.exe");
    public string AutoInstallMarker => Path.Combine(Staging, "auto-install");
    /// <summary>Administrators and SYSTEM only; Core may read the state file.</summary>
    public string WorkRoot => Path.Combine(ProgramData, "SentinelAI-Setup", "central-update");
    public string StateFile => Path.Combine(WorkRoot, "state.json");
    public string DesktopExecutable => Path.Combine(ProgramFiles, "SentinelAI", "Desktop", "SentinelAI.Desktop.exe");
}

/// <summary>The Windows effects of a central update, scripted in tests.</summary>
public interface ICentralUpdateHost
{
    /// <summary>A new folder under <see cref="CentralUpdateLayout.WorkRoot"/> that only administrators and SYSTEM can change.</summary>
    string CreateRunDirectory();
    /// <summary>Writes the attempt record so that Core can show it, and nothing else can change it.</summary>
    void WriteState(byte[] document);
    /// <summary>Ends SentinelAI Desktop, which the upgrade replaces.</summary>
    void CloseDesktop();
    /// <summary>Starts the verified Setup copy and returns without waiting: the upgrade replaces this Updater too.</summary>
    void StartSetup(string executable, bool quiet);
}

/// <summary>
/// MVP-7: runs a newer SentinelAI Setup that Core downloaded from the owner's update server. The downloaded files are
/// untrusted: the manifest must verify with the key, environment and channel the full Setup pinned at installation,
/// name the Setup artifact and be newer than the installed version; the Setup is copied into a folder only
/// administrators and SYSTEM can change and checked against the signed hash before it runs. At night (the scheduled
/// task) it runs only while an administrator keeps automatic installation on, closes Desktop and runs "/upgrade
/// /quiet"; a release is tried at most three times. From Desktop's Install it opens the Setup window instead.
/// </summary>
public sealed class CentralUpdateApplier(CentralUpdateLayout layout, ICentralUpdateHost host, TimeProvider time)
{
    public const string ArtifactId = UpdateManifestFormat.SetupArtifactId;
    public const int MaximumAttempts = 3;
    private const int MaximumDocumentBytes = 4096;

    public async Task<CentralUpdateOutcome> ApplyAsync(bool scheduled, CancellationToken cancellationToken)
    {
        var (keyId, channel) = await ReadSetupReceiptAsync(cancellationToken);
        var publicKey = System.Text.Encoding.ASCII.GetString(await ReadBoundedAsync(layout.PublicKey, 16 * 1024, cancellationToken));
        var installed = await ReadInstalledVersionAsync(cancellationToken);
        if (!File.Exists(layout.StagedManifest) || !File.Exists(layout.StagedPackage)) return CentralUpdateOutcome.NoUpdate;
        if (scheduled && !File.Exists(layout.AutoInstallMarker)) return CentralUpdateOutcome.NotScheduled;

        byte[] manifest;
        try { manifest = await ReadBoundedAsync(layout.StagedManifest, UpdateManifestFormat.MaximumDocumentBytes, cancellationToken); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return CentralUpdateOutcome.Rejected;
        }

        VerifiedUpdateManifest verified;
        try
        {
            verified = UpdateManifestVerifier.Verify(manifest, new UpdateVerificationPolicy("development", channel, ArtifactId, installed,
                new Dictionary<string, string>(StringComparer.Ordinal) { [keyId] = publicKey }));
        }
        catch (UpdateValidationException)
        {
            // Unsigned, foreign, another channel or artifact, or not newer than the installation.
            return UpdateManifestFormat.ReadUnauthenticated(manifest) is { } offered && UpdateManifestFormat.TryParseVersion(offered.Version, out var version) &&
                   UpdateManifestFormat.TryParseVersion(installed, out var current) && version <= current
                ? CentralUpdateOutcome.NoUpdate : CentralUpdateOutcome.Rejected;
        }

        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(manifest));
        var attempts = ReadAttempts(fingerprint);
        if (scheduled && attempts >= MaximumAttempts) return CentralUpdateOutcome.GivenUp;

        var copy = Path.Combine(host.CreateRunDirectory(), "SentinelAI-Setup.exe");
        try
        {
            RejectLink(layout.StagedPackage);
            await UpdateArtifactVerifier.CopyAndVerifyAsync(layout.StagedPackage, copy, verified, cancellationToken);
        }
        catch (Exception exception) when (exception is UpdateValidationException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return CentralUpdateOutcome.Rejected;
        }

        host.WriteState(JsonSerializer.SerializeToUtf8Bytes(new
        {
            manifestSha256 = fingerprint,
            version = verified.Manifest.Version,
            attempts = attempts + 1,
            lastAttemptUtc = time.GetUtcNow().ToString("O", CultureInfo.InvariantCulture)
        }));
        if (scheduled) host.CloseDesktop();
        host.StartSetup(copy, quiet: scheduled);
        return CentralUpdateOutcome.Started;
    }

    /// <summary>The full Setup's receipt: its format, a development key ID, the development environment and a channel.</summary>
    private async Task<(string KeyId, string Channel)> ReadSetupReceiptAsync(CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await ReadBoundedAsync(layout.Receipt, MaximumDocumentBytes, cancellationToken));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid SentinelAI Setup receipt.");
        var keyId = Text(root, "keyId");
        var channel = Text(root, "channel");
        if (Text(root, "format") != "sentinelai-setup-v1" || Text(root, "environment") != "development" ||
            keyId is null || !keyId.StartsWith("dev-", StringComparison.Ordinal) || !UpdateKeyId(keyId) ||
            channel is not ("stable" or "pilot" or "beta"))
            throw new InvalidDataException("Invalid SentinelAI Setup receipt.");
        return (keyId, channel);
    }

    private async Task<string> ReadInstalledVersionAsync(CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await ReadBoundedAsync(layout.CoreReceipt, MaximumDocumentBytes, cancellationToken));
        if (document.RootElement.ValueKind != JsonValueKind.Object || Text(document.RootElement, "component") != "Core" ||
            Text(document.RootElement, "version") is not { } version || !UpdateManifestFormat.TryParseVersion(version, out _))
            throw new InvalidDataException("Invalid Core receipt.");
        return version;
    }

    /// <summary>How often this exact release was started; the task's own record, anything unreadable counts as none.</summary>
    private int ReadAttempts(string fingerprint)
    {
        try
        {
            if (!File.Exists(layout.StateFile)) return 0;
            using var document = JsonDocument.Parse(File.ReadAllBytes(layout.StateFile));
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object && Text(root, "manifestSha256") == fingerprint &&
                   root.TryGetProperty("attempts", out var attempts) && attempts.TryGetInt32(out var count) && count is >= 0 and <= 1000 ? count : 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException) { return 0; }
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool UpdateKeyId(string keyId) => keyId.Length <= 52 &&
        keyId.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

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
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Links and reparse points are not followed.");
        }
    }
}
