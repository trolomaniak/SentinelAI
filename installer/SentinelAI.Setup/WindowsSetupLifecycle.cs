using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using SentinelAI.Setup.Foundation;
using SentinelAI.Updates;

namespace SentinelAI.Setup;

/// <summary>Windows ownership/service adapter for the existing signed, code-only transaction.</summary>
internal sealed class WindowsSetupLifecycle(string workDirectory, SetupMetadata metadata, IProgress<string> progress)
    : ISetupLifecycleBackend
{
    private static string CodeRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SentinelAI");
    private static string SetupData => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI", "Setup");
    private static string Journal => Path.Combine(Path.GetDirectoryName(CodeRoot)!, ".SentinelAI.sentinelai-update.json");
    private readonly PowerShellSetupWorker _worker = new(workDirectory, metadata, progress);
    private readonly TransactionalUpdater _updater = new(healthTimeout: TimeSpan.FromSeconds(30), recoveryTimeout: TimeSpan.FromMinutes(3));

    internal static IDisposable AcquireOperationLock()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI-Setup");
        ProtectedStaging.Validate(directory);
        var path = Path.Combine(directory, "lifecycle.lock");
        if (Directory.Exists(path) || File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Installation lock unavailable.");
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public Task<SetupInstallation> InspectAsync(CancellationToken token) => _worker.InspectAsync(token);

    public async Task<SetupLifecycleResult> ExecuteAsync(SetupLifecycleAction action, bool preserveData, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var lease = AcquireOperationLock();
        var state = await InspectAsync(token).ConfigureAwait(false);
        if (!SetupWorkflow.AllowedLifecycleActions(state, metadata.Version).Contains(action) ||
            action != SetupLifecycleAction.Uninstall && !preserveData)
            return new(false, FailureCode: "installation_unavailable");
        if (DesktopIsRunning()) return new(false, FailureCode: "desktop_running");
        if (state.Kind == SetupInstallationKind.Retained && action != SetupLifecycleAction.Uninstall &&
            Directory.Exists(CodeRoot) && Directory.EnumerateFileSystemEntries(CodeRoot).Any())
            return new(false, FailureCode: "finish_uninstall");
        var policy = await ReadInstalledPolicyAsync(state.Version!, token).ConfigureAwait(false);
        var adapter = new ServiceAdapter(_worker, state.Kind == SetupInstallationKind.RecoveryPending);
        if (state.Kind == SetupInstallationKind.RecoveryPending)
        {
            progress.Report("Recovering the interrupted installation...");
            var recovered = await _updater.RecoverAsync(CodeRoot, policy, adapter, token).ConfigureAwait(false);
            if (recovered.Status == UpdateInstallStatus.RollbackFailed) return new(false, FailureCode: "rollback_failed");
            // A crash before the updater's journal or after its healthy commit can
            // leave only our protected receipt snapshot. Reconcile it explicitly.
            if (recovered.Status == UpdateInstallStatus.NoPendingRecovery && Directory.Exists(CodeRoot))
            {
                await _worker.CommandAsync("lifecycle-reconcile", true, token).ConfigureAwait(false);
                await _worker.CommandAsync("lifecycle-start", true, token).ConfigureAwait(false);
                await _worker.CommandAsync("lifecycle-health", true, token).ConfigureAwait(false);
            }
            await _worker.CommandAsync("lifecycle-cleanup", true, token).ConfigureAwait(false);
            return new(true, FailureCode: "recovered");
        }
        if (action == SetupLifecycleAction.Uninstall)
        {
            await _worker.CommandAsync("uninstall", preserveData, token).ConfigureAwait(false);
            return new(true);
        }
        var manifest = await ReadBoundedAsync(Path.Combine(workDirectory, "bundle", "deployment.manifest.json"), 32 * 1024, token).ConfigureAwait(false);
        var verified = action == SetupLifecycleAction.Repair
            ? UpdateManifestVerifier.VerifyForRepair(manifest, policy) : UpdateManifestVerifier.Verify(manifest, policy);
        if (verified.Manifest.Version != metadata.Version) throw new InvalidDataException("Setup version does not match its signed deployment.");
        var receipt = await _updater.ReadInstalledReceiptAsync(CodeRoot, policy, token).ConfigureAwait(false);
        if (receipt is not null && receipt.Manifest.Version != state.Version)
            throw new InvalidDataException("Installed version does not match its authenticated receipt.");
        var package = Path.Combine(workDirectory, "bundle", "deployment.zip");
        if (state.Kind == SetupInstallationKind.Retained)
        {
            // The code root may have been intentionally removed. Authenticate and
            // fully validate the candidate before creating the owned empty target.
            var verifiedCopy = Path.Combine(workDirectory, "retained-candidate.zip");
            var extracted = Path.Combine(workDirectory, "retained-candidate");
            try
            {
                await UpdateArtifactVerifier.CopyAndVerifyAsync(package, verifiedCopy, verified, token).ConfigureAwait(false);
                await PackageExtractor.ExtractDeploymentAsync(verifiedCopy, extracted, token).ConfigureAwait(false);
                if (DeploymentPackageVersion.Read(await ReadBoundedAsync(Path.Combine(extracted, DeploymentPackageVersion.FileName),
                    DeploymentPackageVersion.MaximumDocumentBytes, token).ConfigureAwait(false)) != verified.Manifest.Version)
                    throw new InvalidDataException("Invalid deployment version.");
            }
            finally
            {
                if (Directory.Exists(extracted)) Directory.Delete(extracted, recursive: true);
                File.Delete(verifiedCopy);
            }
            await _worker.CommandAsync("lifecycle-context", true, token).ConfigureAwait(false);
            adapter.ContextPrepared = true;
        }
        UpdateInstallResult installed;
        try
        {
            installed = state.Kind == SetupInstallationKind.Retained
                ? await _updater.RestoreAsync(manifest, package, policy, CodeRoot, adapter, token).ConfigureAwait(false)
                : action == SetupLifecycleAction.Repair
                    ? await _updater.RepairAsync(manifest, package, policy, CodeRoot, adapter, token).ConfigureAwait(false)
                    : await _updater.InstallAsync(manifest, package, policy, CodeRoot, adapter, token).ConfigureAwait(false);
        }
        catch
        {
            // Failed preflight has not stopped or replaced code. Remove only our
            // snapshot when the transaction has no durable recovery journal.
            if (adapter.ContextPrepared && !File.Exists(Journal))
            {
                try { await _worker.CommandAsync("lifecycle-cleanup", true, CancellationToken.None).ConfigureAwait(false); } catch { }
            }
            throw;
        }
        if (installed.Status == UpdateInstallStatus.RollbackFailed) return new(false, FailureCode: "rollback_failed");
        if (File.Exists(Journal)) return new(false, FailureCode: "recovery_pending");
        await _worker.CommandAsync("lifecycle-cleanup", true, token).ConfigureAwait(false);
        return installed.Status == UpdateInstallStatus.Installed
            ? new(true) : new(false, RolledBack: true, FailureCode: "update_failed");
    }

    private async Task<UpdateVerificationPolicy> ReadInstalledPolicyAsync(string installedVersion, CancellationToken token)
    {
        var keys = await ReadTrustedKeysAsync(token).ConfigureAwait(false);
        return new("development", metadata.Channel, PackageExtractor.DeploymentArtifactId, installedVersion, keys);
    }

    private async Task<IReadOnlyDictionary<string, string>> ReadTrustedKeysAsync(CancellationToken token)
    {
        // The preceding worker inspection proved fixed paths, protected owner,
        // write ACLs, exact receipt schemas and unchanged protected configuration.
        using var document = JsonDocument.Parse(await ReadBoundedAsync(Path.Combine(SetupData, "setup-installation.json"), 4096, token).ConfigureAwait(false));
        var receipt = document.RootElement;
        if (receipt.GetProperty("keyId").GetString() != metadata.KeyId ||
            receipt.GetProperty("environment").GetString() != "development" || receipt.GetProperty("channel").GetString() != metadata.Channel)
            throw new InvalidDataException("Installed trust policy does not match this Setup.");
        var installed = System.Text.Encoding.UTF8.GetString(await ReadBoundedAsync(Path.Combine(SetupData, "public-key.pem"), 4096, token).ConfigureAwait(false));
        var candidate = System.Text.Encoding.UTF8.GetString(await ReadBoundedAsync(Path.Combine(workDirectory, "trust", "root.pem"), 4096, token).ConfigureAwait(false));
        using var installedKey = ECDsa.Create(); using var candidateKey = ECDsa.Create();
        installedKey.ImportFromPem(installed); candidateKey.ImportFromPem(candidate);
        if (!CryptographicOperations.FixedTimeEquals(installedKey.ExportSubjectPublicKeyInfo(), candidateKey.ExportSubjectPublicKeyInfo()))
            throw new InvalidDataException("The installed public trust root cannot be replaced by a candidate.");
        return new Dictionary<string, string>(StringComparer.Ordinal) { [metadata.KeyId] = installed };
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, int maximumBytes, CancellationToken token)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Unsafe maintenance metadata.");
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 || input.Length > maximumBytes) throw new InvalidDataException("Maintenance metadata exceeds its limit.");
        var bytes = new byte[(int)input.Length];
        await input.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        if (input.ReadByte() != -1) throw new InvalidDataException("Maintenance metadata changed during validation.");
        return bytes;
    }

    private static bool DesktopIsRunning()
    {
        var processes = Process.GetProcessesByName("SentinelAI.Desktop");
        try { return processes.Any(process => !process.HasExited); }
        finally { foreach (var process in processes) process.Dispose(); }
    }

    private sealed class ServiceAdapter(PowerShellSetupWorker worker, bool recovering) : IServiceUpdateLifecycle
    {
        public bool ContextPrepared { get; set; }
        public async Task StopAsync(CancellationToken token)
        {
            if (!recovering && !ContextPrepared)
            {
                await worker.CommandAsync("lifecycle-context", true, token).ConfigureAwait(false);
                ContextPrepared = true;
            }
            await worker.CommandAsync("lifecycle-stop", true, token).ConfigureAwait(false);
        }
        public Task StartAsync(string installationDirectory, CancellationToken token) => worker.CommandAsync("lifecycle-start", true, token);
        public async Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken token)
        {
            try { await worker.CommandAsync("lifecycle-health", true, token).ConfigureAwait(false); return true; }
            catch (InvalidDataException) { return false; }
        }
    }
}
