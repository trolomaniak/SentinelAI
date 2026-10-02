using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updates.Tests;

internal static class UpdaterTests
{
    internal static async Task<int> RunAsync()
    {
        var assertions = 0;
        void Ensure(bool condition, string message)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException(message);
        }
        async Task RejectAsync(Func<Task> action, string message)
        {
            assertions++;
            try { await action(); }
            catch (Exception exception) when (exception is UpdateValidationException or InvalidDataException or IOException or ArgumentException) { return; }
            throw new InvalidOperationException(message);
        }
        var updater = new TransactionalUpdater(TimeSpan.FromMilliseconds(40), TimeSpan.FromMilliseconds(2), TimeSpan.FromSeconds(2));
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle();
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && result.Version == "2.0.0", "A signed, hash-verified healthy service commits its update.");
            Ensure(fixture.Code == "candidate" && service.Stops == 1 && service.Starts.SequenceEqual(["candidate"]), "Only the verified replacement is started.");
            Ensure(File.ReadAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName)).SequenceEqual(candidate.Document), "Only healthy installation persists the original signed receipt.");
            Ensure(!File.Exists(fixture.Journal) && !Directory.EnumerateDirectories(fixture.Root).Any(p => p != fixture.Target), "A healthy commit cleans its backup and transaction journal.");
            var replayService = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, replayService), "Installed signed state rejects replay despite a stale operator baseline.");
            Ensure(replayService.Stops == 0 && fixture.Code == "candidate", "Receipt replay is rejected before service lifecycle changes.");
            var next = fixture.Package(version: "3.0.0", code: "next");
            var nextResult = await updater.InstallAsync(next.Document, next.Path, fixture.Policy, fixture.Target, new FakeLifecycle());
            Ensure(nextResult.Status == UpdateInstallStatus.Installed && fixture.Code == "next", "An authenticated newer version advances the installed receipt.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(new byte[UpdateManifestFormat.MaximumDocumentBytes + 1], candidate.Path, fixture.Policy, fixture.Target, service),
                "Oversized installer metadata is rejected before making an asynchronous snapshot.");
            Ensure(service.Stops == 0 && fixture.Code == "previous", "Manifest bounds are checked before filesystem or lifecycle work.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var bytes = File.ReadAllBytes(candidate.Path);
            bytes[bytes.Length / 2] ^= 1;
            File.WriteAllBytes(candidate.Path, bytes);
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "A tampered package is rejected.");
            Ensure(service.Stops == 0 && fixture.Code == "previous" && !File.Exists(fixture.Journal), "Hash rejection leaves current code and service untouched.");
        }
        var unsafeNames = new[] { "../escape", "/escape", "C:/escape", "..\\escape", "folder\\file", "evil:stream", "CON", "CON .txt", "nul.txt", "COM1.exe", "LPT9.txt", "bad.", "bad ", "a//b", "a/../b", "a/./b", "control\u0001", "non-ascii-é" };
        foreach (var name in unsafeNames)
        {
            using var fixture = new Fixture();
            var candidate = fixture.Package(extraEntries: [(name, "unsafe", 0)]);
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), $"Unsafe ZIP paths fail closed: {JsonSerializer.Serialize(name)}.");
            Ensure(service.Stops == 0 && fixture.Code == "previous" && !File.Exists(Path.Combine(fixture.Root, "escape")), "Unsafe extraction cannot stop the service or escape staging.");
        }
        foreach (var extras in new (string, string, int)[][]
                 {
                     [("collision.dll", "a", 0), ("COLLISION.DLL", "b", 0)],
                     [("file", "a", 0), ("file/child", "b", 0)],
                     [("link", "destination", unchecked((int)0xA0000000))],
                     [("reparse", "x", (int)FileAttributes.ReparsePoint)],
                     [("directory/", "nonempty", 0)],
                     [(TransactionalUpdater.ReceiptFileName, "forged receipt", 0)],
                     [("data/sentinelai.db", "synthetic persisted data", 0)],
                     [("data/enrollment-state", "synthetic persisted state", 0)],
                     [("data/installation-id", "synthetic identity", 0)]
                 })
        {
            using var fixture = new Fixture();
            var candidate = fixture.Package(extraEntries: extras);
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "Collisions, links, ambiguous directories and forged installed receipts are rejected.");
            Ensure(service.Stops == 0 && fixture.Code == "previous", "Unsafe archive forms are rejected before stopping.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package(includeExecutable: false);
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "An empty archive does not replace an installation.");
            var many = fixture.Package(extraEntries: Enumerable.Range(0, PackageExtractor.MaximumEntries).Select(i => ($"file{i}.dll", "x", 0)).ToArray());
            await RejectAsync(() => updater.InstallAsync(many.Document, many.Path, fixture.Policy, fixture.Target, service), "ZIP entry count is bounded.");
            var absent = fixture.Package(includeExecutable: false, extraEntries: [("readme.txt", "x", 0)]);
            await RejectAsync(() => updater.InstallAsync(absent.Document, absent.Path, fixture.Policy, fixture.Target, service), "The expected executable is required.");
            var wrongCase = fixture.Package(includeExecutable: false, extraEntries: [("sentinelai.agent.exe", "x", 0)]);
            await RejectAsync(() => updater.InstallAsync(wrongCase.Document, wrongCase.Path, fixture.Policy, fixture.Target, service), "The expected executable has an unambiguous exact spelling.");
            Ensure(service.Stops == 0 && fixture.Code == "previous", "Malformed archive shape does not affect current service code.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle();
            File.WriteAllText(Path.Combine(fixture.Target, "sentinelai.db"), "synthetic persistent data");
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "A configured data directory inside the code target cannot be destructively replaced.");
            Ensure(service.Stops == 0 && fixture.Code == "previous" && File.ReadAllText(Path.Combine(fixture.Target, "sentinelai.db")) == "synthetic persistent data",
                "Known persistent state is preserved and rejected before stop.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle { OnStart = (code, _) => code == "candidate" ? Task.FromException(new IOException("Synthetic candidate start failure.")) : Task.CompletedTask };
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.RolledBack && fixture.Code == "previous", "A candidate start failure restores previous bytes.");
            Ensure(service.Stops == 2 && service.Starts.SequenceEqual(["candidate", "previous"]) && !File.Exists(fixture.Journal), "Rollback stops the candidate before restoring and verifies the restarted previous service.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle { Health = code => code == "previous" };
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.RolledBack && fixture.Code == "previous", "A candidate health timeout restores the previous installation.");
            Ensure(!File.Exists(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName)), "An unhealthy candidate never commits a signed installed receipt.");
        }
        using (var fixture = new Fixture())
        using (var cancellation = new CancellationTokenSource())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle { OnStart = (code, _) => { if (code == "candidate") cancellation.Cancel(); return Task.CompletedTask; } };
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service, cancellation.Token);
            Ensure(result.Status == UpdateInstallStatus.RolledBack && result.FailureCode == "cancelled" && fixture.Code == "previous", "Cancellation after replacement cannot suppress independent bounded rollback.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle { OnStop = (attempt, _) => attempt == 1 ? Task.FromException(new IOException("Synthetic stop failure.")) : Task.CompletedTask };
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.RolledBack && fixture.Code == "previous" && service.Starts.SequenceEqual(["previous"]), "An initial stop failure leaves old code untouched and restarts only the old service.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle
            {
                Health = code => code == "previous",
                OnStop = (attempt, _) => attempt == 2 ? Task.FromException(new IOException("Synthetic rollback stop failure.")) : Task.CompletedTask
            };
            var result = await updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.RollbackFailed && File.Exists(fixture.Journal), "Rollback failure is explicit and retains the journal.");
            var previous = Directory.EnumerateDirectories(fixture.Root).Single(p => p != fixture.Target);
            Ensure(File.ReadAllText(Path.Combine(previous, "previous", "SentinelAI.Agent.exe")) == "previous" && fixture.Code == "candidate", "A failed rollback stop never renames running code and retains its previous backup.");
            var recovered = await updater.RecoverAsync(fixture.Target, fixture.Policy, new FakeLifecycle());
            Ensure(recovered.Status == UpdateInstallStatus.RolledBack && fixture.Code == "previous" && !File.Exists(fixture.Journal), "A later explicit recovery restores the retained backup.");
        }
        foreach (var (phase, target, previous, failed, workExists) in new[]
                 {
                     ("prepared", "previous", false, false, true),
                     ("prepared", "", true, false, true),
                     ("backed-up", "", true, false, true),
                     ("backed-up", "candidate", true, false, true),
                     ("installed", "candidate", true, false, true),
                     ("installed", "", true, true, true),
                     ("restoring", "previous", false, true, true),
                     ("restored", "previous", false, true, true),
                     ("rolled-back", "previous", false, false, false)
                 })
        {
            using var fixture = new Fixture();
            var candidate = fixture.Package();
            fixture.Pending(candidate.Document, phase, target, previous, failed, workExists);
            var service = new FakeLifecycle();
            var recovered = await updater.RecoverAsync(fixture.Target, fixture.Policy, service);
            Ensure(recovered.Status == UpdateInstallStatus.RolledBack && fixture.Code == "previous", "Crash recovery restores old bytes at every rename/restore boundary.");
            Ensure(service.Starts.SequenceEqual(["previous"]) && !File.Exists(fixture.Journal), "Recovered transactions restart only previous code and clean journal after health.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            fixture.Pending(candidate.Document, "committed", "candidate", false, false, workExists: false);
            File.WriteAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName), candidate.Document);
            var service = new FakeLifecycle();
            var result = await updater.RecoverAsync(fixture.Target, fixture.Policy, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && fixture.Code == "candidate" && service.Stops == 0 && !File.Exists(fixture.Journal), "Crash after committed work cleanup safely finishes journal cleanup using the authenticated receipt.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(candidate.Document).Replace("\"version\":\"2.0.0\"", "\"version\":\"3.0.0\"", StringComparison.Ordinal));
            Ensure(!tampered.SequenceEqual(candidate.Document), "The recovery test changes authenticated version metadata while retaining its old signature.");
            fixture.Pending(tampered, "installed", "candidate", previous: true, failed: false, workExists: true);
            var originalJournal = File.ReadAllBytes(fixture.Journal);
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.RecoverAsync(fixture.Target, fixture.Policy, service), "A tampered signed manifest cannot authorize journal recovery.");
            Ensure(service.Stops == 0 && fixture.Code == "candidate" && File.ReadAllBytes(fixture.Journal).SequenceEqual(originalJournal),
                "Failed journal authentication preserves current bytes and journal before service control.");
            var work = Directory.EnumerateDirectories(fixture.Root).Single(p => p != fixture.Target);
            Ensure(File.ReadAllText(Path.Combine(work, "previous", "SentinelAI.Agent.exe")) == "previous", "Tampered journal rejection preserves the previous installation backup.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            File.WriteAllText(fixture.Journal, JsonSerializer.Serialize(new { format = 1, transaction = "../escape", phase = "installed", manifest = Convert.ToBase64String(candidate.Document) }));
            var service = new FakeLifecycle();
            await RejectAsync(() => updater.RecoverAsync(fixture.Target, fixture.Policy, service), "Injected journal paths are not accepted.");
            Ensure(service.Stops == 0 && fixture.Code == "previous" && File.Exists(fixture.Journal), "Malformed recovery state is preserved without acting on paths.");
            File.WriteAllText(fixture.Journal, "{\"format\":1,\"format\":1,\"transaction\":\"" + new string('a', 32) + "\",\"phase\":\"prepared\",\"manifest\":\"" + Convert.ToBase64String(candidate.Document) + "\"}");
            await RejectAsync(() => updater.RecoverAsync(fixture.Target, fixture.Policy, service), "Duplicate journal fields fail closed.");
            Ensure(service.Stops == 0, "Ambiguous journals never reach service control.");
        }
        using (var fixture = new Fixture())
        {
            var candidate = fixture.Package();
            var service = new FakeLifecycle();
            using var held = new FileStream(Path.Combine(fixture.Root, ".Agent.sentinelai-update.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "Concurrent update transactions are excluded.");
            Ensure(service.Stops == 0 && fixture.Code == "previous", "Lock rejection does not affect running code.");
        }
        if (!OperatingSystem.IsWindows())
        {
            using (var writableFixture = new Fixture())
            {
                var writableCandidate = writableFixture.Package();
                var writableService = new FakeLifecycle();
                var originalMode = File.GetUnixFileMode(writableFixture.Root);
                try
                {
                    File.SetUnixFileMode(writableFixture.Root, originalMode | UnixFileMode.OtherWrite);
                    await RejectAsync(() => updater.InstallAsync(writableCandidate.Document, writableCandidate.Path, writableFixture.Policy, writableFixture.Target, writableService),
                        "A world-writable installation parent cannot supply trusted recovery paths.");
                    Ensure(writableService.Stops == 0 && writableFixture.Code == "previous", "Untrusted installation parent is rejected before lifecycle changes.");
                }
                finally { File.SetUnixFileMode(writableFixture.Root, originalMode); }
            }
            using var fixture = new Fixture();
            var candidate = fixture.Package();
            var service = new FakeLifecycle();
            File.CreateSymbolicLink(Path.Combine(fixture.Target, "linked.dll"), candidate.Path);
            await RejectAsync(() => updater.InstallAsync(candidate.Document, candidate.Path, fixture.Policy, fixture.Target, service), "Installation links are rejected.");
            Ensure(service.Stops == 0 && fixture.Code == "previous", "Existing reparse/link code cannot enter a transaction.");
        }
        using (var fixture = new Fixture())
        {
            Ensure((await updater.RecoverAsync(fixture.Target, fixture.Policy, new FakeLifecycle())).Status == UpdateInstallStatus.NoPendingRecovery,
                "Manual recovery is idempotent when no transaction exists.");
        }
        Console.WriteLine($"Transactional updater tests passed ({assertions} assertions, synthetic archives and service lifecycle only).");
        return assertions;
    }

    private sealed class FakeLifecycle : IServiceUpdateLifecycle
    {
        public int Stops { get; private set; }
        public List<string> Starts { get; } = [];
        public Func<int, CancellationToken, Task>? OnStop { get; init; }
        public Func<string, CancellationToken, Task>? OnStart { get; init; }
        public Func<string, bool>? Health { get; init; }
        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Stops++;
            return OnStop?.Invoke(Stops, cancellationToken) ?? Task.CompletedTask;
        }
        public Task StartAsync(string installationDirectory, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var code = File.ReadAllText(Path.Combine(installationDirectory, "SentinelAI.Agent.exe"));
            Starts.Add(code);
            return OnStart?.Invoke(code, cancellationToken) ?? Task.CompletedTask;
        }
        public Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Health?.Invoke(File.ReadAllText(Path.Combine(installationDirectory, "SentinelAI.Agent.exe"))) ?? true);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "sentinelai-update-tests-" + Guid.NewGuid().ToString("N"));
        public string Target => Path.Combine(Root, "Agent");
        public string Journal => Path.Combine(Root, ".Agent.sentinelai-update.json");
        public string Code => File.ReadAllText(Path.Combine(Target, "SentinelAI.Agent.exe"));
        public UpdateVerificationPolicy Policy { get; }

        public Fixture()
        {
            Directory.CreateDirectory(Target);
            File.WriteAllText(Path.Combine(Target, "SentinelAI.Agent.exe"), "previous");
            Policy = new UpdateVerificationPolicy("development", "stable", "sentinelai-agent-win-x64", "1.0.0",
                new Dictionary<string, string> { ["development-update-test"] = _key.ExportSubjectPublicKeyInfoPem() });
        }

        public (byte[] Document, string Path) Package(string version = "2.0.0", string code = "candidate",
            (string Name, string Contents, int Attributes)[]? extraEntries = null, bool includeExecutable = true)
        {
            var path = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".zip");
            using (var file = File.Create(path))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                if (includeExecutable) WriteEntry(archive, "SentinelAI.Agent.exe", code, 0);
                foreach (var (name, contents, attributes) in extraEntries ?? []) WriteEntry(archive, name, contents, attributes);
            }
            var bytes = File.ReadAllBytes(path);
            var manifest = new UpdateManifest(version, "sentinelai-agent-win-x64", "https://updates.example.invalid/agent.zip",
                Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), bytes.Length, "stable", "development");
            var input = UpdateManifestFormat.CreateSigningData(manifest, "development-update-test");
            var signature = _key.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return (UpdateManifestFormat.SerializeSigned(manifest, "development-update-test", signature), path);
        }

        public void Pending(byte[] document, string phase, string targetCode, bool previous, bool failed, bool workExists)
        {
            var id = Guid.NewGuid().ToString("N");
            var work = Path.Combine(Root, ".Agent.sentinelai-update-" + id);
            if (Directory.Exists(Target)) Directory.Delete(Target, true);
            if (targetCode.Length != 0)
            {
                Directory.CreateDirectory(Target);
                File.WriteAllText(Path.Combine(Target, "SentinelAI.Agent.exe"), targetCode);
            }
            if (workExists) Directory.CreateDirectory(work);
            if (previous)
            {
                Directory.CreateDirectory(Path.Combine(work, "previous"));
                File.WriteAllText(Path.Combine(work, "previous", "SentinelAI.Agent.exe"), "previous");
            }
            if (failed)
            {
                Directory.CreateDirectory(Path.Combine(work, "failed"));
                File.WriteAllText(Path.Combine(work, "failed", "SentinelAI.Agent.exe"), "candidate");
            }
            File.WriteAllText(Journal, JsonSerializer.Serialize(new { format = 1, transaction = id, phase, manifest = Convert.ToBase64String(document) }));
        }

        private static void WriteEntry(ZipArchive archive, string name, string contents, int attributes)
        {
            var entry = archive.CreateEntry(name);
            entry.ExternalAttributes = attributes;
            using var stream = entry.Open();
            stream.Write(Encoding.UTF8.GetBytes(contents));
        }

        public void Dispose()
        {
            _key.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, true);
        }
    }
}
