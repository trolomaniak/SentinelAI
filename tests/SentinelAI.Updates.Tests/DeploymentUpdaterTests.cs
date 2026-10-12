using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updates.Tests;

internal static class DeploymentUpdaterTests
{
    private static readonly string[] Components = ["Core", "Agent", "Desktop", "Updater"];

    internal static async Task<int> RunAsync()
    {
        var assertions = 0;
        void Ensure(bool condition, string message)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException(message);
        }
        async Task RejectAsync(Func<Task> operation, string message)
        {
            assertions++;
            try { await operation(); }
            catch (Exception exception) when (exception is UpdateValidationException or InvalidDataException or IOException or ArgumentException) { return; }
            throw new InvalidOperationException(message);
        }
        var updater = new TransactionalUpdater(TimeSpan.FromMilliseconds(40), TimeSpan.FromMilliseconds(2), TimeSpan.FromSeconds(2));

        using (var fixture = new Fixture())
        {
            var data = Snapshot(fixture.Data);
            var previous = Snapshot(fixture.Target);
            var package = fixture.Package();
            var service = new Lifecycle
            {
                OnStop = (_, _) => { Ensure(Equal(previous, Snapshot(fixture.Target)), "All four old components remain together until the first stop."); return Task.CompletedTask; }
            };
            var result = await updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && result.Version == "2.0.0", "A healthy signed whole deployment commits its version.");
            Ensure(service.Stops == 1 && service.Starts.SequenceEqual(["candidate"]), "Services only start after all four candidate components replace the old root.");
            Ensure(HasGeneration(fixture.Target, "candidate"), "Core, Agent, Desktop, Updater and their companion files advance together.");
            Ensure(Equal(data, Snapshot(fixture.Data)), "Upgrade preserves SQLite, installation identity, enrollment, DPAPI/configuration and license bytes outside code.");
            Ensure(File.ReadAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName)).SequenceEqual(package.Document), "A healthy deployment stores its signed receipt.");
            Ensure(!File.Exists(fixture.Journal) && !fixture.WorkDirectories.Any(), "A committed deployment cleans the whole-code backup and journal.");

            var replayService = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, replayService), "The signed receipt prevents whole-deployment replay under a stale version floor.");
            Ensure(replayService.Stops == 0 && HasGeneration(fixture.Target, "candidate"), "Replay is rejected before any service stop or code replacement.");
            var downgrade = fixture.Package(version: "1.5.0", generation: "older");
            await RejectAsync(() => updater.InstallAsync(downgrade.Document, downgrade.Path, fixture.Policy(), fixture.Target, replayService), "An authenticated installed receipt prevents deployment downgrade even above the stale caller floor.");
            Ensure(replayService.Stops == 0 && Equal(data, Snapshot(fixture.Data)), "A rejected downgrade cannot change services or data.");
        }

        foreach (var version in new[] { "1.0.0", "0.9.0" })
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version);
            var previous = Snapshot(fixture.Target);
            var service = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Normal installation still requires a strictly newer version.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)), "Equal-version/downgrade installation rejection preserves all four components.");
        }

        foreach (var failure in new[] { "start", "health", "cancel" })
        {
            using var fixture = new Fixture();
            using var cancellation = new CancellationTokenSource();
            var previous = Snapshot(fixture.Target);
            var data = Snapshot(fixture.Data);
            var package = fixture.Package();
            var service = new Lifecycle
            {
                Health = generation => failure != "health" || generation == "previous",
                OnStart = (generation, _) =>
                {
                    if (generation != "candidate") return Task.CompletedTask;
                    if (failure == "cancel") cancellation.Cancel();
                    return failure == "start" ? Task.FromException(new IOException("Synthetic deployment start failure.")) : Task.CompletedTask;
                }
            };
            var result = await updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service, cancellation.Token);
            Ensure(result.Status == UpdateInstallStatus.RolledBack && result.FailureCode == (failure == "cancel" ? "cancelled" : "update_failed"), "Failed start, health or cancellation triggers a bounded whole-deployment rollback.");
            Ensure(Equal(previous, Snapshot(fixture.Target)), "Rollback restores every previous component and companion file byte-for-byte.");
            Ensure(service.Stops == 2 && service.Starts.SequenceEqual(["candidate", "previous"]), "Rollback stops replacement services and starts only the complete old deployment.");
            Ensure(Equal(data, Snapshot(fixture.Data)), "Rollback preserves all persistent data and identity bytes.");
            Ensure(!File.Exists(fixture.Journal) && !fixture.WorkDirectories.Any(), "Successful rollback removes its journal and temporary code trees.");
        }

        // A retained failed rollback uses the same authenticated journal/recovery mechanism as legacy artifacts.
        using (var fixture = new Fixture())
        {
            var previous = Snapshot(fixture.Target);
            var data = Snapshot(fixture.Data);
            var package = fixture.Package();
            var service = new Lifecycle
            {
                Health = generation => generation == "previous",
                OnStop = (attempt, _) => attempt == 2 ? Task.FromException(new IOException("Synthetic deployment rollback stop failure.")) : Task.CompletedTask
            };
            var result = await updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.RollbackFailed && File.Exists(fixture.Journal), "A failed deployment rollback is explicit and preserves its journal.");
            Ensure(HasGeneration(fixture.Target, "candidate") && HasGeneration(Path.Combine(fixture.WorkDirectories.Single(), "previous"), "previous"), "A failed stop keeps current and previous whole deployments intact.");
            var recovered = await updater.RecoverAsync(fixture.Target, fixture.Policy(), new Lifecycle());
            Ensure(recovered.Status == UpdateInstallStatus.RolledBack && Equal(previous, Snapshot(fixture.Target)), "An explicit retry restores all four components from the retained transaction.");
            Ensure(Equal(data, Snapshot(fixture.Data)) && !File.Exists(fixture.Journal), "Retried recovery preserves persistent state and cleans the completed journal.");
        }

        foreach (var component in Components)
        {
            using var fixture = new Fixture();
            var data = Snapshot(fixture.Data);
            Directory.Delete(Path.Combine(fixture.Target, component), recursive: true);
            var package = fixture.Package(version: "1.0.0", generation: "repaired");
            var service = new Lifecycle();
            var result = await updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && result.Version == "1.0.0", "Explicit same-version repair accepts a missing owned component directory.");
            Ensure(HasGeneration(fixture.Target, "repaired") && service.Starts.SequenceEqual(["repaired"]), "Repair restores the missing executable and coherent code for every component.");
            Ensure(Equal(data, Snapshot(fixture.Data)), "Repair preserves identity, SQLite, DPAPI/configuration and license state.");
        }

        // A signed installed receipt authorizes only the same authenticated release claims, not arbitrary code at that version.
        using (var fixture = new Fixture())
        {
            var package = fixture.Package();
            await updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, new Lifecycle());
            var data = Snapshot(fixture.Data);
            File.Delete(Path.Combine(fixture.Target, "Desktop", "SentinelAI.Desktop.exe"));
            File.Delete(Path.Combine(fixture.Target, "Core", "SentinelAI.Core.exe"));
            File.WriteAllText(Path.Combine(fixture.Target, "Agent", "dependency.dll"), "synthetic damaged code");
            var resigned = fixture.Sign(package.Path, version: "2.0.0");
            Ensure(!resigned.Document.SequenceEqual(package.Document), "The repair receipt test uses a fresh valid ECDSA signature for unchanged claims.");
            var service = new Lifecycle();
            var result = await updater.RepairAsync(resigned.Document, resigned.Path, fixture.Policy("2.0.0"), fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && HasGeneration(fixture.Target, "candidate"), "Repair authenticates matching claims rather than requiring identical signature bytes.");
            Ensure(service.Starts.SequenceEqual(["candidate"]) && Equal(data, Snapshot(fixture.Data)), "Repair restores missing Core/Desktop and damaged dependencies without resetting data.");
        }

        foreach (var version in new[] { "0.9.0", "1.1.0" })
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version);
            var previous = Snapshot(fixture.Target);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Repair is neither a downgrade nor an upgrade authorization.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)), "Repair rejects a version different from the authoritative installed version before stop.");
        }

        foreach (var receiptMismatch in new[] { "hash", "version", "url", "signature" })
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version: "1.0.0");
            var receipt = receiptMismatch switch
            {
                "hash" => fixture.Package(version: "1.0.0", generation: "different-signed-code").Document,
                "version" => fixture.Sign(package.Path, version: "2.0.0").Document,
                "url" => fixture.Sign(package.Path, version: "1.0.0", artifactUrl: "https://updates.example.invalid/other.zip").Document,
                _ => TamperSignature(package.Document)
            };
            File.WriteAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName), receipt);
            var previous = Snapshot(fixture.Target);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Repair rejects an invalid receipt or mismatched signed release claims.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)), "Receipt mismatch rejects repair before changing existing code or service state.");
        }

        foreach (var invalid in new[] { "hash", "signature", "size", "artifact", "channel", "environment" })
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version: "1.0.0");
            if (invalid == "hash")
            {
                var bytes = File.ReadAllBytes(package.Path);
                bytes[bytes.Length / 2] ^= 1;
                File.WriteAllBytes(package.Path, bytes);
            }
            if (invalid == "signature") package = package with { Document = TamperSignature(package.Document) };
            if (invalid == "size") package = fixture.Sign(package.Path, "1.0.0", sizeOffset: 1);
            if (invalid == "artifact") package = fixture.Sign(package.Path, "1.0.0", artifactId: "sentinelai-agent-win-x64");
            if (invalid == "channel") package = fixture.Sign(package.Path, "1.0.0", channel: "beta");
            if (invalid == "environment") package = fixture.Sign(package.Path, "1.0.0", environment: "production");
            var previous = Snapshot(fixture.Target);
            var data = Snapshot(fixture.Data);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Equal-version repair still verifies signature, exact package hash/size and explicit artifact/channel/environment trust.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)) && Equal(data, Snapshot(fixture.Data)), "Invalid repair inputs leave code and persistent data untouched before stop.");
        }

        foreach (var extra in new[] { "foreign.txt", "Foreign/foreign.dll", "Core/sentinelai.db", "Agent/enrollment-state", "Desktop/installation-id", "Updater/pilot-config.json" })
        {
            using var fixture = new Fixture();
            var path = Path.Combine(fixture.Target, extra.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "synthetic foreign or persistent state");
            var previous = Snapshot(fixture.Target);
            var package = fixture.Package(version: "1.0.0");
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Repair rejects foreign root entries and persistent state inside owned code directories.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)), "Unsafe existing repair roots are preserved before stopping services.");
        }

        foreach (var extra in new (string Name, string Contents, int Attributes)[][]
        {
            [("foreign.txt", "foreign", 0)], [("Foreign/foreign.dll", "foreign", 0)],
            [("Core/sentinelai.db", "synthetic database", 0)], [("Agent/enrollment-state", "synthetic DPAPI state", 0)],
            [("Desktop/installation-id", "synthetic identity", 0)], [(TransactionalUpdater.ReceiptFileName, "forged receipt", 0)],
            [("Core/link.dll", "destination", unchecked((int)0xA0000000))],
            [("Agent/reparse.dll", "x", (int)FileAttributes.ReparsePoint)],
            [("Core/collision.dll", "a", 0), ("Core/COLLISION.DLL", "b", 0)],
            [("Desktop/../escape.exe", "x", 0)], [("Updater/file.dll:stream", "x", 0)]
        })
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version: "1.0.0", extras: extra);
            var previous = Snapshot(fixture.Target);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "The deployment archive rejects foreign roots, persistent state, forged receipt, links, collisions and unsafe paths.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)) && !fixture.WorkDirectories.Any(), "Unsafe repair archive shape is rejected and private staging cleaned before service stop.");
        }

        foreach (var missing in Components)
        {
            using var fixture = new Fixture();
            var package = fixture.Package(omittedComponent: missing);
            var service = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Every new deployment must contain all four exact nonempty executables.");
            Ensure(service.Stops == 0 && HasGeneration(fixture.Target, "previous"), "An incomplete candidate cannot replace any existing component.");
        }
        foreach (var marker in new string?[]
        {
            null, "", "[]", "{", "{\"format\":\"sentinelai-deployment-v1\"}",
            "{\"format\":\"other\",\"version\":\"2.0.0\"}",
            "{\"format\":\"sentinelai-deployment-v1\",\"version\":2}",
            "{\"format\":\"sentinelai-deployment-v1\",\"version\":\"02.0.0\"}",
            "{\"format\":\"sentinelai-deployment-v1\",\"version\":\"2.0.0\",\"unknown\":\"x\"}",
            "{\"format\":\"sentinelai-deployment-v1\",\"version\":\"2.0.0\",\"version\":\"2.0.0\"}",
            "{\"format\":\"sentinelai-deployment-v1\",\"version\":\"1.0.0\"}",
            new string('x', DeploymentPackageVersion.MaximumDocumentBytes + 1)
        })
        {
            using var fixture = new Fixture();
            var previous = Snapshot(fixture.Target);
            var package = fixture.Package(markerContents: marker, omitMarker: marker is null);
            var service = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Missing, malformed or mismatched deployment metadata cannot authorize a signed code replacement.");
            Ensure(service.Stops == 0 && Equal(previous, Snapshot(fixture.Target)) && !fixture.WorkDirectories.Any(), "Version metadata is checked and staging cleaned before any service stop.");
        }

        foreach (var version in new[] { "1.0.0", "2.0.0" })
        {
            using var fixture = new Fixture();
            var data = Snapshot(fixture.Data);
            Directory.Delete(fixture.Target, recursive: true);
            Directory.CreateDirectory(fixture.Target);
            var package = fixture.Package(version, generation: "restored");
            var service = new Lifecycle();
            var result = await updater.RestoreAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service);
            Ensure(result.Status == UpdateInstallStatus.Installed && result.Version == version, "Retained installation restores equal or newer authenticated code against its protected version floor.");
            Ensure(service.Stops == 1 && service.Starts.SequenceEqual(["restored"]) && HasGeneration(fixture.Target, "restored"), "Restoration starts the complete four-component deployment.");
            Ensure(Equal(data, Snapshot(fixture.Data)) && File.ReadAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName)).SequenceEqual(package.Document), "Restoration preserves all retained data and commits authenticated code ownership.");
            Ensure(!File.Exists(fixture.Journal) && !fixture.WorkDirectories.Any(), "Healthy retained restoration cleans its transaction.");
        }
        foreach (var invalid in new[] { "downgrade", "nonempty-file", "nonempty-directory", "missing-target", "signature", "environment" })
        {
            using var fixture = new Fixture();
            Directory.Delete(fixture.Target, recursive: true);
            if (invalid != "missing-target") Directory.CreateDirectory(fixture.Target);
            if (invalid == "nonempty-file") File.WriteAllText(Path.Combine(fixture.Target, "foreign.dll"), "foreign");
            if (invalid == "nonempty-directory") Directory.CreateDirectory(Path.Combine(fixture.Target, "Core"));
            var package = fixture.Package(invalid == "downgrade" ? "0.9.0" : "1.0.0");
            if (invalid == "signature") package = package with { Document = TamperSignature(package.Document) };
            if (invalid == "environment") package = fixture.Sign(package.Path, "1.0.0", environment: "production");
            var previous = Directory.Exists(fixture.Target) ? Snapshot(fixture.Target) : null;
            var data = Snapshot(fixture.Data);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RestoreAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Restoration rejects downgrade, unowned/nonempty targets and invalid signed authority.");
            Ensure(service.Stops == 0 && Equal(data, Snapshot(fixture.Data)) && !fixture.WorkDirectories.Any(), "Rejected restoration leaves services and retained data untouched.");
            Ensure(previous is null ? !Directory.Exists(fixture.Target) : Equal(previous, Snapshot(fixture.Target)), "Restoration never creates or adopts an invalid target.");
        }
        using (var fixture = new Fixture())
        {
            var package = fixture.Package(executableContents: "");
            var service = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Empty deployment executables are rejected.");
            File.Delete(Path.Combine(fixture.Target, "Desktop", "SentinelAI.Desktop.exe"));
            var complete = fixture.Package();
            await RejectAsync(() => updater.InstallAsync(complete.Document, complete.Path, fixture.Policy(), fixture.Target, service), "Upgrade does not silently adopt an incomplete code installation as repair.");
            Ensure(service.Stops == 0, "Both malformed candidate and damaged upgrade target are rejected before stop.");
        }

        // A deployment is larger than one service. Its additive extractor must retain the old extractor's bounds.
        using (var fixture = new Fixture())
        {
            var extras = Enumerable.Range(0, 1100).Select(i => ($"Desktop/dependencies/library{i}.dll", "synthetic code", 0)).ToArray();
            var package = fixture.Package(extras: extras);
            var destination = Path.Combine(fixture.Root, "extracted-deployment");
            await PackageExtractor.ExtractDeploymentAsync(package.Path, destination);
            Ensure(HasGeneration(destination, "candidate") && Directory.EnumerateFiles(Path.Combine(destination, "Desktop", "dependencies")).Count() == 1100, "The deployment-specific extractor accepts a bounded directory runtime above the legacy entry limit.");
            Ensure(PackageExtractor.MaximumEntries == 1024 && PackageExtractor.MaximumExpandedBytes == 512L * 1024 * 1024, "Existing single-component extractor limits remain unchanged.");
            Directory.Delete(destination, recursive: true);
            var oversized = fixture.Package(extras: Enumerable.Range(0, 4096).Select(i => ($"Desktop/library{i}.dll", "x", 0)).ToArray());
            var service = new Lifecycle();
            await RejectAsync(() => updater.InstallAsync(oversized.Document, oversized.Path, fixture.Policy(), fixture.Target, service), "Whole deployments remain bounded to 4096 ZIP entries.");
            Ensure(service.Stops == 0 && !fixture.WorkDirectories.Any(), "Oversized deployment archives reject and clean staging before stop.");
        }

        if (!OperatingSystem.IsWindows())
        {
            using var fixture = new Fixture();
            var package = fixture.Package(version: "1.0.0");
            var outside = Path.Combine(fixture.Data, "protected-config.json");
            var data = Snapshot(fixture.Data);
            File.CreateSymbolicLink(Path.Combine(fixture.Target, "Core", "linked.dll"), outside);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RepairAsync(package.Document, package.Path, fixture.Policy(), fixture.Target, service), "Repair refuses an existing code link even inside a known component.");
            Ensure(service.Stops == 0 && Equal(data, Snapshot(fixture.Data)), "Repair cannot follow code links into persistent state.");
        }

        foreach (var (phase, target, previous, failed, workExists) in new[]
        {
            ("prepared", "previous", false, false, true), ("prepared", "", true, false, true),
            ("backed-up", "", true, false, true), ("backed-up", "candidate", true, false, true),
            ("installed", "candidate", true, false, true), ("installed", "", true, true, true),
            ("restoring", "previous", false, true, true), ("restored", "previous", false, true, true),
            ("rolled-back", "previous", false, false, false)
        })
        {
            using var fixture = new Fixture();
            var data = Snapshot(fixture.Data);
            var oldCode = Snapshot(fixture.Target);
            var package = fixture.Package();
            fixture.Pending(package.Document, phase, target, previous, failed, workExists);
            var service = new Lifecycle();
            var recovered = await updater.RecoverAsync(fixture.Target, fixture.Policy(), service);
            Ensure(recovered.Status == UpdateInstallStatus.RolledBack && Equal(oldCode, Snapshot(fixture.Target)), "The shared journal restores every component across interrupted whole-root rename boundaries.");
            Ensure(service.Starts.SequenceEqual(["previous"]) && Equal(data, Snapshot(fixture.Data)), "Interrupted recovery starts a complete old deployment and preserves data.");
            Ensure(!File.Exists(fixture.Journal) && !fixture.WorkDirectories.Any(), "Recovered deployment transactions remove owned work and journal after health succeeds.");
        }
        using (var fixture = new Fixture())
        {
            var package = fixture.Package();
            fixture.Pending(package.Document, "committed", "candidate", previous: false, failed: false, workExists: false);
            File.WriteAllBytes(Path.Combine(fixture.Target, TransactionalUpdater.ReceiptFileName), package.Document);
            var service = new Lifecycle();
            var result = await updater.RecoverAsync(fixture.Target, fixture.Policy(), service);
            Ensure(result.Status == UpdateInstallStatus.Installed && service.Stops == 0 && HasGeneration(fixture.Target, "candidate"), "Committed whole-deployment recovery finishes cleanup without undoing healthy code.");
            Ensure(!File.Exists(fixture.Journal), "Committed deployment cleanup verifies the exact signed transaction receipt.");
        }
        using (var fixture = new Fixture())
        {
            var package = fixture.Package();
            fixture.Pending(TamperSignature(package.Document), "installed", "candidate", previous: true, failed: false, workExists: true);
            var journal = File.ReadAllBytes(fixture.Journal);
            var service = new Lifecycle();
            await RejectAsync(() => updater.RecoverAsync(fixture.Target, fixture.Policy(), service), "An unauthenticated journal cannot authorize whole-deployment recovery.");
            Ensure(service.Stops == 0 && HasGeneration(fixture.Target, "candidate") && File.ReadAllBytes(fixture.Journal).SequenceEqual(journal), "Rejected journal authentication preserves running components and recovery evidence.");
            Ensure(HasGeneration(Path.Combine(fixture.WorkDirectories.Single(), "previous"), "previous"), "Rejected journal authentication preserves every old backup component.");
        }

        Console.WriteLine($"Deployment updater tests passed ({assertions} assertions, generated temporary keys, synthetic code/data and service lifecycle only).");
        return assertions;
    }

    private static byte[] TamperSignature(byte[] document)
    {
        var json = Encoding.UTF8.GetString(document);
        const string marker = "\"signature\":\"";
        var start = json.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        if (start < marker.Length) throw new InvalidOperationException("Synthetic manifest has no signature.");
        return Encoding.UTF8.GetBytes(json[..start] + (json[start] == 'A' ? 'B' : 'A') + json[(start + 1)..]);
    }

    private static Dictionary<string, byte[]> Snapshot(string directory) => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
        .ToDictionary(path => Path.GetRelativePath(directory, path), File.ReadAllBytes, StringComparer.Ordinal);

    private static bool Equal(Dictionary<string, byte[]> left, Dictionary<string, byte[]> right) => left.Count == right.Count &&
        left.All(pair => right.TryGetValue(pair.Key, out var bytes) && pair.Value.SequenceEqual(bytes));

    private static bool HasGeneration(string directory, string generation) => Components.All(component =>
        File.ReadAllText(Path.Combine(directory, component, $"SentinelAI.{component}.exe")) == generation &&
        File.ReadAllText(Path.Combine(directory, component, "dependency.dll")) == generation + " dependency");

    private sealed class Lifecycle : IServiceUpdateLifecycle
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
            var generation = File.ReadAllText(Path.Combine(installationDirectory, "Core", "SentinelAI.Core.exe"));
            if (!HasGeneration(installationDirectory, generation)) throw new IOException("The synthetic service observed mixed component generations.");
            Starts.Add(generation);
            return OnStart?.Invoke(generation, cancellationToken) ?? Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var generation = File.ReadAllText(Path.Combine(installationDirectory, "Core", "SentinelAI.Core.exe"));
            return Task.FromResult(HasGeneration(installationDirectory, generation) && (Health?.Invoke(generation) ?? true));
        }
    }

    private sealed record Candidate(byte[] Document, string Path);

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private const string KeyId = "development-deployment-test";
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "sentinelai-deployment-update-tests-" + Guid.NewGuid().ToString("N"));
        public string Target => Path.Combine(Root, "SentinelAI");
        public string Data => Path.Combine(Root, "Data");
        public string Journal => Path.Combine(Root, ".SentinelAI.sentinelai-update.json");
        public IEnumerable<string> WorkDirectories => Directory.EnumerateDirectories(Root, ".SentinelAI.sentinelai-update-*");

        public Fixture()
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(Root);
            else Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            WriteCode(Target, "previous");
            foreach (var path in new[] { "Core/sentinelai.db", "installation-id", "Agent/endpoint-id", "Agent/enrollment-state", "protected-config.json", "license-state.json" })
            {
                var file = Path.Combine(Data, path.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllText(file, "synthetic persistent " + path);
            }
        }

        public UpdateVerificationPolicy Policy(string installedVersion = "1.0.0") => new("development", "stable", "sentinelai-deployment-win-x64", installedVersion,
            new Dictionary<string, string> { [KeyId] = _key.ExportSubjectPublicKeyInfoPem() });

        public Candidate Package(string version = "2.0.0", string generation = "candidate",
            (string Name, string Contents, int Attributes)[]? extras = null, string? omittedComponent = null, string? executableContents = null,
            string? markerContents = null, bool omitMarker = false)
        {
            var path = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".zip");
            using (var file = File.Create(path))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                if (!omitMarker) WriteEntry(archive, DeploymentPackageVersion.FileName,
                    markerContents ?? JsonSerializer.Serialize(new { format = DeploymentPackageVersion.Format, version }), 0);
                foreach (var component in Components.Where(component => component != omittedComponent))
                {
                    WriteEntry(archive, $"{component}/SentinelAI.{component}.exe", executableContents ?? generation, 0);
                    WriteEntry(archive, $"{component}/dependency.dll", generation + " dependency", 0);
                }
                foreach (var (name, contents, attributes) in extras ?? []) WriteEntry(archive, name, contents, attributes);
            }
            return Sign(path, version);
        }

        public Candidate Sign(string path, string version, string artifactUrl = "https://updates.example.invalid/deployment.zip", long sizeOffset = 0,
            string artifactId = "sentinelai-deployment-win-x64", string channel = "stable", string environment = "development")
        {
            var bytes = File.ReadAllBytes(path);
            var manifest = new UpdateManifest(version, artifactId, artifactUrl,
                Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), bytes.Length + sizeOffset, channel, environment);
            var signature = _key.SignData(UpdateManifestFormat.CreateSigningData(manifest, KeyId), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new Candidate(UpdateManifestFormat.SerializeSigned(manifest, KeyId, signature), path);
        }

        public void Pending(byte[] document, string phase, string targetGeneration, bool previous, bool failed, bool workExists)
        {
            var id = Guid.NewGuid().ToString("N");
            var work = Path.Combine(Root, ".SentinelAI.sentinelai-update-" + id);
            Directory.Delete(Target, recursive: true);
            if (targetGeneration.Length != 0) WriteCode(Target, targetGeneration);
            if (workExists) Directory.CreateDirectory(work);
            if (previous) WriteCode(Path.Combine(work, "previous"), "previous");
            if (failed) WriteCode(Path.Combine(work, "failed"), "candidate");
            File.WriteAllText(Journal, JsonSerializer.Serialize(new { format = 1, transaction = id, phase, manifest = Convert.ToBase64String(document) }));
        }

        private static void WriteCode(string directory, string generation)
        {
            foreach (var component in Components)
            {
                Directory.CreateDirectory(Path.Combine(directory, component));
                File.WriteAllText(Path.Combine(directory, component, $"SentinelAI.{component}.exe"), generation);
                File.WriteAllText(Path.Combine(directory, component, "dependency.dll"), generation + " dependency");
            }
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
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
