using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using SentinelAI.Updater;

namespace SentinelAI.Updates.Tests;

/// <summary>
/// MVP-7: the SYSTEM side of an automatic Agent update. Generated in-memory development keys, synthetic code and a
/// scripted service only; the staged files stand for what a LocalService Agent could have written.
/// </summary>
internal static class AgentUpdateApplierTests
{
    internal static async Task<int> RunAsync()
    {
        var assertions = 0;
        void Ensure(bool condition, string message)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException(message);
        }

        var updater = new TransactionalUpdater(TimeSpan.FromMilliseconds(40), TimeSpan.FromMilliseconds(2), TimeSpan.FromSeconds(2));
        using (var fixture = new Fixture())
        {
            var service = new Service();
            var recorded = new List<string>();
            var applier = new AgentUpdateApplier(fixture.Layout, service, updater, recorded.Add);
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.NoUpdate && service.Stops == 0,
                "Nothing staged must change nothing.");

            fixture.Stage("1.0.0", "same");
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.NoUpdate && fixture.Code == "previous" &&
                   service.Stops == 0, "A staged package that is not newer must not be installed.");

            fixture.Stage("1.1.0", "candidate");
            var before = fixture.ReceiptFields();
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.Installed && fixture.Code == "candidate" &&
                   service.Stops == 1 && recorded.SequenceEqual(["1.1.0"]), "A newer signed Agent package was not installed.");
            var after = fixture.ReceiptFields();
            Ensure(after["version"] == "1.1.0" && after.Count == before.Count &&
                   before.Where(field => field.Key != "version").All(field => after[field.Key] == field.Value),
                "Only the receipt's version may change.");
            Ensure(File.Exists(fixture.Layout.StagedManifest) && File.Exists(fixture.Layout.StagedPackage),
                "The SYSTEM updater must never delete from the Agent's data directory.");
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.NoUpdate && service.Stops == 1,
                "An installed update must not be installed again.");
        }

        using (var fixture = new Fixture())
        {
            fixture.Stage("1.1.0", "candidate");
            var original = File.ReadAllBytes(fixture.Layout.Receipt);
            string? permissions = null;
            string[]? accessRules = null;
            UnixFileMode mode = 0;
            if (OperatingSystem.IsWindows())
            {
                // Match Agent Setup's receipt, not an inherited Windows temp ACL:
                // inheritance is blocked and only Administrators/SYSTEM may access it.
                var protectedAccess = new FileSecurity();
                protectedAccess.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (var sid in new[] { "S-1-5-32-544", "S-1-5-18" })
                    protectedAccess.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                        FileSystemRights.FullControl, AccessControlType.Allow));
                new FileInfo(fixture.Layout.Receipt).SetAccessControl(protectedAccess);
                var before = new FileInfo(fixture.Layout.Receipt).GetAccessControl(AccessControlSections.Access);
                permissions = before.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                accessRules = before.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                    .Select(DescribeAccessRule)
                    .Order(StringComparer.Ordinal).ToArray();
                Ensure(before.AreAccessRulesProtected && before.AreAccessRulesCanonical && accessRules.Length == 2,
                    "The Windows receipt fixture does not match Setup's protected access policy.");
            }
            else
            {
                mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                File.SetUnixFileMode(fixture.Layout.Receipt, mode);
            }
            // Readers that already opened the ownership proof must continue to
            // see a complete old document while new readers see the new one.
            using var reader = new FileStream(fixture.Layout.Receipt, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var service = new Service();
            var applier = new AgentUpdateApplier(fixture.Layout, service, updater);
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.Installed,
                "A concurrent reader must not prevent atomic receipt publication.");
            var observed = new byte[checked((int)reader.Length)];
            reader.ReadExactly(observed);
            Ensure(observed.SequenceEqual(original) && fixture.ReceiptFields()["version"] == "1.1.0",
                "Receipt replacement exposed a truncated or partially rewritten ownership proof.");
            if (OperatingSystem.IsWindows())
            {
                var after = new FileInfo(fixture.Layout.Receipt).GetAccessControl(AccessControlSections.Access);
                var actualRules = after.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                    .Select(DescribeAccessRule)
                    .Order(StringComparer.Ordinal).ToArray();
                // Compare every authority-bearing field. Windows can normalize the
                // descriptor's auto-inheritance bookkeeping without changing rights.
                var actualPermissions = after.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                var expectedPermissions = permissions!;
                Ensure(after.AreAccessRulesProtected && after.AreAccessRulesCanonical && actualRules.SequenceEqual(accessRules!),
                    "Atomic receipt replacement changed its protected Windows access policy. Before=" +
                    expectedPermissions[..Math.Min(expectedPermissions.Length, 1024)] + "; After=" +
                    actualPermissions[..Math.Min(actualPermissions.Length, 1024)]);
            }
            else
                Ensure(File.GetUnixFileMode(fixture.Layout.Receipt) == mode,
                    "Atomic receipt replacement changed its file permissions.");
            Ensure(!Directory.EnumerateFiles(Path.GetDirectoryName(fixture.Layout.Receipt)!, "*.tmp").Any(),
                "Receipt publication left a temporary ownership document.");

            // Simulate interruption after the signed code commit but before the
            // ownership receipt was published: a later run reconciles the old proof.
            File.WriteAllBytes(fixture.Layout.Receipt, original);
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.NoUpdate &&
                   fixture.ReceiptFields()["version"] == "1.1.0" && service.Stops == 1,
                "An interrupted ownership receipt publication did not reconcile from the signed installed receipt.");
        }

        if (!OperatingSystem.IsWindows())
        {
            using var fixture = new Fixture();
            fixture.Stage("1.1.0", "candidate");
            var original = File.ReadAllBytes(fixture.Layout.Receipt);
            var directory = Path.GetDirectoryName(fixture.Layout.Receipt)!;
            var mode = File.GetUnixFileMode(directory);
            var service = new Service();
            var applier = new AgentUpdateApplier(fixture.Layout, service, updater);
            try
            {
                // A protected directory that temporarily refuses new files makes
                // publication fail after the code transaction has committed.
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
                var failed = false;
                try { await applier.ApplyAsync(CancellationToken.None); }
                catch (UnauthorizedAccessException) { failed = true; }
                Ensure(failed && fixture.Code == "candidate" && File.ReadAllBytes(fixture.Layout.Receipt).SequenceEqual(original),
                    "A failed receipt publication must retain the complete previous ownership proof.");
            }
            finally { File.SetUnixFileMode(directory, mode); }
            Ensure(await applier.ApplyAsync(CancellationToken.None) == AgentUpdateOutcome.NoUpdate &&
                   fixture.ReceiptFields()["version"] == "1.1.0" && service.Stops == 1,
                "Retry after failed receipt publication must reconcile without installing the code again.");
        }

        using (var fixture = new Fixture())
        {
            fixture.Stage("1.1.0", "candidate");
            var original = File.ReadAllBytes(fixture.Layout.Receipt);
            var service = new Service();
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            var cancelled = false;
            try { await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(cancellation.Token); }
            catch (OperationCanceledException) { cancelled = true; }
            Ensure(cancelled && service.Stops == 0 && File.ReadAllBytes(fixture.Layout.Receipt).SequenceEqual(original),
                "Cancellation must preserve a complete ownership proof without stopping the Agent.");
        }

        foreach (var (label, prepare) in new (string, Action<Fixture>)[]
                 {
                     ("a tampered package", fixture => { fixture.Stage("1.1.0", "candidate"); fixture.TamperPackage(); }),
                     ("a foreign key", fixture => fixture.Stage("1.1.0", "candidate", foreignKey: true)),
                     ("another channel", fixture => fixture.Stage("1.1.0", "candidate", channel: "beta")),
                     ("a Core package", fixture => fixture.Stage("1.1.0", "candidate", artifactId: "sentinelai-core-win-x64")),
                     ("a linked staging folder", fixture => { fixture.Stage("1.1.0", "candidate"); fixture.LinkStaging(); })
                 })
        {
            using var fixture = new Fixture();
            prepare(fixture);
            var service = new Service();
            var outcome = await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(CancellationToken.None);
            Ensure(outcome is AgentUpdateOutcome.Rejected or AgentUpdateOutcome.NoUpdate && service.Stops == 0 &&
                   fixture.Code == "previous" && fixture.ReceiptFields()["version"] == "1.0.0",
                $"The SYSTEM updater acted on {label}.");
        }

        using (var fixture = new Fixture())
        {
            fixture.Stage("1.1.0", "broken");
            var service = new Service { Healthy = code => code != "broken" };
            Ensure(await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(CancellationToken.None) ==
                   AgentUpdateOutcome.RolledBack && fixture.Code == "previous" && fixture.ReceiptFields()["version"] == "1.0.0" &&
                   service.Starts.SequenceEqual(["broken", "previous"]), "An unhealthy update was not rolled back.");
            for (var attempt = 2; attempt <= AgentUpdateApplier.MaximumAttempts; attempt++)
                Ensure(await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(CancellationToken.None) ==
                       AgentUpdateOutcome.RolledBack && fixture.Code == "previous", "A one-off failure must be retried.");
            var stops = service.Stops;
            Ensure(await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(CancellationToken.None) ==
                   AgentUpdateOutcome.NotRetried && service.Stops == stops && fixture.Code == "previous",
                "A release that keeps rolling back must not restart the Agent again at every run.");
            fixture.Stage("1.2.0", "fixed");
            Ensure(await new AgentUpdateApplier(fixture.Layout, service, updater).ApplyAsync(CancellationToken.None) ==
                   AgentUpdateOutcome.Installed && fixture.Code == "fixed" && !File.Exists(fixture.Layout.RolledBack),
                "A later release was blocked by an earlier rollback.");
        }

        foreach (var (label, receipt) in new (string, string)[]
                 {
                     ("an extra field", """{"format":"sentinelai-agent-setup-v1","version":"1.0.0","keyId":"dev-test","environment":"development","channel":"pilot","coreUrl":"https://core.example.invalid:5443","extra":"x"}"""),
                     ("production trust", """{"format":"sentinelai-agent-setup-v1","version":"1.0.0","keyId":"dev-test","environment":"production","channel":"pilot","coreUrl":"https://core.example.invalid:5443"}"""),
                     ("a non-string value", """{"format":"sentinelai-agent-setup-v1","version":1,"keyId":"dev-test","environment":"development","channel":"pilot","coreUrl":"https://core.example.invalid:5443"}""")
                 })
        {
            using var fixture = new Fixture();
            File.WriteAllText(fixture.Layout.Receipt, receipt);
            fixture.Stage("1.1.0", "candidate");
            var rejected = false;
            try { await new AgentUpdateApplier(fixture.Layout, new Service(), updater).ApplyAsync(CancellationToken.None); }
            catch (InvalidDataException) { rejected = true; }
            Ensure(rejected && fixture.Code == "previous", $"An Agent Setup receipt with {label} was trusted.");
        }

        Console.WriteLine($"Agent update installation tests passed ({assertions} assertions: newer only, exact receipt update, " +
                          "atomic protected receipt and recovery, cancellation, no deletes in the Agent's data, tampered, foreign, " +
                          "other channel, other artifact, linked staging, rollback retried three times, strict receipt).");
        return assertions;
    }

    [SupportedOSPlatform("windows")]
    private static string DescribeAccessRule(FileSystemAccessRule rule) =>
        $"{rule.IdentityReference.Value}|{rule.AccessControlType}|{(int)rule.FileSystemRights}|{rule.InheritanceFlags}|{rule.PropagationFlags}|{rule.IsInherited}";

    private sealed class Service : IServiceUpdateLifecycle
    {
        public int Stops { get; private set; }
        public List<string> Starts { get; } = [];
        public Func<string, bool>? Healthy { get; init; }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Stops++;
            return Task.CompletedTask;
        }

        public Task StartAsync(string installationDirectory, CancellationToken cancellationToken)
        {
            Starts.Add(File.ReadAllText(Path.Combine(installationDirectory, "SentinelAI.Agent.exe")));
            return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken cancellationToken) =>
            Task.FromResult(Healthy?.Invoke(File.ReadAllText(Path.Combine(installationDirectory, "SentinelAI.Agent.exe"))) ?? true);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly string _root = Path.Combine(Path.GetTempPath(), "sentinelai-agent-update-" + Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            Layout = new AgentUpdateLayout(Path.Combine(_root, "code"), Path.Combine(_root, "data"));
            Directory.CreateDirectory(Layout.AgentCode);
            File.WriteAllText(Path.Combine(Layout.AgentCode, "SentinelAI.Agent.exe"), "previous");
            Directory.CreateDirectory(Path.GetDirectoryName(Layout.Receipt)!);
            File.WriteAllText(Layout.Receipt, """{"format":"sentinelai-agent-setup-v1","version":"1.0.0","keyId":"dev-test","environment":"development","channel":"pilot","coreUrl":"https://core.example.invalid:5443"}""");
            File.WriteAllText(Layout.PublicKey, _key.ExportSubjectPublicKeyInfoPem());
        }

        public AgentUpdateLayout Layout { get; }
        public string Code => File.ReadAllText(Path.Combine(Layout.AgentCode, "SentinelAI.Agent.exe"));

        public Dictionary<string, string> ReceiptFields() =>
            JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(Layout.Receipt))!;

        public void Stage(string version, string code, bool foreignKey = false, string channel = "pilot",
            string artifactId = AgentUpdateApplier.ArtifactId)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Layout.StagedPackage)!);
            using (var file = File.Create(Layout.StagedPackage))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                var name = artifactId == AgentUpdateApplier.ArtifactId ? "SentinelAI.Agent.exe" : "SentinelAI.Core.exe";
                using var entry = archive.CreateEntry(name).Open();
                entry.Write(Encoding.UTF8.GetBytes(code));
            }

            var bytes = File.ReadAllBytes(Layout.StagedPackage);
            var manifest = new UpdateManifest(version, artifactId, "https://updates.example.invalid/agent.zip",
                Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length, channel, "development");
            using var signer = foreignKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
            var signature = (signer ?? _key).SignData(UpdateManifestFormat.CreateSigningData(manifest, "dev-test"),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            File.WriteAllBytes(Layout.StagedManifest, UpdateManifestFormat.SerializeSigned(manifest, "dev-test", signature));
        }

        public void TamperPackage()
        {
            var bytes = File.ReadAllBytes(Layout.StagedPackage);
            bytes[bytes.Length / 2] ^= 0x01;
            File.WriteAllBytes(Layout.StagedPackage, bytes);
        }

        /// <summary>The Agent's update folder replaced by a link to a copy elsewhere.</summary>
        public void LinkStaging()
        {
            var staging = Path.GetDirectoryName(Layout.StagedPackage)!;
            var elsewhere = Path.Combine(_root, "elsewhere");
            Directory.Move(staging, elsewhere);
            Directory.CreateSymbolicLink(staging, elsewhere);
        }

        public void Dispose()
        {
            _key.Dispose();
            if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        }
    }
}
