using System.IO.Compression;
using System.Security.Cryptography;
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
                          "no deletes in the Agent's data, tampered, foreign, other channel, other artifact, linked staging, rollback retried three times, strict receipt).");
        return assertions;
    }

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
