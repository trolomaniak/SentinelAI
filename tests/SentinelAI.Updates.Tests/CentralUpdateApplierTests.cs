using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Updater;

namespace SentinelAI.Updates.Tests;

/// <summary>
/// MVP-7: the SYSTEM side of the optional central update. In-memory development keys, synthetic Setup bytes and a
/// scripted host only; the staged files stand for what Core, which can write there, downloaded.
/// </summary>
internal static class CentralUpdateApplierTests
{
    internal static async Task<int> RunAsync()
    {
        var assertions = 0;
        void Ensure(bool condition, string message)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException(message);
        }

        using (var fixture = new Fixture())
        {
            var host = new Host(fixture.Layout);
            var applier = new CentralUpdateApplier(fixture.Layout, host, TimeProvider.System);
            Ensure(await applier.ApplyAsync(true, CancellationToken.None) == CentralUpdateOutcome.NoUpdate && host.Calls.Count == 0,
                "Nothing downloaded must change nothing.");

            fixture.Stage("1.1.0");
            File.Delete(fixture.Layout.AutoInstallMarker);
            Ensure(await applier.ApplyAsync(true, CancellationToken.None) == CentralUpdateOutcome.NotScheduled && host.Calls.Count == 0,
                "The night-time task ran a Setup while automatic installation was off.");

            File.WriteAllBytes(fixture.Layout.AutoInstallMarker, []);
            Ensure(await applier.ApplyAsync(true, CancellationToken.None) == CentralUpdateOutcome.Started &&
                   host.Calls.SequenceEqual(["run", "state", "close-desktop", "start-quiet"]) &&
                   File.ReadAllBytes(host.Started!).AsSpan().SequenceEqual(fixture.Package) && fixture.Attempts() == 1,
                "The night-time task did not run the verified copy quietly after closing Desktop.");
            Ensure(File.Exists(fixture.Layout.StagedPackage) && File.Exists(fixture.Layout.StagedManifest),
                "The update task deleted from Core's data directory.");

            host.Calls.Clear();
            Ensure(await applier.ApplyAsync(false, CancellationToken.None) == CentralUpdateOutcome.Started &&
                   host.Calls.SequenceEqual(["run", "state", "start-window"]) && fixture.Attempts() == 2,
                "Install from Desktop did not open the verified Setup.");

            await applier.ApplyAsync(true, CancellationToken.None);
            host.Calls.Clear();
            Ensure(await applier.ApplyAsync(true, CancellationToken.None) == CentralUpdateOutcome.GivenUp && host.Calls.Count == 0,
                "The night-time task tried a release more than three times.");
            Ensure(await applier.ApplyAsync(false, CancellationToken.None) == CentralUpdateOutcome.Started,
                "Install from Desktop was refused after the night-time attempts.");

            // A different release starts counting again.
            fixture.Stage("1.2.0");
            host.Calls.Clear();
            Ensure(await applier.ApplyAsync(true, CancellationToken.None) == CentralUpdateOutcome.Started && fixture.Attempts() == 1,
                "A later release inherited an earlier release's attempts.");

            fixture.Stage("1.0.0");
            host.Calls.Clear();
            Ensure(await applier.ApplyAsync(false, CancellationToken.None) == CentralUpdateOutcome.NoUpdate && host.Calls.Count == 0,
                "A Setup that is not newer was run.");
        }

        foreach (var (label, prepare) in new (string, Action<Fixture>)[]
                 {
                     ("a tampered Setup", fixture => { fixture.Stage("1.1.0"); fixture.Tamper(); }),
                     ("a foreign key", fixture => fixture.Stage("1.1.0", foreignKey: true)),
                     ("another channel", fixture => fixture.Stage("1.1.0", channel: "beta")),
                     ("a deployment package", fixture => fixture.Stage("1.1.0", artifactId: "sentinelai-deployment-win-x64")),
                     ("a linked download folder", fixture => { fixture.Stage("1.1.0"); fixture.LinkStaging(); })
                 })
        {
            using var fixture = new Fixture();
            prepare(fixture);
            var host = new Host(fixture.Layout);
            var outcome = await new CentralUpdateApplier(fixture.Layout, host, TimeProvider.System).ApplyAsync(false, CancellationToken.None);
            Ensure(outcome == CentralUpdateOutcome.Rejected && host.Started is null && fixture.Attempts() == 0, $"The update task ran {label}.");
        }

        foreach (var (label, receipt) in new (string, string)[]
                 {
                     ("production trust", """{"format":"sentinelai-setup-v1","keyId":"dev-test","environment":"production","channel":"pilot"}"""),
                     ("a non-development key", """{"format":"sentinelai-setup-v1","keyId":"prod-test","environment":"development","channel":"pilot"}"""),
                     ("another format", """{"format":"sentinelai-agent-setup-v1","keyId":"dev-test","environment":"development","channel":"pilot"}"""),
                     ("no channel", """{"format":"sentinelai-setup-v1","keyId":"dev-test","environment":"development"}""")
                 })
        {
            using var fixture = new Fixture();
            File.WriteAllText(fixture.Layout.Receipt, receipt);
            fixture.Stage("1.1.0");
            var host = new Host(fixture.Layout);
            var rejected = false;
            try { await new CentralUpdateApplier(fixture.Layout, host, TimeProvider.System).ApplyAsync(false, CancellationToken.None); }
            catch (InvalidDataException) { rejected = true; }
            Ensure(rejected && host.Started is null, $"A Setup receipt with {label} was trusted.");
        }

        Console.WriteLine($"Central update installation tests passed ({assertions} assertions: night-time switch, quiet run after closing Desktop, " +
                          "Install from Desktop, three attempts per release, not newer, tampered, foreign, other channel, other artifact, linked folder, strict receipt).");
        return assertions;
    }

    private sealed class Host(CentralUpdateLayout layout) : ICentralUpdateHost
    {
        public List<string> Calls { get; } = [];
        public string? Started { get; private set; }

        public string CreateRunDirectory()
        {
            Calls.Add("run");
            var run = Path.Combine(layout.WorkRoot, "run-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(run);
            return run;
        }

        public void WriteState(byte[] document)
        {
            Calls.Add("state");
            File.WriteAllBytes(layout.StateFile, document);
        }

        public void CloseDesktop() => Calls.Add("close-desktop");

        public void StartSetup(string executable, bool quiet)
        {
            Calls.Add(quiet ? "start-quiet" : "start-window");
            Started = executable;
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly string _root = Path.Combine(Path.GetTempPath(), "sentinelai-central-update-" + Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            Layout = new CentralUpdateLayout(Path.Combine(_root, "ProgramData"), Path.Combine(_root, "Program Files"));
            Directory.CreateDirectory(Path.GetDirectoryName(Layout.Receipt)!);
            Directory.CreateDirectory(Path.GetDirectoryName(Layout.CoreReceipt)!);
            Directory.CreateDirectory(Layout.WorkRoot);
            File.WriteAllText(Layout.Receipt, """{"format":"sentinelai-setup-v1","keyId":"dev-test","environment":"development","channel":"pilot","desktopDirectory":"x","updaterDirectory":"y","desktopSha256":"0","updaterSha256":"0"}""");
            File.WriteAllText(Layout.PublicKey, _key.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(Layout.CoreReceipt, """{"format":"sentinelai-pilot-v1","component":"Core","version":"1.0.0","channel":"pilot"}""");
        }

        public CentralUpdateLayout Layout { get; }
        public byte[] Package { get; private set; } = [];

        public int Attempts()
        {
            if (!File.Exists(Layout.StateFile)) return 0;
            using var document = JsonDocument.Parse(File.ReadAllBytes(Layout.StateFile));
            return document.RootElement.GetProperty("attempts").GetInt32();
        }

        public void Stage(string version, bool foreignKey = false, string channel = "pilot", string artifactId = CentralUpdateApplier.ArtifactId)
        {
            Directory.CreateDirectory(Layout.Staging);
            Package = Encoding.UTF8.GetBytes("synthetic SentinelAI Setup " + version + " " + Guid.NewGuid().ToString("N"));
            File.WriteAllBytes(Layout.StagedPackage, Package);
            File.WriteAllBytes(Layout.AutoInstallMarker, []);
            var manifest = new UpdateManifest(version, artifactId, "https://updates.example.invalid/sentinelai/" + version + "/SentinelAI-Setup.exe",
                Convert.ToHexStringLower(SHA256.HashData(Package)), Package.Length, channel, "development");
            using var signer = foreignKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
            var signature = (signer ?? _key).SignData(UpdateManifestFormat.CreateSigningData(manifest, "dev-test"),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            File.WriteAllBytes(Layout.StagedManifest, UpdateManifestFormat.SerializeSigned(manifest, "dev-test", signature));
        }

        public void Tamper()
        {
            var bytes = File.ReadAllBytes(Layout.StagedPackage);
            bytes[bytes.Length / 2] ^= 0x01;
            File.WriteAllBytes(Layout.StagedPackage, bytes);
        }

        /// <summary>Core's download folder replaced by a link to a copy elsewhere.</summary>
        public void LinkStaging()
        {
            var elsewhere = Path.Combine(_root, "elsewhere");
            Directory.Move(Layout.Staging, elsewhere);
            Directory.CreateSymbolicLink(Layout.Staging, elsewhere);
        }

        public void Dispose()
        {
            _key.Dispose();
            if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        }
    }
}
