using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.UpdateDev;
using SentinelAI.Updater;

namespace SentinelAI.Updates.Tests;

internal static class CommandTests
{
    private static int _assertions;
    private const string KeyId = "dev-command-test";
    private const string ArtifactId = "sentinelai-agent-win-x64";
    private const string ArtifactUrl = "https://updates.example.test/agent/1.2.3.zip";

    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-update-command-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var keysDirectory = Path.Combine(directory, "keys");
            var privateKey = Path.Combine(keysDirectory, KeyId + ".private.pem");
            var publicKey = Path.Combine(keysDirectory, KeyId + ".public.pem");
            var package = Path.Combine(directory, "agent.zip");
            var manifest = Path.Combine(directory, "manifest.json");
            await CreatePackageAsync(package);
            var packageBytes = await File.ReadAllBytesAsync(package);

            var generated = await RunDevAsync(["keygen", "--directory", keysDirectory, "--key-id", KeyId]);
            Ensure(generated.ExitCode == 0 && File.Exists(privateKey) && File.Exists(publicKey),
                "Development key generation did not create the separate key files.");
            EnsureNoSecrets(generated, privateKey);
            using (var key = ECDsa.Create())
            {
                key.ImportFromPem(await File.ReadAllTextAsync(publicKey));
                Ensure(key.KeySize == 256 && key.ExportParameters(false).Curve.Oid.Value == "1.2.840.10045.3.1.7",
                    "Development public key is not a P-256 key.");
            }
            if (!OperatingSystem.IsWindows())
            {
                Ensure(File.GetUnixFileMode(privateKey) == (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                    "Development private key permissions are not restricted to its owner.");
                Ensure(File.GetUnixFileMode(keysDirectory) ==
                       (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
                    "Development key directory permissions are not restricted to its owner.");
            }

            var privateBytes = await File.ReadAllBytesAsync(privateKey);
            var publicBytes = await File.ReadAllBytesAsync(publicKey);
            var regenerated = await RunDevAsync(["keygen", "--directory", keysDirectory, "--key-id", KeyId]);
            EnsureRejected(regenerated, privateKey);
            Ensure((await File.ReadAllBytesAsync(privateKey)).SequenceEqual(privateBytes) &&
                   (await File.ReadAllBytesAsync(publicKey)).SequenceEqual(publicBytes),
                "Repeated key generation overwrote an existing key.");

            var signingArguments = SignArguments(privateKey, package, manifest);
            var signed = await RunDevAsync(signingArguments);
            Ensure(signed.ExitCode == 0 && File.Exists(manifest), "Development signing did not create a manifest.");
            EnsureNoSecrets(signed, privateKey);
            using (var document = JsonDocument.Parse(await File.ReadAllBytesAsync(manifest)))
            {
                var metadata = document.RootElement.GetProperty("manifest");
                Ensure(metadata.GetProperty("environment").GetString() == "development" &&
                       metadata.GetProperty("channel").GetString() == "stable" &&
                       metadata.GetProperty("version").GetString() == "1.2.3" &&
                       metadata.GetProperty("artifactId").GetString() == ArtifactId &&
                       metadata.GetProperty("artifactUrl").GetString() == ArtifactUrl,
                    "Development signing did not authenticate the explicit update metadata.");
                Ensure(metadata.GetProperty("sizeBytes").GetInt64() == new FileInfo(package).Length &&
                       metadata.GetProperty("sha256").GetString() ==
                       Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(package))).ToLowerInvariant(),
                    "Development manifest does not bind the package bytes.");
                Ensure(document.RootElement.GetProperty("keyId").GetString() == KeyId &&
                       document.RootElement.GetProperty("signature").GetString() is { Length: > 0 },
                    "Development manifest is missing its signature or key identifier.");
            }

            var manifestBytes = await File.ReadAllBytesAsync(manifest);
            EnsureRejected(await RunDevAsync(signingArguments), privateKey);
            Ensure((await File.ReadAllBytesAsync(manifest)).SequenceEqual(manifestBytes),
                "Signing overwrote an existing manifest.");

            var verifyingArguments = ClientArguments("verify", manifest, package, publicKey);
            var entriesBeforeVerification = Directory.GetFileSystemEntries(directory, "*", SearchOption.AllDirectories)
                .Order(StringComparer.Ordinal).ToArray();
            var verified = await RunClientAsync(verifyingArguments);
            EnsureVerified(verified, privateKey);
            Ensure((await File.ReadAllBytesAsync(package)).SequenceEqual(packageBytes) &&
                   Directory.GetFileSystemEntries(directory, "*", SearchOption.AllDirectories)
                       .Order(StringComparer.Ordinal).SequenceEqual(entriesBeforeVerification),
                "Verification changed the package or created installation state.");

            var stagedPackage = Path.Combine(directory, "staged.zip");
            var stagingArguments = ClientArguments("stage", manifest, package, publicKey)
                .Concat(["--output", stagedPackage]).ToArray();
            EnsureVerified(await RunClientAsync(stagingArguments), privateKey);
            var stagedBytes = await File.ReadAllBytesAsync(stagedPackage);
            Ensure(stagedBytes.SequenceEqual(packageBytes),
                "Staging changed the authenticated package bytes.");
            Ensure(!Directory.EnumerateFiles(directory, "SentinelAI.Agent.exe", SearchOption.AllDirectories).Any(),
                "Verify or stage extracted or installed an executable.");
            if (!OperatingSystem.IsWindows())
                Ensure(File.GetUnixFileMode(stagedPackage) == (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                    "Staged package permissions are not restricted to its owner.");

            EnsureRejected(await RunClientAsync(stagingArguments), privateKey);
            Ensure((await File.ReadAllBytesAsync(stagedPackage)).SequenceEqual(stagedBytes),
                "Repeated staging overwrote the existing package.");

            var tamperedPackage = Path.Combine(directory, "tampered.zip");
            var tamperedBytes = await File.ReadAllBytesAsync(package);
            tamperedBytes[^1] ^= 1;
            await File.WriteAllBytesAsync(tamperedPackage, tamperedBytes);
            EnsureRejected(await RunClientAsync(ClientArguments("verify", manifest, tamperedPackage, publicKey)), privateKey);
            var rejectedStage = Path.Combine(directory, "rejected.zip");
            EnsureRejected(await RunClientAsync(ClientArguments("stage", manifest, tamperedPackage, publicKey)
                .Concat(["--output", rejectedStage]).ToArray()), privateKey);
            Ensure(!File.Exists(rejectedStage), "A package with an invalid hash was staged.");

            var tamperedManifest = Path.Combine(directory, "tampered-manifest.json");
            var json = JsonNode.Parse(manifestBytes)!;
            json["manifest"]!["version"] = "1.2.4";
            await File.WriteAllTextAsync(tamperedManifest, json.ToJsonString());
            EnsureRejected(await RunClientAsync(ClientArguments("verify", tamperedManifest, package, publicKey)), privateKey);
            json = JsonNode.Parse(manifestBytes)!;
            var signature = json["signature"]!.GetValue<string>();
            json["signature"] = (signature[0] == 'A' ? "B" : "A") + signature[1..];
            await File.WriteAllTextAsync(tamperedManifest, json.ToJsonString());
            EnsureRejected(await RunClientAsync(ClientArguments("verify", tamperedManifest, package, publicKey)), privateKey);
            await File.WriteAllTextAsync(tamperedManifest, "{}");
            EnsureRejected(await RunClientAsync(ClientArguments("verify", tamperedManifest, package, publicKey)), privateKey);
            EnsureRejected(await RunClientAsync(ReplaceValue(verifyingArguments, "--public-key", privateKey)), privateKey);

            foreach (var (flag, value) in new[]
                     {
                         ("--channel", "pilot"), ("--channel", "beta"), ("--environment", "production"),
                         ("--artifact-id", "sentinelai-core-win-x64"), ("--key-id", "dev-other"),
                         ("--installed-version", "1.2.3"), ("--installed-version", "2.0.0")
                     })
                EnsureRejected(await RunClientAsync(ReplaceValue(verifyingArguments, flag, value)), privateKey);

            foreach (var channel in new[] { "pilot", "beta" })
            {
                var channelManifest = Path.Combine(directory, channel + ".json");
                var channelSigningArguments = ReplaceValue(ReplaceValue(signingArguments, "--channel", channel),
                    "--output", channelManifest);
                var channelSigned = await RunDevAsync(channelSigningArguments);
                Ensure(channelSigned.ExitCode == 0 && File.Exists(channelManifest),
                    "Development signing does not support an initial pilot/beta channel.");
                var channelVerification = ReplaceValue(ReplaceValue(verifyingArguments, "--channel", channel),
                    "--manifest", channelManifest);
                EnsureVerified(await RunClientAsync(channelVerification), privateKey, channel);
            }

            await VerifyPreparationAsync(directory, signingArguments, verifyingArguments, tamperedPackage, privateKey);
            await VerifyStrictArgumentsAsync(directory, signingArguments, verifyingArguments, privateKey);
            await VerifyRepositoryKeyRejectionAsync(directory, package, privateKey);
            await VerifyPartialKeyPairAsync(directory, privateKey);
            if (!OperatingSystem.IsWindows())
                await VerifyLinkedPathsAsync(directory, signingArguments, stagingArguments, privateKey);
            Console.WriteLine($"Signed update command tests passed ({_assertions} assertions).");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task VerifyPreparationAsync(string directory, string[] signingArguments,
        string[] verifyingArguments, string tamperedPackage, string privateKey)
    {
        var candidate = Path.Combine(directory, "prepared-agent");
        var preparingArguments = verifyingArguments.ToArray();
        preparingArguments[0] = "prepare";
        preparingArguments = preparingArguments.Concat(["--output", candidate]).ToArray();
        EnsureVerified(await RunClientAsync(preparingArguments), privateKey);
        Ensure(await File.ReadAllTextAsync(Path.Combine(candidate, "SentinelAI.Agent.exe")) ==
               "Synthetic development agent executable; never run." &&
               Directory.GetFileSystemEntries(candidate).Length == 1,
            "Fresh Agent preparation did not produce only the authenticated executable.");
        if (!OperatingSystem.IsWindows())
            Ensure(File.GetUnixFileMode(candidate) ==
                   (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
                "Prepared code directory permissions are not restricted to its owner.");

        var marker = Path.Combine(candidate, "operator-marker.txt");
        await File.WriteAllTextAsync(marker, "Existing operator data.");
        EnsureRejected(await RunClientAsync(preparingArguments), privateKey);
        Ensure(await File.ReadAllTextAsync(marker) == "Existing operator data.",
            "Repeated preparation changed an existing installation directory.");
        var existingFile = Path.Combine(directory, "existing-code-file");
        await File.WriteAllTextAsync(existingFile, "Existing operator file.");
        EnsureRejected(await RunClientAsync(ReplaceValue(preparingArguments, "--output", existingFile)), privateKey);
        Ensure(await File.ReadAllTextAsync(existingFile) == "Existing operator file.",
            "Preparation overwrote an existing destination file.");
        EnsureRejected(await RunClientAsync(ReplaceValue(preparingArguments, "--output", "relative-code")), privateKey);
        EnsureRejected(await RunClientAsync(preparingArguments[..^2]), privateKey);
        EnsureRejected(await RunClientAsync(preparingArguments.Concat(["--unknown", "value"]).ToArray()), privateKey);

        var rejected = Path.Combine(directory, "rejected-agent");
        var freshArguments = ReplaceValue(preparingArguments, "--output", rejected);
        EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--package", tamperedPackage)), privateKey);
        Ensure(!Directory.Exists(rejected), "Preparation retained a candidate with an invalid package hash.");
        var modifiedManifest = Path.Combine(directory, "prepare-invalid-signature.json");
        var json = JsonNode.Parse(await File.ReadAllBytesAsync(verifyingArguments[Array.IndexOf(verifyingArguments, "--manifest") + 1]))!;
        json["manifest"]!["version"] = "1.2.4";
        await File.WriteAllTextAsync(modifiedManifest, json.ToJsonString());
        EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--manifest", modifiedManifest)), privateKey);
        Ensure(!Directory.Exists(rejected), "Preparation retained a candidate with an invalid signature.");

        var corePackage = Path.Combine(directory, "core.zip");
        var coreManifest = Path.Combine(directory, "core.manifest.json");
        await CreatePackageAsync(corePackage,
            ("SentinelAI.Core.exe", "Synthetic Core executable; never run."),
            ("wwwroot/index.html", "Synthetic dashboard document."),
            ("wwwroot/assets/app.js", "Synthetic dashboard asset."));
        var coreSigning = ReplaceValue(ReplaceValue(ReplaceValue(signingArguments, "--package", corePackage),
            "--output", coreManifest), "--artifact-id", "sentinelai-core-win-x64");
        Ensure((await RunDevAsync(coreSigning)).ExitCode == 0, "Synthetic Core package could not be signed.");
        var coreCandidate = Path.Combine(directory, "prepared-core");
        var coreArguments = ReplaceValue(ReplaceValue(ReplaceValue(ReplaceValue(preparingArguments,
            "--package", corePackage), "--manifest", coreManifest), "--artifact-id", "sentinelai-core-win-x64"),
            "--output", coreCandidate);
        EnsureVerified(await RunClientAsync(coreArguments), privateKey, artifactId: "sentinelai-core-win-x64");
        Ensure(await File.ReadAllTextAsync(Path.Combine(coreCandidate, "SentinelAI.Core.exe")) ==
               "Synthetic Core executable; never run." &&
               await File.ReadAllTextAsync(Path.Combine(coreCandidate, "wwwroot", "index.html")) ==
               "Synthetic dashboard document." &&
               await File.ReadAllTextAsync(Path.Combine(coreCandidate, "wwwroot", "assets", "app.js")) ==
               "Synthetic dashboard asset.", "Core preparation did not preserve its authenticated dashboard layout.");

        foreach (var (name, entries) in new (string, (string Path, string Contents)[])[]
                 {
                     ("traversal", [("SentinelAI.Agent.exe", "Synthetic executable."), ("../outside.txt", "Unsafe path.")]),
                     ("state", [("SentinelAI.Agent.exe", "Synthetic executable."), ("enrollment-state", "Synthetic state.")]),
                     ("receipt", [("SentinelAI.Agent.exe", "Synthetic executable."), (".sentinelai-update-receipt.json", "Synthetic installed-state receipt.")]),
                     ("receipt-alias", [("SentinelAI.Agent.exe", "Synthetic executable."), (".SENTINELAI-UPDATE-RECEIPT.JSON", "Synthetic installed-state receipt alias.")]),
                     ("wrong-executable", [("SentinelAI.Core.exe", "Synthetic Core executable.")]),
                     ("collision", [("SentinelAI.Agent.exe", "Synthetic executable."), ("sentinelai.agent.exe", "Duplicate path.")])
                 })
        {
            var unsafePackage = Path.Combine(directory, name + ".zip");
            var unsafeManifest = Path.Combine(directory, name + ".manifest.json");
            await CreatePackageAsync(unsafePackage, entries);
            Ensure((await RunDevAsync(ReplaceValue(ReplaceValue(signingArguments, "--package", unsafePackage),
                "--output", unsafeManifest))).ExitCode == 0, "Synthetic unsafe archive could not be signed.");
            EnsureRejected(await RunClientAsync(ReplaceValue(ReplaceValue(freshArguments, "--package", unsafePackage),
                "--manifest", unsafeManifest)), privateKey);
            Ensure(!Directory.Exists(rejected), "Failed archive preparation retained partially extracted code.");
        }
        Ensure(!File.Exists(Path.Combine(directory, "outside.txt")), "Preparation wrote outside its candidate directory.");

        var malformedPackage = Path.Combine(directory, "malformed.zip");
        var malformedManifest = Path.Combine(directory, "malformed.manifest.json");
        await File.WriteAllTextAsync(malformedPackage, "Synthetic bytes, not a ZIP archive.");
        Ensure((await RunDevAsync(ReplaceValue(ReplaceValue(signingArguments, "--package", malformedPackage),
            "--output", malformedManifest))).ExitCode == 0, "Synthetic malformed package could not be signed.");
        EnsureRejected(await RunClientAsync(ReplaceValue(ReplaceValue(freshArguments, "--package", malformedPackage),
            "--manifest", malformedManifest)), privateKey);
        Ensure(!Directory.Exists(rejected), "Malformed ZIP preparation retained an empty code directory.");

        var unsupportedManifest = Path.Combine(directory, "unsupported.manifest.json");
        Ensure((await RunDevAsync(ReplaceValue(ReplaceValue(signingArguments, "--artifact-id", "sentinelai-other-win-x64"),
            "--output", unsupportedManifest))).ExitCode == 0, "Synthetic unsupported artifact could not be signed.");
        EnsureRejected(await RunClientAsync(ReplaceValue(ReplaceValue(freshArguments, "--artifact-id", "sentinelai-other-win-x64"),
            "--manifest", unsupportedManifest)), privateKey);
        Ensure(!Directory.Exists(rejected), "Preparation accepted an unsupported executable artifact.");

        if (!OperatingSystem.IsWindows())
        {
            var linked = Path.Combine(directory, "prepare-linked");
            Directory.CreateSymbolicLink(linked, candidate);
            EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--output", linked)), privateKey);
            EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--output", Path.Combine(linked, "child"))), privateKey);
            Ensure(await File.ReadAllTextAsync(marker) == "Existing operator data." &&
                   !Directory.Exists(Path.Combine(candidate, "child")), "Preparation followed a destination link.");
            var brokenLink = Path.Combine(directory, "prepare-broken-link");
            Directory.CreateSymbolicLink(brokenLink, Path.Combine(directory, "absent-target"));
            EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--output", brokenLink)), privateKey);
            Ensure(new DirectoryInfo(brokenLink).LinkTarget is not null &&
                   !Directory.Exists(Path.Combine(directory, "absent-target")),
                "Preparation replaced a broken link or created its target.");
            var unsafeParent = Path.Combine(directory, "prepare-shared-parent");
            Directory.CreateDirectory(unsafeParent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(unsafeParent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                            UnixFileMode.GroupWrite);
            var unsafeOutput = Path.Combine(unsafeParent, "code");
            EnsureRejected(await RunClientAsync(ReplaceValue(freshArguments, "--output", unsafeOutput)), privateKey);
            Ensure(!Directory.Exists(unsafeOutput), "Preparation wrote into a parent writable by other accounts.");
        }
    }

    private static async Task VerifyStrictArgumentsAsync(string directory, string[] signingArguments,
        string[] verifyingArguments, string privateKey)
    {
        foreach (var arguments in new[]
                 {
                     Array.Empty<string>(), new[] { "install" },
                     verifyingArguments.Concat(["--unknown", "value"]).ToArray(),
                     verifyingArguments.Concat(["--channel", "stable"]).ToArray(),
                     verifyingArguments[..^1], verifyingArguments[..^2],
                     ReplaceValue(verifyingArguments, "--environment", "Development")
                 })
            EnsureRejected(await RunClientAsync(arguments), privateKey);

        var productionOutput = Path.Combine(directory, "production.json");
        var freshSigningArguments = ReplaceValue(signingArguments, "--output", productionOutput);
        foreach (var arguments in new[]
                 {
                     Array.Empty<string>(), new[] { "production-sign" },
                     freshSigningArguments.Concat(["--environment", "production"]).ToArray(),
                     freshSigningArguments.Concat(["--production", "true"]).ToArray(),
                     freshSigningArguments.Concat(["--unknown", "value"]).ToArray(),
                     freshSigningArguments.Concat(["--channel", "stable"]).ToArray(),
                     freshSigningArguments[..^1], freshSigningArguments[..^2]
                 })
            EnsureRejected(await RunDevAsync(arguments), privateKey);
        Ensure(!File.Exists(productionOutput), "Invalid development signing arguments created a manifest.");

        var unusedKeys = Path.Combine(directory, "invalid-keys");
        foreach (var arguments in new[]
                 {
                     new[] { "keygen", "--directory", unusedKeys, "--key-id", KeyId, "--unknown", "value" },
                     new[] { "keygen", "--directory", unusedKeys, "--key-id", KeyId, "--key-id", KeyId },
                     new[] { "keygen", "--directory", unusedKeys, "--key-id" },
                     new[] { "keygen", "--directory", unusedKeys }
                 })
            EnsureRejected(await RunDevAsync(arguments), privateKey);
        Ensure(!Directory.Exists(unusedKeys), "Invalid key generation arguments created signing-key state.");
    }

    private static async Task VerifyRepositoryKeyRejectionAsync(string directory, string package, string privateKey)
    {
        var fakeRepository = Path.Combine(directory, "repository");
        Directory.CreateDirectory(fakeRepository);
        await File.WriteAllTextAsync(Path.Combine(fakeRepository, "AGENTS.md"), "Synthetic test checkout.");
        await File.WriteAllTextAsync(Path.Combine(fakeRepository, "SentinelAI.sln"), "Synthetic test checkout.");
        Directory.CreateDirectory(Path.Combine(fakeRepository, ".git"));
        var unsafeDirectory = Path.Combine(fakeRepository, "keys");
        EnsureRejected(await RunDevAsync(["keygen", "--directory", unsafeDirectory, "--key-id", KeyId]), privateKey);
        Ensure(!Directory.Exists(unsafeDirectory), "Key generation created a private-key directory inside a checkout.");

        // This fixture contains no private key. Rejection must happen before private-key import.
        var unsafePrivateKey = Path.Combine(fakeRepository, "not-a-private-key.pem");
        await File.WriteAllTextAsync(unsafePrivateKey, "Synthetic non-secret public data.");
        var output = Path.Combine(directory, "unsafe-manifest.json");
        EnsureRejected(await RunDevAsync(SignArguments(unsafePrivateKey, package, output)), unsafePrivateKey);
        Ensure(!File.Exists(output), "Signing accepted a private-key path inside a checkout.");
    }

    private static async Task VerifyPartialKeyPairAsync(string directory, string privateKey)
    {
        var keyDirectory = Path.Combine(directory, "partial-keys");
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(keyDirectory);
        else Directory.CreateDirectory(keyDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var publicPath = Path.Combine(keyDirectory, KeyId + ".public.pem");
        var privatePath = Path.Combine(keyDirectory, KeyId + ".private.pem");
        const string existingPublicData = "Synthetic existing public data, never a private key.";
        await File.WriteAllTextAsync(publicPath, existingPublicData);
        EnsureRejected(await RunDevAsync(["keygen", "--directory", keyDirectory, "--key-id", KeyId]), privateKey);
        Ensure(!File.Exists(privatePath) && await File.ReadAllTextAsync(publicPath) == existingPublicData,
            "A conflicting public key left a partial private key or changed the existing public file.");
    }

    private static async Task VerifyLinkedPathsAsync(string directory, string[] signingArguments,
        string[] stagingArguments, string privateKey)
    {
        var actualDirectory = Path.Combine(directory, "actual");
        Directory.CreateDirectory(actualDirectory);
        var linkedDirectory = Path.Combine(directory, "linked");
        Directory.CreateSymbolicLink(linkedDirectory, actualDirectory);
        var linkedKeyDirectory = Path.Combine(linkedDirectory, "keys");
        EnsureRejected(await RunDevAsync(["keygen", "--directory", linkedKeyDirectory, "--key-id", KeyId]), privateKey);
        Ensure(!Directory.Exists(Path.Combine(actualDirectory, "keys")), "Key generation followed a directory link.");

        var linkedPrivateKey = Path.Combine(directory, "linked-private.pem");
        File.CreateSymbolicLink(linkedPrivateKey, privateKey);
        var linkedManifest = Path.Combine(directory, "linked-manifest.json");
        EnsureRejected(await RunDevAsync(ReplaceValue(ReplaceValue(signingArguments, "--private-key", linkedPrivateKey),
            "--output", linkedManifest)), privateKey);
        Ensure(!File.Exists(linkedManifest), "Signing followed a private-key link.");

        var linkedOutput = Path.Combine(linkedDirectory, "stage.zip");
        EnsureRejected(await RunClientAsync(ReplaceValue(stagingArguments, "--output", linkedOutput)), privateKey);
        Ensure(!File.Exists(Path.Combine(actualDirectory, "stage.zip")), "Staging followed a directory link.");
    }

    private static string[] SignArguments(string privateKey, string package, string manifest) =>
    [
        "sign", "--private-key", privateKey, "--key-id", KeyId, "--package", package, "--version", "1.2.3",
        "--artifact-id", ArtifactId, "--artifact-url", ArtifactUrl, "--channel", "stable", "--output", manifest
    ];

    private static string[] ClientArguments(string command, string manifest, string package, string publicKey) =>
    [
        command, "--manifest", manifest, "--package", package, "--public-key", publicKey, "--key-id", KeyId,
        "--environment", "development", "--channel", "stable", "--artifact-id", ArtifactId,
        "--installed-version", "1.2.2"
    ];

    private static string[] ReplaceValue(string[] arguments, string option, string value)
    {
        var replaced = arguments.ToArray();
        var index = Array.IndexOf(replaced, option);
        Ensure(index >= 0 && index + 1 < replaced.Length, "Test option was not found.");
        replaced[index + 1] = value;
        return replaced;
    }

    private static async Task CreatePackageAsync(string path)
        => await CreatePackageAsync(path, ("SentinelAI.Agent.exe", "Synthetic development agent executable; never run."));

    private static async Task CreatePackageAsync(string path, params (string Path, string Contents)[] entries)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entryPath, contents) in entries)
        {
            var entry = archive.CreateEntry(entryPath);
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes(contents));
        }
    }

    private static async Task<CommandResult> RunDevAsync(string[] arguments)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await DevelopmentUpdateCommand.RunAsync(arguments, output, error);
        return new CommandResult(exitCode, output.ToString(), error.ToString());
    }

    private static async Task<CommandResult> RunClientAsync(string[] arguments)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await UpdaterCommand.RunAsync(arguments, output, error);
        return new CommandResult(exitCode, output.ToString(), error.ToString());
    }

    private static void EnsureVerified(CommandResult result, string privateKey, string channel = "stable",
        string artifactId = ArtifactId)
    {
        Ensure(result.ExitCode == 0 && string.IsNullOrEmpty(result.Error), "The client rejected the signed development package.");
        using var output = JsonDocument.Parse(result.Output);
        var properties = output.RootElement.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        Ensure(properties.SetEquals(["version", "artifactId", "channel", "environment"]) &&
               output.RootElement.GetProperty("version").GetString() == "1.2.3" &&
               output.RootElement.GetProperty("artifactId").GetString() == artifactId &&
               output.RootElement.GetProperty("channel").GetString() == channel &&
               output.RootElement.GetProperty("environment").GetString() == "development",
            "Verification stdout did not expose only the bounded authenticated metadata.");
        EnsureNoSecrets(result, privateKey);
    }

    private static void EnsureRejected(CommandResult result, string privateKey)
    {
        Ensure(result.ExitCode != 0 && string.IsNullOrEmpty(result.Output) && !string.IsNullOrWhiteSpace(result.Error),
            "Invalid update command did not fail closed without a success payload.");
        EnsureNoSecrets(result, privateKey);
        Ensure(!result.Error.Contains(ArtifactUrl, StringComparison.Ordinal) &&
               !result.Error.Contains(privateKey, StringComparison.Ordinal),
            "Update command error disclosed input paths or metadata.");
    }

    private static void EnsureNoSecrets(CommandResult result, string privateKey)
    {
        var text = result.Output + result.Error;
        Ensure(!text.Contains("PRIVATE KEY", StringComparison.Ordinal) &&
               !text.Contains("PUBLIC KEY", StringComparison.Ordinal) &&
               !text.Contains("password", StringComparison.OrdinalIgnoreCase),
            "Update command exposed PEM material or credential details.");
        if (File.Exists(privateKey))
        {
            var lines = File.ReadAllLines(privateKey);
            Ensure(!lines.Where(line => line.Length > 20 && !line.StartsWith("-----", StringComparison.Ordinal))
                .Any(line => text.Contains(line, StringComparison.Ordinal)),
                "Update command exposed raw private-key material.");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed record CommandResult(int ExitCode, string Output, string Error);
}
