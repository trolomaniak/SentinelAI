using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SentinelAI.Rules.Vulnerabilities;
using SentinelAI.Updates;

namespace SentinelAI.UpdateDev;

/// <summary>Development-only signer. Production signing is deliberately absent.</summary>
public static class DevelopmentUpdateCommand
{
    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                await output.WriteLineAsync("keygen --directory ABSOLUTE_OUTSIDE_REPOSITORY --key-id dev-ID; sign --private-key PEM --key-id dev-ID --package ZIP --version X.Y.Z --artifact-id ID --artifact-url HTTPS_URL --channel stable|pilot|beta --output NEW_MANIFEST; trust --private-key PEM --key-id dev-ID --channel stable|pilot|beta --output NEW_FILE; feed-build --products JSON --nvd DIRECTORY --kev JSON --nvd-retrieved UTC --kev-retrieved UTC --generated UTC --output NEW_FILE. Signing always uses environment development.");
                return 0;
            }
            var command = args.FirstOrDefault();
            var required = command switch
            {
                "keygen" => new[] { "directory", "key-id" },
                "sign" => ["private-key", "key-id", "package", "version", "artifact-id", "artifact-url", "channel", "output"],
                "trust" => ["private-key", "key-id", "channel", "output"],
                "feed-build" => ["products", "nvd", "kev", "nvd-retrieved", "kev-retrieved", "generated", "output"],
                _ => throw new ArgumentException()
            };
            var options = Parse(args, required);
            if (command == "feed-build")
            {
                await BuildFeedAsync(options);
                await output.WriteLineAsync("Vulnerability feed created; sign it as artifact " + VulnerabilityFeedFormat.ArtifactId + ".");
                return 0;
            }
            if (!Regex.IsMatch(options["key-id"], @"\Adev-[A-Za-z0-9_-]{1,48}\z", RegexOptions.CultureInvariant)) throw new ArgumentException();
            if (command == "trust")
            {
                if (options["channel"] is not ("stable" or "pilot" or "beta")) throw new ArgumentException();
                using var trusted = await LoadPrivateKeyAsync(options["private-key"]);
                // TASK-030: built into Core, which verifies vulnerability feeds with it; public data only.
                var trust = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string>
                {
                    ["format"] = "sentinelai-update-trust-v1", ["keyId"] = options["key-id"], ["environment"] = "development",
                    ["channel"] = options["channel"], ["publicKey"] = trusted.ExportSubjectPublicKeyInfoPem()
                });
                await using var trustFile = CreatePrivateFile(Path.GetFullPath(options["output"]));
                await trustFile.WriteAsync(trust);
                await output.WriteLineAsync("Update trust file created.");
                return 0;
            }
            if (command == "keygen")
            {
                var directory = EnsureOutsideRepository(options["directory"]);
                if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
                else
                {
                    Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                    if ((File.GetUnixFileMode(directory) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0) throw new ArgumentException();
                }
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var privatePath = Path.Combine(directory, options["key-id"] + ".private.pem");
                var publicPath = Path.Combine(directory, options["key-id"] + ".public.pem");
                // Reserve both files first: an existing public or private key is never replaced.
                var privateCreated = false;
                var publicCreated = false;
                try
                {
                    await using var privateFile = CreatePrivateFile(privatePath);
                    privateCreated = true;
                    await using var publicFile = CreatePrivateFile(publicPath);
                    publicCreated = true;
                    await privateFile.WriteAsync(Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()));
                    await publicFile.WriteAsync(Encoding.UTF8.GetBytes(key.ExportSubjectPublicKeyInfoPem()));
                }
                catch
                {
                    if (privateCreated) File.Delete(privatePath);
                    if (publicCreated) File.Delete(publicPath);
                    throw;
                }
                await output.WriteLineAsync("Development key files created outside the repository.");
            }
            else
            {
                using var key = await LoadPrivateKeyAsync(options["private-key"]);
                await using var package = new FileStream(options["package"], FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous);
                if (package.Length <= 0 || package.Length > UpdateManifestFormat.MaximumBytes(options["artifact-id"])) throw new ArgumentException();
                var size = package.Length;
                var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(package));
                if (package.Position != size || package.Length != size) throw new ArgumentException();
                var manifest = new UpdateManifest(options["version"], options["artifact-id"], options["artifact-url"], hash,
                    size, options["channel"], "development");
                var data = UpdateManifestFormat.CreateSigningData(manifest, options["key-id"]);
                var signature = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                var document = UpdateManifestFormat.SerializeSigned(manifest, options["key-id"], signature);
                await using var destination = CreatePrivateFile(Path.GetFullPath(options["output"]));
                await destination.WriteAsync(document);
                await output.WriteLineAsync("Signed development update manifest created.");
            }
            return 0;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or
                                         UpdateValidationException or CryptographicException or FormatException or JsonException or
                                         InvalidOperationException or KeyNotFoundException)
        {
            await error.WriteLineAsync("Development update command failed. Use development keys outside the repository and check the command arguments.");
            return 1;
        }
    }

    private static async Task<ECDsa> LoadPrivateKeyAsync(string path)
    {
        var privatePath = EnsureOutsideRepository(path);
        if (new FileInfo(privatePath).Length is <= 0 or > 16384) throw new ArgumentException();
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(privatePath) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0) throw new ArgumentException();
        var pem = await File.ReadAllTextAsync(privatePath);
        if (!PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "PRIVATE KEY" ||
            !string.IsNullOrWhiteSpace(pem[..fields.Location.Start.GetOffset(pem.Length)]) ||
            !string.IsNullOrWhiteSpace(pem[fields.Location.End.GetOffset(pem.Length)..])) throw new ArgumentException();
        var key = ECDsa.Create();
        try
        {
            var der = Convert.FromBase64String(pem[fields.Base64Data]);
            key.ImportPkcs8PrivateKey(der, out var consumed);
            if (consumed != der.Length) throw new ArgumentException();
            var parameters = key.ExportParameters(false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value || key.KeySize != 256) throw new ArgumentException();
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// TASK-030: builds the vulnerability feed from NVD CVE API 2.0 pages (every .json file in a directory), the CISA KEV
    /// catalog and the curated product list. The times are given, so the same inputs always give the same bytes.
    /// </summary>
    private static async Task BuildFeedAsync(Dictionary<string, string> options)
    {
        DateTimeOffset Time(string name) => DateTimeOffset.ParseExact(options[name], "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        const long maximumInput = 512L * 1024 * 1024;
        async Task<JsonDocument> ReadAsync(string path)
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length is <= 0 or > maximumInput) throw new ArgumentException();
            await using var stream = info.OpenRead();
            return await JsonDocument.ParseAsync(stream, new JsonDocumentOptions { MaxDepth = 64 });
        }

        using var products = await ReadAsync(Path.GetFullPath(options["products"]));
        var curated = VulnerabilityFeedBuilder.ReadProductList(products.RootElement);
        using var kev = await ReadAsync(Path.GetFullPath(options["kev"]));
        var files = Directory.GetFiles(Path.GetFullPath(options["nvd"]), "*.json").Order(StringComparer.Ordinal).ToArray();
        if (files.Length is 0 or > 10_000) throw new ArgumentException();
        var documents = new List<JsonDocument>();
        try
        {
            foreach (var file in files) documents.Add(await ReadAsync(file));
            var feed = VulnerabilityFeedBuilder.Build(curated, documents.Select(document => document.RootElement), kev.RootElement,
                Time("generated"), Time("nvd-retrieved"), Time("kev-retrieved"));
            await using var destination = CreatePrivateFile(Path.GetFullPath(options["output"]));
            await destination.WriteAsync(VulnerabilityFeedFormat.Serialize(feed));
        }
        finally
        {
            foreach (var document in documents) document.Dispose();
        }
    }

    private static Dictionary<string, string> Parse(string[] args, string[] required)
    {
        if (args.Length != 1 + required.Length * 2) throw new ArgumentException();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            var flag = args[index];
            if (!flag.StartsWith("--", StringComparison.Ordinal) || !required.Contains(flag[2..], StringComparer.Ordinal) ||
                string.IsNullOrWhiteSpace(args[index + 1]) || !result.TryAdd(flag[2..], args[index + 1])) throw new ArgumentException();
        }
        return result;
    }

    private static string EnsureOutsideRepository(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException();
        var full = Path.GetFullPath(path);
        for (var current = full; current is not null; current = Path.GetDirectoryName(current))
        {
            if (File.Exists(current) || Directory.Exists(current))
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new ArgumentException();
            }
            if (Directory.Exists(Path.Combine(current, ".git")) || File.Exists(Path.Combine(current, ".git")) ||
                (File.Exists(Path.Combine(current, "AGENTS.md")) && File.Exists(Path.Combine(current, "SentinelAI.sln")))) throw new ArgumentException();
        }
        return full;
    }

    private static FileStream CreatePrivateFile(string path)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous
        };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }
}
