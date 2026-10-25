using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using SentinelAI.Licensing;

namespace SentinelAI.PilotLicense;

/// <summary>
/// The owner's pilot license issuer (MVP-3). It runs only on the owner's own computer: the private key never enters
/// the repository or any SentinelAI artifact, and Core, Desktop and Setup only ever verify.
/// </summary>
public static class PilotLicenseCommand
{
    public const int MaximumDays = 365;
    private const UnixFileMode GroupOrOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, TimeProvider time)
    {
        try
        {
            if (args is ["--help"])
            {
                await output.WriteLineAsync("keygen --directory NEW_DIRECTORY_OUTSIDE_REPOSITORY --key-id ID");
                await output.WriteLineAsync("issue --private-key PEM --key-id ID --customer \"COMPANY\" --days 1-365 [--start yyyy-mm-dd]");
                await output.WriteLineAsync("check --public-key PEM");
                return 0;
            }
            var command = args.FirstOrDefault();
            var options = command switch
            {
                "keygen" => Parse(args, ["directory", "key-id"], []),
                "issue" => Parse(args, ["private-key", "key-id", "customer", "days"], ["start"]),
                "check" => Parse(args, ["public-key"], []),
                _ => throw new ArgumentException("Unknown command.")
            };
            if (options.TryGetValue("key-id", out var keyId) && !Regex.IsMatch(keyId, @"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant))
                throw new ArgumentException("The key ID must be 1-64 letters, digits, '_' or '-'.");
            if (command == "check") CheckPublicKey(options["public-key"]);
            else if (command == "keygen") await KeyGenerateAsync(options, output);
            else await IssueAsync(options, output, time);
            return 0;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or CryptographicException or FormatException)
        {
            // Only the reason, never key material or a key.
            await error.WriteLineAsync("pilot-license: " + (exception is ArgumentException ? exception.Message : "The key files could not be used."));
            return 1;
        }
    }

    private static async Task KeyGenerateAsync(IReadOnlyDictionary<string, string> options, TextWriter output)
    {
        var directory = EnsureOutsideRepository(options["directory"]);
        if (Directory.Exists(directory) || File.Exists(directory)) throw new ArgumentException("The key directory must not exist yet.");
        CreateOwnerOnlyDirectory(directory);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(directory, options["key-id"] + ".private.pem");
        var publicPath = Path.Combine(directory, options["key-id"] + ".public.pem");
        await using (var privateFile = CreateOwnerOnlyFile(privatePath))
            await privateFile.WriteAsync(Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()));
        await using (var publicFile = CreateOwnerOnlyFile(publicPath))
            await publicFile.WriteAsync(Encoding.UTF8.GetBytes(key.ExportSubjectPublicKeyInfoPem()));
        await output.WriteLineAsync(privatePath);
        await output.WriteLineAsync(publicPath);
    }

    private static async Task IssueAsync(IReadOnlyDictionary<string, string> options, TextWriter output, TimeProvider time)
    {
        var customer = options["customer"];
        if (!PilotLicenseFormat.IsCustomer(customer)) throw new ArgumentException("The customer must be 1-64 characters without surrounding spaces or control characters.");
        if (!int.TryParse(options["days"], NumberStyles.None, CultureInfo.InvariantCulture, out var days) || days is < 1 or > MaximumDays)
            throw new ArgumentException("The duration must be 1-365 days.");
        var start = DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime);
        if (options.TryGetValue("start", out var text) &&
            !DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out start))
            throw new ArgumentException("The start date must be yyyy-mm-dd.");
        var issued = new DateTimeOffset(start.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
        var claims = new PilotLicenseClaims(customer, issued, issued.AddDays(days));

        var privatePath = EnsureOutsideRepository(options["private-key"]);
        var file = new FileInfo(privatePath);
        if (!file.Exists || file.Length is <= 0 or > 16384) throw new ArgumentException("The private key file is missing or invalid.");
        if (OperatingSystem.IsWindows() ? !IsOwnerOnly(file) : (File.GetUnixFileMode(privatePath) & GroupOrOther) != 0)
            throw new ArgumentException("The private key file must be readable by its owner only.");
        var pem = await File.ReadAllTextAsync(privatePath);
        if (!PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "PRIVATE KEY" ||
            !string.IsNullOrWhiteSpace(pem[..fields.Location.Start.GetOffset(pem.Length)]) ||
            !string.IsNullOrWhiteSpace(pem[fields.Location.End.GetOffset(pem.Length)..])) throw new ArgumentException("The private key file is missing or invalid.");
        using var key = ECDsa.Create();
        var der = Convert.FromBase64String(pem[fields.Base64Data]);
        try
        {
            key.ImportPkcs8PrivateKey(der, out var consumed);
            if (consumed != der.Length || key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
                throw new ArgumentException("The private key must be ECDSA P-256.");
        }
        finally { CryptographicOperations.ZeroMemory(der); }
        var signingInput = PilotLicenseFormat.CreateSigningInput(claims, options["key-id"]);
        var signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await output.WriteLineAsync(PilotLicenseFormat.Assemble(signingInput, signature));
    }

    /// <summary>
    /// The packaging check for a pilot public key: exactly what Core and Setup accept (one P-256 SPKI PEM, never a
    /// private key), so a wrong key fails the build instead of the installed product. Exit 0 means usable.
    /// </summary>
    private static void CheckPublicKey(string path)
    {
        var file = new FileInfo(Path.GetFullPath(path));
        if (!file.Exists || file.Length is <= 0 or > 4096) throw new ArgumentException("The public key file is missing or invalid.");
        try { _ = new PilotLicenseVerifier(new Dictionary<string, string> { ["check"] = File.ReadAllText(file.FullName) }); }
        catch (ArgumentException) { throw new ArgumentException("Only a P-256 public key in SPKI PEM form can be a pilot public key."); }
    }

    // Windows counterpart of the Unix group/other check: only the current user, SYSTEM and Administrators may read the key.
    [SupportedOSPlatform("windows")]
    private static bool IsOwnerOnly(FileInfo file)
    {
        using var identity = WindowsIdentity.GetCurrent();
        string[] allowed = [identity.User!.Value, "S-1-5-18", "S-1-5-32-544"];
        foreach (FileSystemAccessRule rule in file.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & FileSystemRights.ReadData) != 0 &&
                !allowed.Contains(((SecurityIdentifier)rule.IdentityReference).Value)) return false;
        return true;
    }

    private static Dictionary<string, string> Parse(string[] args, string[] required, string[] optional)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length) throw new ArgumentException("Every option needs a value.");
            var name = args[index][2..];
            if (!required.Contains(name) && !optional.Contains(name) || !options.TryAdd(name, args[index + 1])) throw new ArgumentException("Unknown or repeated option.");
        }
        if (required.Any(name => !options.ContainsKey(name))) throw new ArgumentException("A required option is missing.");
        return options;
    }

    private static void CreateOwnerOnlyDirectory(string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            // Only the current user, with no inherited entries.
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            using var identity = WindowsIdentity.GetCurrent();
            security.SetOwner(identity.User!);
            security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            var parent = Path.GetDirectoryName(directory);
            if (parent is null || !Directory.Exists(parent)) throw new ArgumentException("The parent folder must exist.");
            new DirectoryInfo(directory).Create(security);
        }
        else
        {
            var parent = Path.GetDirectoryName(directory);
            if (parent is null || !Directory.Exists(parent)) throw new ArgumentException("The parent folder must exist.");
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if ((File.GetUnixFileMode(directory) & GroupOrOther) != 0) throw new IOException("Owner-only permissions could not be applied.");
        }
    }

    private static FileStream CreateOwnerOnlyFile(string path)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }

    // A private key never goes into a repository, this one or any other.
    private static string EnsureOutsideRepository(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute path is required.");
        var full = Path.GetFullPath(path);
        for (var current = full; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Linked key paths are not supported.");
            if (Directory.Exists(Path.Combine(current, ".git")) || File.Exists(Path.Combine(current, ".git")) ||
                (File.Exists(Path.Combine(current, "AGENTS.md")) && File.Exists(Path.Combine(current, "SentinelAI.sln"))))
                throw new ArgumentException("Pilot keys must stay outside every repository.");
        }
        return full;
    }
}
