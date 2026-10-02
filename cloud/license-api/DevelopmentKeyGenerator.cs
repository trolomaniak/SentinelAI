using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.LicenseApi;

public static class DevelopmentKeyGenerator
{
    public static IReadOnlyList<string> Generate(string outputDirectory)
    {
        var path = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new IOException("Output directory already exists.");
        }
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credential = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var files = new[]
        {
            ("private.pem", key.ExportPkcs8PrivateKeyPem()),
            ("public.pem", key.ExportSubjectPublicKeyInfoPem()),
            ("activation-credential.txt", credential),
            ("activation-credential.sha256", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential))))
        };
        var generated = new List<string>();
        foreach (var (name, value) in files)
        {
            var filePath = Path.Combine(path, name);
            var fileOptions = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
            {
                fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            using var stream = new FileStream(filePath, fileOptions);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.Write(value);
            generated.Add(filePath);
        }
        return generated.AsReadOnly();
    }
}
