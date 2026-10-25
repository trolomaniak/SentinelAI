using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

internal sealed class EmbeddedInstallation : IDisposable
{
    public SetupMetadata Metadata { get; }
    private readonly Stream _payload;
    private readonly byte[] _trust;
    private EmbeddedInstallation(SetupMetadata metadata, Stream payload, byte[] trust) { Metadata = metadata; _payload = payload; _trust = trust; }

    public static EmbeddedInstallation Open()
    {
        var assembly = Assembly.GetExecutingAssembly();
        Stream Resource(string name) => assembly.GetManifestResourceStream(name) ?? throw new InvalidDataException("Setup payload unavailable.");
        using var metadataStream = Resource("SentinelAI.Setup.Metadata");
        var metadata = SetupMetadata.Parse(ReadSmall(metadataStream, 4096));
        using var trustStream = Resource("SentinelAI.Setup.Trust");
        var trust = ReadSmall(trustStream, 4096);
        var text = Encoding.UTF8.GetString(trust);
        if (!text.TrimStart().StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) || text.Contains("PRIVATE", StringComparison.Ordinal)) throw new InvalidDataException("Invalid public trust.");
        using var key = ECDsa.Create(); key.ImportFromPem(text);
        if (key.KeySize != 256) throw new InvalidDataException("Unsupported public trust.");
        return new(metadata, Resource("SentinelAI.Setup.Payload"), trust);
    }

    /// <param name="image">The native wrapper's own executable, opened read-only and verified as its running image. The
    /// worker keeps this copy as the installed Setup that Windows Apps runs to uninstall.</param>
    public async Task<string> ExtractAsync(SafeFileHandle image, CancellationToken token)
    {
        await SetupPayload.VerifyAsync(_payload, Metadata, token).ConfigureAwait(false);
        var work = ProtectedStaging.Create();
        try
        {
            await SetupPayload.ExtractAsync(_payload, work, token, Metadata.Product).ConfigureAwait(false);
            var trustDirectory = Path.Combine(work, "trust"); Directory.CreateDirectory(trustDirectory);
            await File.WriteAllBytesAsync(Path.Combine(trustDirectory, "root.pem"), _trust, token).ConfigureAwait(false);
            var installerDirectory = Path.Combine(work, "installer"); Directory.CreateDirectory(installerDirectory);
            await CopyImageAsync(image, Path.Combine(installerDirectory, "setup.exe"), token).ConfigureAwait(false);
            ProtectedStaging.Validate(work);
            return work;
        }
        catch { ProtectedStaging.TryRemove(work); throw; }
    }

    private static async Task CopyImageAsync(SafeFileHandle image, string destination, CancellationToken token)
    {
        var length = RandomAccess.GetLength(image);
        if (length is <= 0 or > int.MaxValue) throw new InvalidDataException("Invalid setup image.");
        await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous);
        var buffer = new byte[1024 * 1024];
        for (long offset = 0; offset < length;)
        {
            var read = RandomAccess.Read(image, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
            if (read <= 0) throw new InvalidDataException("Invalid setup image.");
            await output.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            offset += read;
        }
        await output.FlushAsync(token).ConfigureAwait(false);
    }

    private static byte[] ReadSmall(Stream stream, int limit)
    {
        if (!stream.CanSeek || stream.Length is <= 0 || stream.Length > limit) throw new InvalidDataException("Invalid setup resource.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
    }
    public void Dispose() { _payload.Dispose(); CryptographicOperations.ZeroMemory(_trust); }
}
