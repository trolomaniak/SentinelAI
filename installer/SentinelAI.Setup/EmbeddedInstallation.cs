using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
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

    public async Task<string> ExtractAsync(CancellationToken token)
    {
        await SetupPayload.VerifyAsync(_payload, Metadata, token).ConfigureAwait(false);
        var work = ProtectedStaging.Create();
        try
        {
            await SetupPayload.ExtractAsync(_payload, work, token).ConfigureAwait(false);
            var trustDirectory = Path.Combine(work, "trust"); Directory.CreateDirectory(trustDirectory);
            await File.WriteAllBytesAsync(Path.Combine(trustDirectory, "root.pem"), _trust, token).ConfigureAwait(false);
            ProtectedStaging.Validate(work);
            return work;
        }
        catch { ProtectedStaging.TryRemove(work); throw; }
    }

    private static byte[] ReadSmall(Stream stream, int limit)
    {
        if (!stream.CanSeek || stream.Length is <= 0 || stream.Length > limit) throw new InvalidDataException("Invalid setup resource.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
    }
    public void Dispose() { _payload.Dispose(); CryptographicOperations.ZeroMemory(_trust); }
}
