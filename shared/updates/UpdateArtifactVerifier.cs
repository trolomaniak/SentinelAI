using System.Buffers;
using System.Security.Cryptography;

namespace SentinelAI.Updates;

public static class UpdateArtifactVerifier
{
    /// <summary>Hashes the exact bytes copied to a new private staging file; installation must use that copy.</summary>
    public static async Task CopyAndVerifyAsync(string packagePath, string destinationNewFile, VerifiedUpdateManifest verified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var created = false;
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            await using var source = new FileStream(packagePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: buffer.Length, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (source.Length != verified.Manifest.SizeBytes) throw new UpdateValidationException();
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = buffer.Length,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using var destination = new FileStream(destinationNewFile, options);
            created = true;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long size = 0;
            int read;
            while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
            {
                size += read;
                if (size > verified.Manifest.SizeBytes || size > UpdateManifestFormat.MaximumArtifactBytes)
                    throw new UpdateValidationException();
                hash.AppendData(buffer, 0, read);
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
            var actualHash = hash.GetHashAndReset();
            if (size != verified.Manifest.SizeBytes ||
                !CryptographicOperations.FixedTimeEquals(actualHash, Convert.FromHexString(verified.Manifest.Sha256)))
                throw new UpdateValidationException();
            await destination.FlushAsync(cancellationToken);
            destination.Flush(flushToDisk: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or UpdateValidationException or OperationCanceledException or ArgumentException)
        {
            if (created)
            {
                try { File.Delete(destinationNewFile); }
                catch (Exception cleanupException) when (cleanupException is IOException or UnauthorizedAccessException) { }
            }
            if (exception is OperationCanceledException) throw;
            throw new UpdateValidationException();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }
}
