using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Backup;

/// <summary>
/// Versioned, bounded streaming backup encryption. Each archive gets a distinct derived
/// key; every frame authenticates the header, position, length and final marker. Plaintext
/// written by DecryptAsync remains provisional until the entire stream has been accepted.
/// Callers must use private staging and publish only after successful completion.
/// </summary>
public static class BackupArchive
{
    public const long MaximumPayloadBytes = 1024L * 1024 * 1024;
    public const long MaximumArchiveBytes = MaximumPayloadBytes + 4L * 1024 * 1024;
    public const int KeyBytes = 32;
    public const int ChunkBytes = 1024 * 1024;
    private const int HeaderBytes = 40;
    private const int FrameHeaderBytes = 13;
    private const int TagBytes = 16;
    private static readonly byte[] Magic = "SAIBKP01"u8.ToArray();
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("SentinelAI.Backup.Archive.v1\0");

    public static string KeyId(ReadOnlySpan<byte> key)
    {
        ValidateKey(key.Length);
        return Convert.ToHexStringLower(SHA256.HashData(key));
    }

    public static async Task EncryptAsync(Stream input, Stream output, ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default)
    {
        ValidateStreams(input, output, key.Length);
        cancellationToken.ThrowIfCancellationRequested();
        var header = new byte[HeaderBytes];
        Magic.CopyTo(header, 0);
        RandomNumberGenerator.Fill(header.AsSpan(Magic.Length));
        var derived = Derive(key.Span, header.AsSpan(Magic.Length));
        var plaintext = new byte[ChunkBytes];
        var ciphertext = new byte[ChunkBytes];
        var frame = new byte[FrameHeaderBytes];
        var aad = new byte[HeaderBytes + FrameHeaderBytes];
        var tag = new byte[TagBytes];
        var nonce = new byte[12];
        try
        {
            using var aes = new AesGcm(derived, TagBytes);
            header.CopyTo(aad, 0);
            await output.WriteAsync(header, cancellationToken);
            long total = 0;
            ulong sequence = 0;
            while (true)
            {
                var read = await FillAsync(input, plaintext, cancellationToken);
                if (read == 0) break;
                if (read > MaximumPayloadBytes - total) throw Invalid();
                total += read;
                WriteFrame(frame, sequence, read, final: false);
                frame.CopyTo(aad, HeaderBytes);
                WriteNonce(nonce, sequence);
                aes.Encrypt(nonce, plaintext.AsSpan(0, read), ciphertext.AsSpan(0, read), tag, aad);
                await output.WriteAsync(frame, cancellationToken);
                await output.WriteAsync(ciphertext.AsMemory(0, read), cancellationToken);
                await output.WriteAsync(tag, cancellationToken);
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, read));
                sequence++;
            }

            WriteFrame(frame, sequence, 0, final: true);
            frame.CopyTo(aad, HeaderBytes);
            WriteNonce(nonce, sequence);
            aes.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);
            await output.WriteAsync(frame, cancellationToken);
            await output.WriteAsync(tag, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static async Task DecryptAsync(Stream input, Stream output, ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default)
    {
        ValidateStreams(input, output, key.Length);
        cancellationToken.ThrowIfCancellationRequested();
        var header = new byte[HeaderBytes];
        await ExactAsync(input, header, cancellationToken);
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw Invalid();
        var derived = Derive(key.Span, header.AsSpan(Magic.Length));
        var plaintext = new byte[ChunkBytes];
        var ciphertext = new byte[ChunkBytes];
        var frame = new byte[FrameHeaderBytes];
        var aad = new byte[HeaderBytes + FrameHeaderBytes];
        var tag = new byte[TagBytes];
        var nonce = new byte[12];
        try
        {
            using var aes = new AesGcm(derived, TagBytes);
            header.CopyTo(aad, 0);
            long total = 0;
            long consumed = HeaderBytes;
            ulong sequence = 0;
            var shortFrame = false;
            while (true)
            {
                await ExactAsync(input, frame, cancellationToken);
                consumed += FrameHeaderBytes;
                var actualSequence = BinaryPrimitives.ReadUInt64BigEndian(frame.AsSpan(0, 8));
                var length = BinaryPrimitives.ReadInt32BigEndian(frame.AsSpan(8, 4));
                var final = frame[12];
                if (actualSequence != sequence || final > 1 || length < 0 || length > ChunkBytes ||
                    final == 0 && length == 0 || final == 1 && length != 0 || shortFrame && final != 1 ||
                    length > MaximumPayloadBytes - total ||
                    length + TagBytes > MaximumArchiveBytes - consumed) throw Invalid();
                await ExactAsync(input, ciphertext.AsMemory(0, length), cancellationToken);
                await ExactAsync(input, tag, cancellationToken);
                consumed += length + TagBytes;
                frame.CopyTo(aad, HeaderBytes);
                WriteNonce(nonce, sequence);
                try { aes.Decrypt(nonce, ciphertext.AsSpan(0, length), tag, plaintext.AsSpan(0, length), aad); }
                catch (CryptographicException) { throw Invalid(); }
                if (final == 1)
                {
                    var trailing = new byte[1];
                    if (await input.ReadAsync(trailing, cancellationToken) != 0) throw Invalid();
                    return;
                }
                await output.WriteAsync(plaintext.AsMemory(0, length), cancellationToken);
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, length));
                total += length;
                shortFrame = length < ChunkBytes;
                sequence++;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static byte[] Derive(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
    {
        var message = new byte[Domain.Length + salt.Length];
        Domain.CopyTo(message, 0);
        salt.CopyTo(message.AsSpan(Domain.Length));
        return HMACSHA256.HashData(key, message);
    }

    private static void WriteFrame(byte[] frame, ulong sequence, int length, bool final)
    {
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(0, 8), sequence);
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(8, 4), length);
        frame[12] = final ? (byte)1 : (byte)0;
    }

    private static void WriteNonce(byte[] nonce, ulong sequence)
    {
        // Four fixed bytes followed by a unique position under a per-archive derived key.
        nonce[0] = (byte)'S'; nonce[1] = (byte)'A'; nonce[2] = (byte)'I'; nonce[3] = (byte)'B';
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), sequence);
    }

    private static async Task<int> FillAsync(Stream input, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await input.ReadAsync(buffer[read..], cancellationToken);
            if (count == 0) break;
            read += count;
        }
        return read;
    }

    private static async Task ExactAsync(Stream input, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (await FillAsync(input, buffer, cancellationToken) != buffer.Length) throw Invalid();
    }

    private static void ValidateStreams(Stream input, Stream output, int keyLength)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ValidateKey(keyLength);
        if (!input.CanRead || !output.CanWrite || ReferenceEquals(input, output))
            throw new ArgumentException("Separate readable and writable streams are required.");
    }

    private static void ValidateKey(int length)
    {
        if (length != KeyBytes) throw new ArgumentException("A 32-byte recovery key is required.");
    }

    private static InvalidDataException Invalid() => new("The backup archive is invalid or could not be authenticated.");
}
