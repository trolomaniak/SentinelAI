using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SentinelAI.Backup;

/// <summary>A portable recovery secret encrypted with an owner-supplied passphrase; no filesystem or logging.</summary>
public static class RecoveryKeyFile
{
    public const int Iterations = 600_000;
    public const int MaximumFileBytes = 104;
    private const int HeaderBytes = 56;
    private const int KeyBytes = 32;
    private const int TagBytes = 16;
    private static readonly byte[] Magic = "SAIRKY01"u8.ToArray();

    public static byte[] Create(ReadOnlySpan<byte> key, ReadOnlySpan<char> passphrase)
    {
        Validate(key.Length, passphrase);
        var file = new byte[MaximumFileBytes];
        Magic.CopyTo(file, 0);
        BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(8, 4), Iterations);
        RandomNumberGenerator.Fill(file.AsSpan(12, 32));
        RandomNumberGenerator.Fill(file.AsSpan(44, 12));
        var wrapping = Rfc2898DeriveBytes.Pbkdf2(passphrase, file.AsSpan(12, 32), Iterations, HashAlgorithmName.SHA256, KeyBytes);
        try
        {
            using var aes = new AesGcm(wrapping, TagBytes);
            aes.Encrypt(file.AsSpan(44, 12), key, file.AsSpan(HeaderBytes, KeyBytes),
                file.AsSpan(HeaderBytes + KeyBytes, TagBytes), file.AsSpan(0, HeaderBytes));
            return file;
        }
        finally { CryptographicOperations.ZeroMemory(wrapping); }
    }

    public static byte[] Open(ReadOnlySpan<byte> file, ReadOnlySpan<char> passphrase)
    {
        Validate(KeyBytes, passphrase);
        if (file.Length != MaximumFileBytes || !file[..8].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadInt32BigEndian(file.Slice(8, 4)) != Iterations)
            throw Invalid();
        var wrapping = Rfc2898DeriveBytes.Pbkdf2(passphrase, file.Slice(12, 32), Iterations, HashAlgorithmName.SHA256, KeyBytes);
        var key = new byte[KeyBytes];
        try
        {
            using var aes = new AesGcm(wrapping, TagBytes);
            aes.Decrypt(file.Slice(44, 12), file.Slice(HeaderBytes, KeyBytes), file.Slice(HeaderBytes + KeyBytes, TagBytes),
                key, file[..HeaderBytes]);
            return key;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Invalid();
        }
        finally { CryptographicOperations.ZeroMemory(wrapping); }
    }

    private static void Validate(int keyLength, ReadOnlySpan<char> passphrase)
    {
        if (keyLength != KeyBytes) throw new ArgumentException("A 32-byte recovery key is required.");
        if (passphrase.Length is < 12 or > 1024) throw new ArgumentException("The recovery passphrase must have 12 to 1024 characters.");
        // Reject ill-formed UTF-16 rather than permitting two distinct inputs to derive the same replacement text.
        for (var i = 0; i < passphrase.Length; i++)
        {
            if (char.IsHighSurrogate(passphrase[i]))
            {
                if (i + 1 >= passphrase.Length || !char.IsLowSurrogate(passphrase[++i])) throw new ArgumentException("The recovery passphrase is invalid.");
            }
            else if (char.IsLowSurrogate(passphrase[i])) throw new ArgumentException("The recovery passphrase is invalid.");
        }
    }

    private static InvalidDataException Invalid() => new("The recovery key file or passphrase is invalid.");
}
