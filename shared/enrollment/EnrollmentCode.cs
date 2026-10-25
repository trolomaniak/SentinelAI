using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Enrollment;

// One enrollment code (MVP-2): the central Core's local-network address and port, the SHA-256 pin of its
// certificate and one enrollment token. Linked into Core, which issues codes, and the Agent Setup, which reads
// them. A code is a secret: callers never log it.
//
// Text form: "SAI1-" followed by Crockford Base32 groups of five characters. The decoded bytes are
// version (1) | port (2, big-endian) | pin (32) | token (32) | address length (1) | ASCII address | checksum (4),
// where the checksum is the first four bytes of SHA-256 over "SAIE" and everything before it.
internal sealed record EnrollmentCode(string Address, int Port, string CertificateSha256, string EnrollmentToken)
{
    public const string FileExtension = ".sentinelai-enroll";
    public const int MaximumTextLength = 512;
    public const int MaximumFileBytes = 4096;
    // DNS allows 253 characters, but the longest code must stay within MaximumTextLength with a line break: a
    // 180-character address gives 489 characters.
    public const int MaximumAddressLength = 180;
    private const string Prefix = "SAI1-";
    private const byte Version = 1;
    private const int ChecksumLength = 4;
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static readonly byte[] ChecksumDomain = "SAIE"u8.ToArray();

    public Uri CoreUrl => new($"https://{Address}:{Port.ToString(CultureInfo.InvariantCulture)}");

    // The token is a secret: the record's text form never shows it.
    public override string ToString() => nameof(EnrollmentCode);

    public string Encode()
    {
        if (!IsValid(Address, Port, CertificateSha256, EnrollmentToken)) throw new ArgumentException("The enrollment code values are invalid.");
        var address = Encoding.ASCII.GetBytes(Address);
        var bytes = new byte[1 + 2 + 32 + 32 + 1 + address.Length + ChecksumLength];
        bytes[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(1), (ushort)Port);
        Convert.FromHexString(CertificateSha256).CopyTo(bytes, 3);
        Convert.FromHexString(EnrollmentToken).CopyTo(bytes, 35);
        bytes[67] = (byte)address.Length;
        address.CopyTo(bytes, 68);
        Checksum(bytes.AsSpan(0, bytes.Length - ChecksumLength)).CopyTo(bytes.AsSpan(bytes.Length - ChecksumLength));
        var encoded = Base32(bytes);
        var text = new StringBuilder(Prefix, Prefix.Length + encoded.Length + encoded.Length / 5);
        for (var index = 0; index < encoded.Length; index += 5)
        {
            if (index > 0) text.Append('-');
            text.Append(encoded, index, Math.Min(5, encoded.Length - index));
        }

        return text.ToString();
    }

    // Accepts a pasted code with any case, spaces, line breaks and hyphens; Crockford's O, I and L read as 0, 1, 1.
    public static bool TryParse(string? text, out EnrollmentCode? code)
    {
        code = null;
        if (text is null || text.Length > MaximumTextLength) return false;
        var compact = string.Concat(text.Where(character => character is not (' ' or '\r' or '\n' or '\t')));
        if (!compact.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var symbols = new StringBuilder(compact.Length);
        foreach (var character in compact.AsSpan(Prefix.Length))
        {
            if (character == '-') continue;
            symbols.Append(char.ToUpperInvariant(character) switch { 'O' => '0', 'I' or 'L' => '1', var other => other });
        }

        if (!TryBase32(symbols.ToString(), out var bytes) || bytes.Length < 1 + 2 + 32 + 32 + 1 + 1 + ChecksumLength ||
            bytes[0] != Version || bytes[67] != bytes.Length - 68 - ChecksumLength ||
            !CryptographicOperations.FixedTimeEquals(Checksum(bytes.AsSpan(0, bytes.Length - ChecksumLength)), bytes.AsSpan(bytes.Length - ChecksumLength)))
            return false;

        var address = bytes.AsSpan(68, bytes[67]);
        foreach (var value in address)
            if (value is < 0x21 or > 0x7E) return false;
        var candidate = new EnrollmentCode(Encoding.ASCII.GetString(address), BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(1)),
            Convert.ToHexString(bytes, 3, 32), Convert.ToHexString(bytes, 35, 32));
        if (!IsValid(candidate.Address, candidate.Port, candidate.CertificateSha256, candidate.EnrollmentToken)) return false;
        code = candidate;
        return true;
    }

    // A ".sentinelai-enroll" file holds exactly one code as UTF-8 text.
    public static bool TryParseFile(ReadOnlySpan<byte> content, out EnrollmentCode? code)
    {
        code = null;
        if (content.Length is 0 or > MaximumFileBytes) return false;
        string text;
        try { text = new UTF8Encoding(false, true).GetString(content.StartsWith("﻿"u8) ? content[3..] : content); }
        catch (DecoderFallbackException) { return false; }
        return TryParse(text, out code);
    }

    public static bool IsAddress(string? value) =>
        value is { Length: > 0 and <= MaximumAddressLength } &&
        (IPAddress.TryParse(value, out var address) ? address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                                                     address.ToString() == value
                                                   : IsDnsName(value));

    private static bool IsValid(string address, int port, string pin, string token) =>
        IsAddress(address) && port is > 0 and <= 65535 && IsUpperHex(pin) && IsUpperHex(token);

    private static bool IsUpperHex(string? value) => value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    // Windows accepts underscores in computer names; names with national letters arrive as IDN A-labels.
    private static bool IsDnsName(string value) =>
        !value.All(character => character is >= '0' and <= '9' or '.') &&
        value.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
            label.All(character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_'));

    private static byte[] Checksum(ReadOnlySpan<byte> payload)
    {
        Span<byte> hash = stackalloc byte[32];
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(ChecksumDomain);
        sha.AppendData(payload);
        sha.GetHashAndReset(hash);
        return hash[..ChecksumLength].ToArray();
    }

    private static string Base32(ReadOnlySpan<byte> bytes)
    {
        var text = new StringBuilder((bytes.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                text.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0) text.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return text.ToString();
    }

    private static bool TryBase32(string text, out byte[] bytes)
    {
        bytes = [];
        var output = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var character in text)
        {
            var value = Alphabet.IndexOf(character);
            if (value < 0) return false;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }

            buffer &= (1 << bits) - 1;
        }

        // Only the zero padding of the last symbol may remain.
        if (bits >= 5 || buffer != 0) return false;
        bytes = output.ToArray();
        return true;
    }
}
