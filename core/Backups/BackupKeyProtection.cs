using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Core.Backups;

public interface IBackupKeyProtection
{
    bool IsSupported { get; }
    byte[] Protect(ReadOnlySpan<byte> value);
    byte[] Unprotect(ReadOnlySpan<byte> value);
}

/// <summary>Machine DPAPI plus the installer's Core-only storage ACL; no portable plaintext key is stored by Core.</summary>
public sealed class WindowsBackupKeyProtection : IBackupKeyProtection
{
    public bool IsSupported => OperatingSystem.IsWindows();
    public byte[] Protect(ReadOnlySpan<byte> value) => Transform(value, protect: true);
    public byte[] Unprotect(ReadOnlySpan<byte> value) => Transform(value, protect: false);
    private static byte[] Transform(ReadOnlySpan<byte> value, bool protect)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (value.Length is < 1 or > 8192) throw new CryptographicException("Backup key protection failed.");
        var bytes = value.ToArray();
        var entropyBytes = Encoding.UTF8.GetBytes("SentinelAI/CoreBackup/recovery-key/v1");
        var inputHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(entropyBytes, GCHandleType.Pinned);
        Blob output = default;
        try
        {
            var input = new Blob { Length = bytes.Length, Data = inputHandle.AddrOfPinnedObject() };
            var entropy = new Blob { Length = entropyBytes.Length, Data = entropyHandle.AddrOfPinnedObject() };
            var success = protect
                ? CryptProtectData(ref input, null, ref entropy, IntPtr.Zero, IntPtr.Zero, 5, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!success || output.Length is < 1 or > 8192) throw new CryptographicException("Backup key protection failed.");
            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                // DPAPI's output may contain the recovery secret after Unprotect.
                for (var offset = 0; offset < output.Length; offset++) Marshal.WriteByte(output.Data, offset, 0);
                _ = LocalFree(output.Data);
            }
            inputHandle.Free(); entropyHandle.Free();
            CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string? description, ref Blob entropy, IntPtr reserved,
        IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, ref Blob entropy, IntPtr reserved,
        IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
