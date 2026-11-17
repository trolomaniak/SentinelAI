using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Core.Notifications;

public interface INotificationCredentialProtection
{
    bool IsSupported { get; }
    byte[] Protect(ReadOnlySpan<byte> value);
    byte[] Unprotect(ReadOnlySpan<byte> value);
}

// Machine DPAPI is paired with the installer's Core-only database ACL. Separate entropy
// prevents a notification ciphertext from being interpreted as another Core credential.
public sealed class WindowsNotificationCredentialProtection : INotificationCredentialProtection
{
    public bool IsSupported => OperatingSystem.IsWindows();
    public byte[] Protect(ReadOnlySpan<byte> value) => Transform(value, true);
    public byte[] Unprotect(ReadOnlySpan<byte> value) => Transform(value, false);
    private static byte[] Transform(ReadOnlySpan<byte> value, bool protect)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (value.Length is < 1 or > 16384) throw new CryptographicException("Credential protection failed.");
        var inputBytes = value.ToArray();
        var entropyBytes = Encoding.UTF8.GetBytes("SentinelAI/Notifications/credentials/v1");
        var inputHandle = GCHandle.Alloc(inputBytes, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(entropyBytes, GCHandleType.Pinned);
        Blob output = default;
        try
        {
            var input = new Blob { Length = inputBytes.Length, Data = inputHandle.AddrOfPinnedObject() };
            var entropy = new Blob { Length = entropyBytes.Length, Data = entropyHandle.AddrOfPinnedObject() };
            var success = protect
                ? CryptProtectData(ref input, null, ref entropy, IntPtr.Zero, IntPtr.Zero, 5, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!success || output.Length is < 1 or > 16384) throw new CryptographicException("Credential protection failed.");
            var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                for (var offset = 0; offset < output.Length; offset++) Marshal.WriteByte(output.Data, offset, 0);
                _ = LocalFree(output.Data);
            }
            inputHandle.Free(); entropyHandle.Free();
            CryptographicOperations.ZeroMemory(inputBytes); CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob input, string? description,
        ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description,
        ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
