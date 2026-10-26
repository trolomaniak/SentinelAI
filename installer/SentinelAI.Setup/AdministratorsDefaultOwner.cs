using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SentinelAI.Setup;

/// <summary>
/// Makes Administrators the owner of every object this elevated host and the processes it starts create: Core's
/// first-run database, the Updater's code, the worker's files. Windows can otherwise give them the administrator's own
/// account, whose non-elevated programs could change their access as owner, and Setup's checks trust no account. If
/// Windows refuses (an unelevated host), objects keep the token's owner and those checks fail closed.
/// </summary>
internal static class AdministratorsDefaultOwner
{
    public static void Apply()
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var sid = new byte[administrators.BinaryLength];
        administrators.GetBinaryForm(sid, 0);
        var pinned = GCHandle.Alloc(sid, GCHandleType.Pinned);
        try
        {
            using var process = Process.GetCurrentProcess();
            if (!OpenProcessToken(process.SafeHandle, 0x0080, out var token)) return; // TOKEN_ADJUST_DEFAULT
            using (token)
            {
                var owner = new TokenOwner { Owner = pinned.AddrOfPinnedObject() };
                _ = SetTokenInformation(token, 4, ref owner, Marshal.SizeOf<TokenOwner>()); // TokenOwner
            }
        }
        finally { pinned.Free(); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct TokenOwner { public IntPtr Owner; }
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int informationClass, ref TokenOwner information, int size);
}
