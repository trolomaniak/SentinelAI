using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SentinelAI.Setup;

internal static class OrdinaryDesktopLauncher
{
    public static bool TryOpen()
    {
        object? windows = null; object? desktop = null; object? application = null;
        try
        {
            var shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "SentinelAI", "SentinelAI.lnk");
            if (!File.Exists(shortcut) || (File.GetAttributes(shortcut) & FileAttributes.ReparsePoint) != 0) return false;
            // Obtain the already running interactive shell. Shell.Application alone
            // can create an elevated COM server and propagate setup's authority.
            var type = Type.GetTypeFromCLSID(new Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39"), throwOnError: true)!;
            windows = Activator.CreateInstance(type);
            dynamic shellWindows = windows!;
            object location = 0; object root = 0;
            desktop = shellWindows.FindWindowSW(ref location, ref root, 8, out int window, 1);
            if (desktop is null || !HasOrdinaryToken(new IntPtr(window))) return false;
            dynamic shellDesktop = desktop;
            application = shellDesktop.Document.Application;
            dynamic shell = application;
            shell.ShellExecute(shortcut, "", Path.GetDirectoryName(shortcut), "open", 1);
            return true;
        }
        catch { return false; }
        finally
        {
            foreach (var value in new[] { application, desktop, windows })
                if (value is not null && Marshal.IsComObject(value)) try { Marshal.FinalReleaseComObject(value); } catch { }
        }
    }

    private static bool HasOrdinaryToken(IntPtr window)
    {
        if (window == IntPtr.Zero || GetWindowThreadProcessId(window, out var processId) == 0 || processId == 0) return false;
        using var process = OpenProcess(0x1000, false, processId); // query limited information
        if (process.IsInvalid || !OpenProcessToken(process, 0x0008, out var token)) return false;
        using (token) return GetTokenInformation(token, 20, out var elevated, sizeof(int), out _) && elevated == 0;
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, out int information, int size, out int returnedSize);
}
