using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SentinelAI.Setup;

/// <summary>Creates an administrator-only tree atomically, never inheriting a permissive staging ACL.</summary>
internal static class ProtectedStaging
{
    private static readonly HashSet<string> Writers = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
    private static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI-Setup");
    public static string Create()
    {
        ValidateAncestors(Path.GetDirectoryName(Root)!);
        CreateProtected(Root, allowExisting: true);
        Validate(Root);
        var work = Path.Combine(Root, Guid.NewGuid().ToString("N"));
        CreateProtected(work, allowExisting: false);
        Validate(work);
        return work;
    }

    private static void CreateProtected(string path, bool allowExisting)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, out var descriptor, out _)) throw new Win32Exception();
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), SecurityDescriptor = descriptor };
            if (!CreateDirectory(path, ref attributes) && !(allowExisting && Marshal.GetLastWin32Error() == 183)) throw new Win32Exception();
        }
        finally { _ = LocalFree(descriptor); }
    }

    public static void Validate(string path)
    {
        var full = Path.GetFullPath(path);
        if (!(string.Equals(full, Root, StringComparison.OrdinalIgnoreCase) || full.StartsWith(Root + "\\", StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("Invalid setup staging path.");
        ValidateAncestors(full);
    }

    private static void ValidateAncestors(string path)
    {
        for (var current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != FileAttributes.Directory) throw new InvalidDataException("Unsafe setup parent.");
            var security = new DirectoryInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var owner = (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
            if (owner is null || !Writers.Contains(owner)) throw new InvalidDataException("Unsafe setup owner.");
            var unsafeRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            if (!string.Equals(current, path, StringComparison.OrdinalIgnoreCase)) unsafeRights &= ~FileSystemRights.AppendData;
            if (string.Equals(current, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase)) unsafeRights &= ~FileSystemRights.Write;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                    (rule.FileSystemRights & unsafeRights) != 0 && !Writers.Contains(((SecurityIdentifier)rule.IdentityReference).Value)) throw new InvalidDataException("Unsafe setup writer.");
        }
    }

    public static void TryRemove(string path)
    {
        try { Validate(path); Directory.Delete(path, recursive: true); } catch { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public IntPtr SecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path, ref SecurityAttributes security);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
