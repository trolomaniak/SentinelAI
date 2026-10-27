using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SentinelAI.Updater;

/// <summary>
/// The central computer's side of a central update. The run folders live under the Setup's protected
/// <c>%ProgramData%\SentinelAI-Setup</c>: Administrators and SYSTEM only, owned by Administrators, never a link. Only the
/// attempt record additionally grants Core's service account read access, so Desktop can show it.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsCentralUpdateHost(CentralUpdateLayout layout) : ICentralUpdateHost
{
    private static readonly HashSet<string> Writers = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

    public string CreateRunDirectory()
    {
        EnsureProtected(Path.GetDirectoryName(layout.WorkRoot)!);
        EnsureProtected(layout.WorkRoot);
        // Earlier runs' copies; one still running is skipped and removed by a later run.
        foreach (var earlier in Directory.EnumerateDirectories(layout.WorkRoot, "run-*"))
        {
            try
            {
                if ((File.GetAttributes(earlier) & FileAttributes.ReparsePoint) == 0) Directory.Delete(earlier, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }

        var run = Path.Combine(layout.WorkRoot, "run-" + Guid.NewGuid().ToString("N"));
        new DirectoryInfo(run).Create(DirectorySecurity());
        Validate(run);
        return run;
    }

    public void WriteState(byte[] document)
    {
        Validate(layout.WorkRoot);
        var temporary = layout.StateFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var security = new FileSecurity();
        Protect(security);
        try
        {
            var core = new NTAccount("NT SERVICE", "SentinelAICore").Translate(typeof(SecurityIdentifier));
            security.AddAccessRule(new FileSystemAccessRule(core, FileSystemRights.Read, AccessControlType.Allow));
        }
        catch (IdentityNotMappedException) { }

        try
        {
            using (var stream = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Synchronize,
                       FileShare.None, 4096, FileOptions.WriteThrough, security))
                stream.Write(document);
            if (File.Exists(layout.StateFile) && (File.GetAttributes(layout.StateFile) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The central update record is a link.");
            File.Move(temporary, layout.StateFile, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public void CloseDesktop()
    {
        foreach (var process in Process.GetProcessesByName("SentinelAI.Desktop"))
        {
            using (process)
            {
                try
                {
                    // Only this installation's Desktop; it keeps no state of its own, the services keep monitoring.
                    if (!string.Equals(process.MainModule?.FileName, layout.DesktopExecutable, StringComparison.OrdinalIgnoreCase)) continue;
                    process.Kill();
                    process.WaitForExit(15_000);
                }
                catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
    }

    public void StartSetup(string executable, bool quiet)
    {
        using var process = Process.Start(new ProcessStartInfo(executable, quiet ? "/upgrade /quiet" : string.Empty)
        {
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(executable)!
        }) ?? throw new InvalidOperationException("SentinelAI Setup did not start.");
    }

    private static void EnsureProtected(string directory)
    {
        if (!Directory.Exists(directory)) new DirectoryInfo(directory).Create(DirectorySecurity());
        Validate(directory);
    }

    private static DirectorySecurity DirectorySecurity()
    {
        var security = new DirectorySecurity();
        Protect(security);
        return security;
    }

    private static void Protect(FileSystemSecurity security)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(security is DirectorySecurity
                ? new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)
                : new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        }
    }

    /// <summary>Not a link, owned by Administrators, SYSTEM or TrustedInstaller, and writable by nobody else.</summary>
    private static void Validate(string directory)
    {
        if ((File.GetAttributes(directory) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != FileAttributes.Directory)
            throw new InvalidDataException("Unsafe central update folder.");
        var security = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Writers.Contains(owner.Value))
            throw new InvalidDataException("Unsafe central update folder owner.");
        const FileSystemRights unsafeRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                                              FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & unsafeRights) != 0 &&
                !Writers.Contains(((SecurityIdentifier)rule.IdentityReference).Value))
                throw new InvalidDataException("Unsafe central update folder writer.");
        }
    }
}
