using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SentinelAI.Hosting;

namespace SentinelAI.Agent;

// A restricted one-use installer handoff, never part of persistent configuration or state.
internal static class EnrollmentTokenHandoff
{
    public static async Task<string> ReadAsync(AgentOptions options, CancellationToken cancellationToken)
    {
        if (options.EnrollmentToken is not null) return options.EnrollmentToken;
        if (options.EnrollmentTokenFile is not { } path)
            throw new InvalidOperationException("An enrollment token is not configured.");
        ValidateFile(path);
        byte[] bytes;
        await using (var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.None,
            Options = FileOptions.Asynchronous
        }))
        {
            if (stream.Length is <= 0 or > 128) throw Invalid();
            bytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(bytes, cancellationToken);
            if (stream.ReadByte() != -1) throw Invalid();
        }
        try
        {
            string token;
            try { token = new UTF8Encoding(false, true).GetString(bytes).Trim(); }
            catch (DecoderFallbackException) { throw Invalid(); }
            if (token.Length != 64 || !token.All(Uri.IsHexDigit)) throw Invalid();
            return token;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static void DeleteIfPresent(AgentOptions options)
    {
        if (options.EnrollmentTokenFile is not { } path) return;
        PilotHostConfiguration.RejectLinks(path);
        if (!File.Exists(path)) return;
        ValidateFile(path);
        File.Delete(path);
    }

    private static void ValidateFile(string path)
    {
        PilotHostConfiguration.RejectLinks(path);
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.Directory) != 0) throw Invalid();
        if (OperatingSystem.IsWindows()) ValidateWindowsPermissions(path);
        else if ((File.GetUnixFileMode(path) &
                 (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0) throw Invalid();
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsPermissions(string path)
    {
        var security = new FileInfo(path).GetAccessControl();
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.DiscretionaryAcl is null || descriptor.DiscretionaryAcl.Count == 0) throw Invalid();
        using var identity = WindowsIdentity.GetCurrent();
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
        };
        if (identity.User is not null) allowed.Add(identity.User.Value);
        if (identity.Groups is not null)
            foreach (var group in identity.Groups)
                if (group.Value.StartsWith("S-1-5-80-", StringComparison.Ordinal)) allowed.Add(group.Value);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value)) throw Invalid();
    }

    private static InvalidDataException Invalid() =>
        new("The installer enrollment token handoff is missing, invalid or insufficiently protected.");
}
