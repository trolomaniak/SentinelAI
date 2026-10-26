# Setup's central installation and Agent Setup load this module administrators-only: their ACLs name no
# Windows account and their checks trust none, so any administrator maintains them. The separate console
# pilot (the default) runs Core as the installing operator's non-elevated console process, so its Core
# folders, configuration and parents also grant that account full control.
param([bool]$AdministratorsOnly = $false)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:OperatorAccess = -not $AdministratorsOnly
# The one account an earlier central installation granted full control. Setup's maintenance accepts it
# only until it removed that account's entries (Set-PilotLegacyOperatorSid).
$script:LegacyOperatorSid = $null
$script:ServiceName = 'SentinelAIAgent'
$script:ServiceAccount = 'NT AUTHORITY\LocalService'
$script:ServiceSid = 'S-1-5-19'
$script:AdministratorsSid = 'S-1-5-32-544'
$script:SystemSid = 'S-1-5-18'
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:PilotPrepareTimeoutSeconds = 330
$script:PilotLocalNetworkPort = 5443
# Processes that could not be released after a kill (stuck in the kernel) are kept referenced, never disposed.
$script:PilotAbandonedProcesses = New-Object 'System.Collections.Generic.List[object]'

function Assert-PilotSupportedHost {
    param([bool]$RequireElevation = $true)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
        -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or
        [Environment]::OSVersion.Version.Major -lt 10) {
        throw 'The pilot installer requires Windows 10/11 or Windows Server 2016 or later, with an x64 PowerShell process.'
    }
    if (-not $RequireElevation) { return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Run PowerShell as administrator before invoking the pilot installer. Automatic elevation is not performed.'
        }
    } finally { $identity.Dispose() }
}

function Get-PilotCurrentOperatorSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return $identity.User.Value } finally { $identity.Dispose() }
}

# The account granted access to the console pilot's Core; none for an administrators-only installation.
function Get-PilotOperatorAccessSid {
    if ($script:OperatorAccess) { return Get-PilotCurrentOperatorSid }
}

# Accounts whose ownership and write access the installation checks accept besides the built-in ones.
function Get-PilotTrustedAccountSids {
    $accounts = @(Get-PilotOperatorAccessSid)
    if ($null -ne $script:LegacyOperatorSid) { $accounts += $script:LegacyOperatorSid }
    return $accounts
}

function Get-PilotSharedProgramsPath { return [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms) }

function Set-PilotLegacyOperatorSid {
    param([AllowNull()][string]$Sid)
    if ([string]::IsNullOrEmpty($Sid)) { $script:LegacyOperatorSid = $null; return }
    # Only an ordinary local, domain or Microsoft Entra account, never a group or built-in identity.
    if ($script:OperatorAccess -or $Sid -cnotmatch '\AS-1-(?:5-21|12-1)-\d+-\d+-\d+-\d+\z') { throw 'Invalid legacy installation account.' }
    $script:LegacyOperatorSid = $Sid
}

# Removes one account's explicit Allow entries and ownership from an existing entry. Its other entries,
# their inheritance and the DACL protection are unchanged; Windows updates the inherited copies below it.
function Remove-PilotAccountAccess {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Sid)
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links and reparse points are unsupported.' }
    $container = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    $acl = Get-PilotAcl -Path $Path -Container $container
    $account = New-Object Security.Principal.SecurityIdentifier($Sid)
    $changed = $false
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $Sid) {
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:AdministratorsSid)))
        $changed = $true
    }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ceq $Sid -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) { $changed = $true }
    }
    if (-not $changed) { return }
    [void]$acl.RemoveAccessRuleAll((New-Object Security.AccessControl.FileSystemAccessRule($account, 'FullControl', 'Allow')))
    Set-PilotAcl -Path $Path -Container $container -Acl $acl
}

function Initialize-PilotNativeHelpers {
    if ('SentinelAI.Pilot.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
namespace SentinelAI.Pilot {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] private struct FileInformation {
            public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
            public System.Runtime.InteropServices.ComTypes.FILETIME Access;
            public System.Runtime.InteropServices.ComTypes.FILETIME Write;
            public uint VolumeSerial; public uint SizeHigh; public uint SizeLow;
            public uint LinkCount; public uint IndexHigh; public uint IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        public static uint GetLinkCount(string path) {
            // FILE_READ_ATTRIBUTES only: Windows applies no sharing check to it, so a file a service
            // holds exclusively while writing is still inspected instead of failing as in use.
            // FILE_FLAG_OPEN_REPARSE_POINT opens the entry itself, never a link target.
            using (var handle = CreateFileW(path, 0x80, 0x7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
                if (handle.IsInvalid) {
                    int error = Marshal.GetLastWin32Error();
                    // ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND: the entry no longer exists.
                    if (error == 2 || error == 3) throw new FileNotFoundException("Cannot inspect file links.", path);
                    throw new IOException("Cannot inspect file links.", Marshal.GetHRForLastWin32Error());
                }
                FileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) throw new IOException("Cannot inspect file links.");
                return information.LinkCount;
            }
        }
        public static RemoteCertificateValidationCallback CertificateValidator(string pin) {
            return delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                if (certificate == null || errors != SslPolicyErrors.None) return false;
                if (String.IsNullOrEmpty(pin)) return true;
                using (var sha = SHA256.Create()) {
                    var actual = BitConverter.ToString(sha.ComputeHash(certificate.GetRawCertData())).Replace("-", "");
                    return String.Equals(actual, pin, StringComparison.OrdinalIgnoreCase);
                }
            };
        }
    }
}
'@ | Out-Null
}

function Get-PilotHardLinkCount {
    param([Parameter(Mandatory=$true)][string]$Path)
    Initialize-PilotNativeHelpers
    return [SentinelAI.Pilot.Native]::GetLinkCount($Path)
}

function Assert-PilotPath {
    param([Parameter(Mandatory=$true)][string]$Path, [switch]$MustExist, [switch]$File)
    if ($Path -notmatch '\A[A-Za-z]:\\' -or $Path.Contains('/') -or $Path -match '[\x00-\x1f<>"|?*]' -or
        $Path.Substring(2).Contains(':') -or $Path -match '\\\\' -or $Path.Length -gt 220) {
        throw 'Use a canonical absolute local Windows path on an NTFS volume. UNC, device and provider paths are unsupported.'
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetPathRoot($Path)
    if ($full.Length -le 3 -or -not [string]::Equals($full, $Path.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Root, relative and noncanonical installation paths are unsupported.'
    }
    foreach ($part in $full.Substring(3).Split('\')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -in '.', '..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|\z)') {
            throw 'The installation path contains an unsupported Windows path component.'
        }
    }
    $drive = New-Object IO.DriveInfo($root)
    if (-not $drive.IsReady -or $drive.DriveFormat -ne 'NTFS' -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The pilot installer requires a local fixed NTFS volume.'
    }
    for ($current = $full; $null -ne $current; $current = [IO.Path]::GetDirectoryName($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links and reparse points are unsupported.' }
            if (-not $item.PSIsContainer -and (Get-PilotHardLinkCount -Path $current) -ne 1) { throw 'Hard-linked files are unsupported.' }
        }
    }
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw 'A required pilot installation file or directory is missing.' }
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if ($File -and $item.PSIsContainer) { throw 'A regular file is required.' }
        if (-not $File -and -not $item.PSIsContainer) { throw 'A directory is required.' }
    }
    return $full
}

function Assert-PilotPathLayout {
    param([Parameter(Mandatory=$true)][string]$CodeDirectory, [Parameter(Mandatory=$true)][string]$DataDirectory)
    $code = $CodeDirectory.TrimEnd('\', '/')
    $data = $DataDirectory.TrimEnd('\', '/')
    $separator = [IO.Path]::DirectorySeparatorChar
    if ([string]::Equals($code, $data, [StringComparison]::OrdinalIgnoreCase) -or
        $code.StartsWith($data + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $data.StartsWith($code + $separator, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Code and persistent data directories must be separate and must not contain each other.'
    }
}

function Assert-PilotCoreOrigin {
    param([Parameter(Mandatory=$true)][string]$CoreUrl, [string]$CoreCertificateSha256)
    $uri = $null
    if (-not [Uri]::TryCreate($CoreUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin 'http', 'https' -or $uri.AbsolutePath -ne '/' -or
        $uri.UserInfo.Length -ne 0 -or $uri.Query.Length -ne 0 -or $uri.Fragment.Length -ne 0) {
        throw 'CoreUrl must be an HTTP/HTTPS origin without credentials, path, query or fragment.'
    }
    if (-not $uri.IsLoopback -and ($uri.Scheme -ne 'https' -or $CoreCertificateSha256 -notmatch '\A[0-9a-fA-F]{64}\z')) {
        throw 'A remote Core requires verified HTTPS and an explicit SHA-256 certificate fingerprint.'
    }
    if (-not [string]::IsNullOrEmpty($CoreCertificateSha256) -and
        ($uri.Scheme -ne 'https' -or $CoreCertificateSha256 -notmatch '\A[0-9a-fA-F]{64}\z')) {
        throw 'A certificate fingerprint requires HTTPS and exactly 64 hexadecimal characters.'
    }
    return $uri
}

function Assert-PilotTrustedPath {
    param([Parameter(Mandatory=$true)][string]$Path, [switch]$AllowServiceWrite, [switch]$AllowServiceParent, [switch]$Tree,
          [string]$ServiceWriteSid, [string]$ServiceWriteRoot)
    if ($ServiceWriteSid -and (-not $ServiceWriteRoot -or $ServiceWriteSid -notmatch '\AS-1-5-80-(\d+-){4}\d+\z')) {
        throw 'A scoped virtual-service SID and data root are required.'
    }
    $trusted = @($script:AdministratorsSid, $script:SystemSid, $script:TrustedInstallerSid) + @(Get-PilotTrustedAccountSids)
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    # Entries found by listing a directory, as opposed to the requested path and its ancestors.
    $listed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $Path) { $pending.Enqueue($Path) }
    $ancestor = [IO.Path]::GetDirectoryName($Path)
    while ($null -ne $ancestor) {
        if (Test-Path -LiteralPath $ancestor) { $pending.Enqueue($ancestor) }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    $count = 0
    while ($pending.Count -ne 0) {
        $current = $pending.Dequeue()
        if (++$count -gt 8192) { throw 'The existing installation tree is too large to validate.' }
        try {
            # File.GetAttributes reads the entry itself and reports a missing one as not found.
            # Get-Item can instead return an object for a concurrently removed file whose
            # attributes read as -1, which looks like a directory and a reparse point.
            $attributes = [IO.File]::GetAttributes($current)
            $isContainer = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
            $isLink = ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            # A link is rejected below without opening it or reading through it.
            $linkCount = if ($isLink -or $isContainer) { 1 } else { Get-PilotHardLinkCount -Path $current }
            $acl = if ($isLink) { $null } else { Get-PilotAcl -Path $current -Container $isContainer }
        } catch {
            # Running services create and remove transient files in their data trees (Core's
            # SQLite rollback journal, the Agent's atomic-write temporaries), so a listed entry
            # can vanish before it is inspected. Skip a listed entry only when the file system
            # reports it missing; a name created again afterwards is a new entry, as if made
            # after the scan. The requested path, its ancestors and every other failure fail closed.
            $failure = $_.Exception.GetBaseException()
            if ($listed.Contains($current) -and ($failure -is [IO.FileNotFoundException] -or $failure -is [IO.DirectoryNotFoundException])) { continue }
            throw
        }
        if ($isLink) { throw 'Links and reparse points are unsupported.' }
        if ($linkCount -ne 1) { throw 'Hard-linked files are unsupported.' }
        $isAncestor = -not [string]::Equals($current, $Path, [StringComparison]::OrdinalIgnoreCase) -and
            $Path.StartsWith($current.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
        $currentTrusted = $trusted
        $serviceScope = -not $ServiceWriteSid -or
            [string]::Equals($current.TrimEnd('\'), $ServiceWriteRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
            $current.StartsWith($ServiceWriteRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
        if ($serviceScope -and ($AllowServiceWrite -or ($AllowServiceParent -and $isAncestor))) {
            $currentTrusted += $(if ($ServiceWriteSid) { $ServiceWriteSid } else { $script:ServiceSid })
        }
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $currentTrusted) { throw 'An existing installation path has an untrusted owner. Provision a protected location first.' }
        $rights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        # Creating a name in an ancestor is different from modifying a protected existing child.
        # Windows' standard ProgramData additionally grants Users file creation/attribute rights.
        # Permit those only on that known trusted ancestor, never on targets or arbitrary parents.
        if ($isAncestor -and $isContainer) { $rights = $rights -band (-bnot [int][Security.AccessControl.FileSystemRights]::AppendData) }
        $standardData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData).TrimEnd('\')
        if ($isAncestor -and $isContainer -and
            [string]::Equals($current.TrimEnd('\'), $standardData, [StringComparison]::OrdinalIgnoreCase)) {
            $rights = $rights -band (-bnot [int][Security.AccessControl.FileSystemRights]::Write)
        }
        # Windows' shared Start Menu Programs folder is the one ancestor some computers let the account running
        # Setup write (owner decision of 2026-10-26). It may write there, never own it; Setup's own Start Menu
        # folder below stays protected. At worst that account could change what SentinelAI's shortcut opens,
        # never what runs as a service.
        $currentWriters = $currentTrusted
        $sharedPrograms = (Get-PilotSharedProgramsPath).TrimEnd('\')
        if ($isAncestor -and $isContainer -and $sharedPrograms.Length -ne 0 -and
            [string]::Equals($current.TrimEnd('\'), $sharedPrograms, [StringComparison]::OrdinalIgnoreCase)) {
            $currentWriters += @(Get-PilotCurrentOperatorSid)
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                ($rule.FileSystemRights -band $rights) -ne 0 -and $rule.IdentityReference.Value -notin $currentWriters) {
                throw 'An existing installation path grants write access outside the trusted installer accounts.'
            }
        }
        if ($Tree -and $isContainer -and -not $isAncestor) {
            foreach ($child in Get-ChildItem -LiteralPath $current -Force) { [void]$listed.Add($child.FullName); $pending.Enqueue($child.FullName) }
        }
    }
}

function Get-PilotAcl {
    param([Parameter(Mandatory=$true)][string]$Path, [bool]$Container)
    # The access control Get-Acl reads (owner, group and access rules), but a missing entry is
    # reported only as FileNotFound or DirectoryNotFound and access denial as UnauthorizedAccess.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($Container) { return [IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.DirectoryInfo($Path))) }
        return [IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.FileInfo($Path)))
    }
    if ($Container) { return [IO.Directory]::GetAccessControl($Path) }
    return [IO.File]::GetAccessControl($Path)
}

# Windows can make the extracting administrator's own account the owner of each extracted entry. Installed
# code is owned by Administrators instead, so no account keeps owner rights and any administrator's
# checks accept it.
function Set-PilotAdministratorsOwner {
    param([Parameter(Mandatory=$true)][string]$Path)
    $administrators = New-Object Security.Principal.SecurityIdentifier($script:AdministratorsSid)
    foreach ($entry in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
        $acl = Get-PilotAcl -Path $entry.FullName -Container $entry.PSIsContainer
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $script:AdministratorsSid) {
            $acl.SetOwner($administrators)
            Set-PilotAcl -Path $entry.FullName -Container $entry.PSIsContainer -Acl $acl
        }
    }
}

function Set-PilotAcl {
    param([Parameter(Mandatory=$true)][string]$Path, [bool]$Container, [Parameter(Mandatory=$true)]$Acl)
    # Writes only the sections changed on an object read by Get-PilotAcl, so an existing service owner
    # is never rewritten (Set-Acl can try to set the owner it read back).
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($Container) { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.DirectoryInfo($Path)), $Acl) }
        else { [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.FileInfo($Path)), $Acl) }
        return
    }
    if ($Container) { [IO.Directory]::SetAccessControl($Path, $Acl) } else { [IO.File]::SetAccessControl($Path, $Acl) }
}

function Get-PilotDirectoryAclDefinition {
    param([Parameter(Mandatory=$true)][ValidateSet('CoreCode','CoreData','AgentCode','AgentData','AgentRoot','Container')][string]$Kind)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:AdministratorsSid)))
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @($script:AdministratorsSid, $script:SystemSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inheritance, $propagation, 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    # Only the console pilot grants its installing account: AgentRoot (Agent Setup's own roots) and every
    # administrators-only installation have no such entry, so any administrator can maintain them.
    if ($Kind -like 'Core*' -or $Kind -eq 'Container') {
        foreach ($sid in @(Get-PilotOperatorAccessSid)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inheritance, $propagation, 'Allow')
            [void]$acl.AddAccessRule($rule)
        }
    }
    if ($Kind -like 'Agent*' -or $Kind -eq 'Container') {
        $rights = if ($Kind -eq 'AgentData') { 'Modify' } else { 'ReadAndExecute' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($script:ServiceSid)), $rights, $inheritance, $propagation, 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-PilotDirectoryAcl {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][ValidateSet('CoreCode','CoreData','AgentCode','AgentData','AgentRoot','Container')][string]$Kind)
    Set-Acl -LiteralPath $Path -AclObject (Get-PilotDirectoryAclDefinition -Kind $Kind)
}

function New-PilotDirectoryWithAcl {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Kind)
    $parent = [IO.Path]::GetDirectoryName($Path)
    if ($null -eq $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'A protected existing parent is required.' }
    # Check using the child path so the standard ProgramData create-only ancestor policy applies;
    # this checks every existing parent immediately before the native creation operation.
    Assert-PilotTrustedPath -Path $Path
    $acl = Get-PilotDirectoryAclDefinition -Kind $Kind
    # Create the new directory with its restricted DACL in the same native operation.
    # An inherited writable window is unnecessary, including under the standard ProgramData parent.
    if ($PSVersionTable.PSVersion.Major -ge 6) { [void][IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path) }
    else { [void][IO.Directory]::CreateDirectory($Path, $acl) }
}

function Set-PilotFileAcl {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][ValidateSet('CoreConfig','AgentConfig','AgentToken','Receipt')][string]$Kind)
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:AdministratorsSid)))
    foreach ($sid in @($script:AdministratorsSid, $script:SystemSid)) {
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')))
    }
    if ($Kind -eq 'CoreConfig') {
        foreach ($sid in @(Get-PilotOperatorAccessSid)) {
            [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')))
        }
    }
    if ($Kind -in 'AgentConfig', 'AgentToken') {
        $rights = if ($Kind -eq 'AgentToken') { 'Read, Delete' } else { 'Read' }
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($script:ServiceSid)), $rights, 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-PilotProtectedDirectory {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Kind)
    if (-not (Test-Path -LiteralPath $Path)) {
        $parent = [IO.Path]::GetDirectoryName($Path)
        if (-not (Test-Path -LiteralPath $parent)) { New-PilotProtectedDirectory -Path $parent -Kind Container }
        New-PilotDirectoryWithAcl -Path $Path -Kind $Kind
    }
    Assert-PilotTrustedPath -Path $Path -AllowServiceWrite:($Kind -eq 'AgentData')
    Set-PilotDirectoryAcl -Path $Path -Kind $Kind
}

function Ensure-PilotProtectedParent {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-PilotProtectedDirectory -Path $Path -Kind Container }
    else { Assert-PilotTrustedPath -Path $Path }
}

function Write-PilotProtectedFile {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Content, [Parameter(Mandatory=$true)][string]$Kind)
    if (Test-Path -LiteralPath $Path) { throw 'A protected pilot configuration or token already exists; it is not overwritten.' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $completed = $false
    try {
        Set-PilotFileAcl -Path $Path -Kind $Kind
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $completed = $true
    } finally {
        $stream.Dispose()
        if (-not $completed -and (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $Path -Force }
    }
}

function Invoke-PilotPrepare {
    param([string]$BundleDirectory, [string]$PublicKeyPath, [string]$KeyId, [string]$Environment, [string]$Channel,
          [ValidateSet('Core','Agent')][string]$Component, [string]$OutputDirectory)
    $updaterDirectory = Assert-PilotPath -Path (Join-Path $BundleDirectory 'updater') -MustExist
    Assert-PilotTrustedPath -Path $updaterDirectory -Tree
    $updater = Join-Path $updaterDirectory 'SentinelAI.Updater.exe'
    $updater = Assert-PilotPath -Path $updater -MustExist -File
    Assert-PilotTrustedPath -Path $updater
    $stem = $Component.ToLowerInvariant()
    $manifest = Assert-PilotPath -Path (Join-Path $BundleDirectory "$stem.manifest.json") -MustExist -File
    $package = Assert-PilotPath -Path (Join-Path $BundleDirectory "$stem.zip") -MustExist -File
    $arguments = @('prepare', '--manifest', $manifest, '--package', $package, '--public-key', $PublicKeyPath,
        '--key-id', $KeyId, '--environment', $Environment, '--channel', $Channel,
        '--artifact-id', "sentinelai-$stem-win-x64", '--installed-version', '0.0.0', '--output', $OutputDirectory)
    # The Updater stops itself after five minutes; a stalled Updater that cannot must fail this step, not hang Setup.
    $result = Invoke-PilotBoundedProcess -FilePath $updater -Arguments $arguments -WorkingDirectory $updaterDirectory -TimeoutSeconds $script:PilotPrepareTimeoutSeconds
    if ($result.Outcome -ceq 'Timeout' -or ($result.Outcome -ceq 'Exited' -and $result.ExitCode -eq 2)) {
        throw 'The signed pilot package preparation did not finish within its time limit.'
    }
    if ($result.Outcome -cne 'Exited' -or $result.ExitCode -ne 0 -or $result.Output -cnotmatch '\A[^\r\n]{1,1024}\r?\n\z') {
        throw 'The signed pilot package was rejected.'
    }
    try { $metadata = $result.Output.TrimEnd() | ConvertFrom-Json } catch { throw 'The signed pilot package metadata is invalid.' }
    if ($metadata.version -notmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
        $metadata.artifactId -cne "sentinelai-$stem-win-x64" -or $metadata.channel -cne $Channel -or $metadata.environment -cne $Environment) {
        throw 'The signed pilot package metadata does not match the installation policy.'
    }
    return $metadata
}

function Get-PilotAgentImagePath {
    param([Parameter(Mandatory=$true)][string]$ExecutablePath, [Parameter(Mandatory=$true)][string]$ConfigurationPath)
    if ($ExecutablePath.Contains('"') -or $ConfigurationPath.Contains('"') -or
        $ExecutablePath -match '[\r\n]' -or $ConfigurationPath -match '[\r\n]') { throw 'The service path is invalid.' }
    return '"' + $ExecutablePath + '" --config "' + $ConfigurationPath + '"'
}

function ConvertTo-PilotWindowsArgument {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Argument)
    if ($Argument.Contains([string][char]0)) { throw 'A native argument contains an invalid character.' }
    $encoded = New-Object Text.StringBuilder
    [void]$encoded.Append('"')
    $slashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$encoded.Append(('\' * (2 * $slashes + 1)))
            [void]$encoded.Append('"')
        } else {
            [void]$encoded.Append(('\' * $slashes))
            [void]$encoded.Append($character)
        }
        $slashes = 0
    }
    [void]$encoded.Append(('\' * (2 * $slashes)))
    [void]$encoded.Append('"')
    return $encoded.ToString()
}

function Invoke-PilotBoundedProcess {
    param([Parameter(Mandatory=$true)][string]$FilePath, [Parameter(Mandatory=$true)][string[]]$Arguments,
          [Parameter(Mandatory=$true)][string]$WorkingDirectory, [ValidateRange(1,600)][int]$TimeoutSeconds)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $start.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $start.Arguments = (@($Arguments | ForEach-Object { ConvertTo-PilotWindowsArgument -Argument $_ }) -join ' ')
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $released = $true
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            if (-not $process.WaitForExit(5000) -or -not $stdout.Wait(5000)) { $released = $false }
            return [pscustomobject]@{ Outcome = 'Timeout'; ExitCode = -1; Output = '' }
        }
        # End of output depends on every process that inherited the pipe; never wait for it unbounded.
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
            $released = $false
            return [pscustomobject]@{ Outcome = 'OutputHeld'; ExitCode = $process.ExitCode; Output = '' }
        }
        return [pscustomobject]@{ Outcome = 'Exited'; ExitCode = $process.ExitCode; Output = [string]$stdout.Result }
    } finally {
        if ($released) { $process.Dispose() } else { [void]$script:PilotAbandonedProcesses.Add($process) }
    }
}

function Invoke-PilotSc {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Encode the Windows argv explicitly: PowerShell 5.1's native invocation can otherwise
    # remove the literal quotes required inside the SCM binPath value.
    $start.Arguments = (@($Arguments | ForEach-Object { ConvertTo-PilotWindowsArgument -Argument $_ }) -join ' ')
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch { }
            throw 'The Windows service operation timed out.'
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'The Windows service operation failed.' }
    } finally { $process.Dispose() }
}

function Get-PilotService {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAIAgent'"
}

function Register-PilotService {
    param([Parameter(Mandatory=$true)][string]$ExecutablePath, [Parameter(Mandatory=$true)][string]$ConfigurationPath)
    $imagePath = Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath
    Invoke-PilotSc -Arguments @('create', $script:ServiceName, 'binPath=', $imagePath, 'start=', 'auto',
        'obj=', $script:ServiceAccount, 'DisplayName=', 'SentinelAI Endpoint Agent')
}

function Start-PilotService {
    param([int]$TimeoutSeconds = 180)
    $service = Get-Service -Name $script:ServiceName
    try {
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { $service.Start() }
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds($TimeoutSeconds))
    }
    finally { $service.Dispose() }
}

function Stop-PilotService {
    param([int]$TimeoutSeconds = 180)
    $service = Get-Service -Name $script:ServiceName
    try {
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            $service.Stop()
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($TimeoutSeconds))
        }
    } finally { $service.Dispose() }
}

function Remove-PilotService {
    Invoke-PilotSc -Arguments @('delete', $script:ServiceName)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($null -eq (Get-PilotService)) { return }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt 15)
    throw 'The Agent service is still marked for deletion. Close service-management handles before retrying.'
}

function Invoke-PilotJsonRequest {
    param([Parameter(Mandatory=$true)][string]$Uri, [ValidateSet('GET','POST')][string]$Method = 'GET',
          [string]$Body, [string]$AccessToken, [string]$CoreCertificateSha256)
    Initialize-PilotNativeHelpers
    $request = [Net.HttpWebRequest]::CreateHttp($Uri)
    $request.Method = $Method
    $request.AllowAutoRedirect = $false
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $request.Accept = 'application/json'
    $request.ServerCertificateValidationCallback = [SentinelAI.Pilot.Native]::CertificateValidator($CoreCertificateSha256)
    if ($AccessToken) { $request.Headers['Authorization'] = 'Bearer ' + $AccessToken }
    if ($null -ne $Body -and $Body.Length -ne 0) {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Body)
        $request.ContentType = 'application/json'
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    $response = $null
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt 65536 -or
            -not $response.ContentType.StartsWith('application/json', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The authenticated Core request failed.'
        }
        $source = $response.GetResponseStream()
        $buffer = New-Object byte[] 4096
        $result = New-Object IO.MemoryStream
        try {
            while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($result.Length + $read -gt 65536) { throw 'The Core response exceeded the pilot response limit.' }
                $result.Write($buffer, 0, $read)
            }
            $json = (New-Object Text.UTF8Encoding($false, $true)).GetString($result.ToArray())
            return $json | ConvertFrom-Json
        } finally { $result.Dispose(); $source.Dispose(); [Array]::Clear($buffer, 0, $buffer.Length) }
    } catch { throw 'The authenticated Core request failed. Check the running Core, credentials and verified TLS configuration.' }
    finally { if ($null -ne $response) { $response.Dispose() } }
}

function Request-PilotEnrollmentToken {
    param([Parameter(Mandatory=$true)][string]$CoreUrl, [string]$CoreCertificateSha256, [PSCredential]$AdminCredential)
    if ($null -eq $AdminCredential) { $AdminCredential = Get-Credential -Message 'Enter the existing SentinelAI Core administrator credentials.' }
    if ($null -eq $AdminCredential -or [string]::IsNullOrWhiteSpace($AdminCredential.UserName)) { throw 'Administrator credentials are required for one-use enrollment.' }
    $password = $null
    $body = $null
    $session = $null
    try {
        $password = $AdminCredential.GetNetworkCredential().Password
        $body = @{ username = $AdminCredential.UserName; password = $password } | ConvertTo-Json -Compress
        $session = Invoke-PilotJsonRequest -Uri ($CoreUrl + '/api/auth/login') -Method POST -Body $body -CoreCertificateSha256 $CoreCertificateSha256
        if ($session.tokenType -cne 'Bearer' -or [string]::IsNullOrWhiteSpace($session.accessToken) -or $session.accessToken.Length -gt 8192) {
            throw 'The Core login response is invalid.'
        }
        $response = Invoke-PilotJsonRequest -Uri ($CoreUrl + '/api/admin/enrollment-tokens') -Method POST -AccessToken $session.accessToken -CoreCertificateSha256 $CoreCertificateSha256
        if ($response.token -notmatch '\A[0-9a-fA-F]{64}\z' -or [DateTimeOffset]::Parse($response.expiresUtc) -le [DateTimeOffset]::UtcNow) {
            throw 'The one-use enrollment response is invalid.'
        }
        return $response.token
    } catch { throw 'Could not issue a one-use enrollment token. No service was installed.' }
    finally { $password = $null; $body = $null; $session = $null }
}

function Read-PilotGuidFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    $text = (Read-PilotUtf8Document -Path $Path -MaximumBytes 64).Trim()
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParseExact($text, 'D', [ref]$guid) -or $guid -eq [Guid]::Empty) { throw 'The Agent identity receipt is invalid.' }
    return $guid.ToString('D')
}

function Wait-PilotAgentEnrollment {
    param([Parameter(Mandatory=$true)][string]$DataDirectory, [int]$TimeoutSeconds = 180)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $service = Get-PilotService
        if ($null -eq $service -or $service.State -ne 'Running') { throw 'The Agent service stopped before enrollment completed.' }
        $endpoint = Read-PilotGuidFile -Path (Join-Path $DataDirectory 'endpoint-id')
        $installation = Read-PilotGuidFile -Path (Join-Path $DataDirectory 'installation-id')
        if ($endpoint -and $installation -and (Test-Path -LiteralPath (Join-Path $DataDirectory 'enrollment-state') -PathType Leaf) -and
            -not (Test-Path -LiteralPath (Join-Path $DataDirectory 'pilot-enrollment-token'))) {
            return [PSCustomObject]@{ endpointId = $endpoint; installationId = $installation }
        }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw 'Agent enrollment did not complete within the configured timeout. State and code were preserved for diagnosis.'
}

function Read-PilotInstallationReceipt {
    param([string]$Path, [string]$Component, [string]$CodeDirectory, [string]$DataDirectory,
          [string]$ServiceWriteSid, [string]$ServiceWriteRoot)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    Assert-PilotTrustedPath -Path $Path -AllowServiceParent:($Component -eq 'Agent' -or [bool]$ServiceWriteSid) -ServiceWriteSid $ServiceWriteSid -ServiceWriteRoot $ServiceWriteRoot
    try {
        $json = Read-PilotUtf8Document -Path $Path -MaximumBytes 4096
        $receipt = Read-PilotStrictJson -Json $json
        Assert-PilotObjectProperties -Object $receipt -Names @('format','component','version','codeDirectory','dataDirectory','coreUrl','environment','channel','serviceName','serviceAccountSid')
    } catch { throw 'The pilot installation receipt is invalid.' }
    if ($receipt.format -cne 'sentinelai-pilot-v1' -or $receipt.component -cne $Component -or
        $receipt.codeDirectory -cne $CodeDirectory -or $receipt.dataDirectory -cne $DataDirectory -or
        $receipt.serviceName -cne $(if ($Component -eq 'Agent') { $script:ServiceName } else { '' }) -or
        $receipt.serviceAccountSid -cne $(if ($Component -eq 'Agent') { $script:ServiceSid } else { '' })) {
        throw 'The existing pilot installation does not match the selected paths or fixed service account.'
    }
    return $receipt
}

function Read-PilotUtf8Document {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][ValidateRange(1,65536)][int]$MaximumBytes)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw 'The pilot document exceeds its bounded size.' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'The pilot document was truncated.' }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) { throw 'The pilot document grew during validation.' }
        return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes)
    } finally { $stream.Dispose() }
}

function Read-PilotStrictJson {
    param([Parameter(Mandatory=$true)][string]$Json)
    # These small schemas contain only objects and string values. Validate that complete grammar
    # before ConvertFrom-Json, whose PowerShell versions may accept comments/trailing commas.
    $tokens = [regex]::Matches($Json, '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{},:]')
    $end = 0
    foreach ($token in $tokens) {
        if ($Json.Substring($end, $token.Index - $end) -notmatch '\A[ \t\r\n]*\z') { throw 'The pilot JSON document is not strict JSON.' }
        $end = $token.Index + $token.Length
    }
    if ($Json.Substring($end) -notmatch '\A[ \t\r\n]*\z' -or $tokens.Count -lt 2 -or $tokens[0].Value -ne '{') {
        throw 'The pilot JSON document is not a strict JSON object.'
    }
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $states = New-Object 'System.Collections.Generic.List[string]'
    $states.Add('key-or-end')
    for ($index = 1; $index -lt $tokens.Count; $index++) {
        if ($states.Count -eq 0) { throw 'Trailing content in the pilot JSON document is unsupported.' }
        $last = $states.Count - 1
        $value = $tokens[$index].Value
        $state = $states[$last]
        if ($state -in 'key-or-end', 'key') {
            if ($value -eq '}' -and $state -eq 'key-or-end') { $states.RemoveAt($last); continue }
            if (-not $value.StartsWith('"')) { throw 'The pilot JSON object has an invalid property.' }
            $name = $value | ConvertFrom-Json
            if (-not $names.Add($name)) { throw 'Duplicate JSON configuration fields are unsupported.' }
            $states[$last] = 'colon'
        } elseif ($state -eq 'colon') {
            if ($value -ne ':') { throw 'The pilot JSON property is missing its separator.' }
            $states[$last] = 'value'
        } elseif ($state -eq 'value') {
            $states[$last] = 'comma-or-end'
            if ($value -eq '{') {
                if ($states.Count -ge 8) { throw 'The pilot JSON document is too deeply nested.' }
                $states.Add('key-or-end')
            } elseif (-not $value.StartsWith('"')) { throw 'Pilot configuration values must be strings or objects.' }
        } elseif ($state -eq 'comma-or-end') {
            if ($value -eq ',') { $states[$last] = 'key' }
            elseif ($value -eq '}') { $states.RemoveAt($last) }
            else { throw 'The pilot JSON object has an invalid separator.' }
        }
    }
    if ($states.Count -ne 0) { throw 'The pilot JSON document is incomplete.' }
    return $Json | ConvertFrom-Json -ErrorAction Stop
}

function Assert-PilotObjectProperties {
    param([Parameter(Mandatory=$true)]$Object, [Parameter(Mandatory=$true)][string[]]$Names)
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Names.Count) { throw 'The pilot configuration contains missing or unsupported fields.' }
    foreach ($name in $actual) {
        if ($name -cnotin $Names) { throw 'The pilot configuration contains missing or unsupported fields.' }
    }
}

function Get-PilotCoreLocalNetworkSettings {
    param([Parameter(Mandatory=$true)]$CoreSettings)
    # Core's local-network listener: the fixed port and the exact SHA-256 Agents pin, together or not at all.
    $names = @($CoreSettings.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names -cnotcontains 'LocalNetworkPort' -and $names -cnotcontains 'LocalNetworkCertificateSha256') {
        Assert-PilotObjectProperties -Object $CoreSettings -Names @('DataDirectory')
        return $null
    }
    Assert-PilotObjectProperties -Object $CoreSettings -Names @('DataDirectory','LocalNetworkPort','LocalNetworkCertificateSha256')
    if ($CoreSettings.LocalNetworkPort -isnot [string] -or $CoreSettings.LocalNetworkPort -cne [string]$script:PilotLocalNetworkPort -or
        $CoreSettings.LocalNetworkCertificateSha256 -isnot [string] -or $CoreSettings.LocalNetworkCertificateSha256 -cnotmatch '\A[0-9A-F]{64}\z') {
        throw 'The Core local-network configuration is invalid.'
    }
    return [pscustomobject]@{ Port = $script:PilotLocalNetworkPort; CertificateSha256 = $CoreSettings.LocalNetworkCertificateSha256 }
}

function Get-PilotCoreLocalNetwork {
    param([Parameter(Mandatory=$true)][string]$Path, [string]$ServiceWriteSid, [string]$ServiceWriteRoot)
    # Called after the configuration was validated at its trusted protected path.
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    Assert-PilotTrustedPath -Path $Path -AllowServiceParent:([bool]$ServiceWriteSid) -ServiceWriteSid $ServiceWriteSid -ServiceWriteRoot $ServiceWriteRoot
    $config = Read-PilotStrictJson -Json (Read-PilotUtf8Document -Path $Path -MaximumBytes 8192)
    Assert-PilotObjectProperties -Object $config -Names @('urls','SentinelAI')
    return Get-PilotCoreLocalNetworkSettings -CoreSettings $config.SentinelAI
}

function Assert-PilotExistingConfiguration {
    param([string]$Path, [ValidateSet('Core','Agent')][string]$Component, [string]$DataDirectory,
          [string]$CoreUrl, [string]$CoreCertificateSha256, [string]$ServiceWriteSid, [string]$ServiceWriteRoot,
          [string]$LocalNetworkCertificateSha256, [switch]$AnyLocalNetwork)
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    Assert-PilotTrustedPath -Path $Path -AllowServiceParent:($Component -eq 'Agent' -or [bool]$ServiceWriteSid) -ServiceWriteSid $ServiceWriteSid -ServiceWriteRoot $ServiceWriteRoot
    $config = Read-PilotStrictJson -Json (Read-PilotUtf8Document -Path $Path -MaximumBytes 8192)
    if ($Component -eq 'Core') {
        Assert-PilotObjectProperties -Object $config -Names @('urls','SentinelAI')
        $network = Get-PilotCoreLocalNetworkSettings -CoreSettings $config.SentinelAI
        if ($config.urls -isnot [string] -or $config.urls -cne $CoreUrl -or
            $config.SentinelAI.DataDirectory -isnot [string] -or $config.SentinelAI.DataDirectory -cne $DataDirectory) {
            throw 'Existing Core configuration does not match the selected pilot paths and origin.'
        }
        # Maintenance keeps whichever role the installation has; a retried install must match exactly.
        if (-not $AnyLocalNetwork -and (($null -eq $network) -ne [string]::IsNullOrEmpty($LocalNetworkCertificateSha256) -or
            ($null -ne $network -and $network.CertificateSha256 -cne $LocalNetworkCertificateSha256))) {
            throw 'Existing Core configuration does not match the selected local-network role.'
        }
    } else {
        Assert-PilotObjectProperties -Object $config -Names @('Agent')
        $names = @('CoreUrl','DataDirectory','EnrollmentTokenFile')
        if ($CoreCertificateSha256) { $names += 'CoreCertificateSha256' }
        Assert-PilotObjectProperties -Object $config.Agent -Names $names
        if ($config.Agent.CoreUrl -isnot [string] -or $config.Agent.CoreUrl -cne $CoreUrl -or
            $config.Agent.DataDirectory -isnot [string] -or $config.Agent.DataDirectory -cne $DataDirectory -or
            $config.Agent.EnrollmentTokenFile -isnot [string] -or
            $config.Agent.EnrollmentTokenFile -cne (Join-Path $DataDirectory 'pilot-enrollment-token') -or
            ($CoreCertificateSha256 -and ($config.Agent.CoreCertificateSha256 -isnot [string] -or
                $config.Agent.CoreCertificateSha256 -cne $CoreCertificateSha256.ToUpperInvariant()))) {
            throw 'Existing Agent configuration does not match the selected pilot paths, origin and certificate.'
        }
    }
}

function Assert-PilotOwnedService {
    param([Parameter(Mandatory=$true)]$Service, [Parameter(Mandatory=$true)]$Receipt, [string]$ExecutablePath, [string]$ConfigurationPath)
    $expected = Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath
    if ($Service.Name -cne $script:ServiceName -or
        -not [string]::Equals($Service.PathName, $expected, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-PilotServiceAccountSid -AccountName $Service.StartName) -cne $script:ServiceSid -or
        $Receipt.serviceAccountSid -cne $script:ServiceSid) {
        throw 'The existing Windows service is not owned by this pilot installation. It will not be changed.'
    }
}

function Get-PilotServiceAccountSid {
    param([Parameter(Mandatory=$true)][string]$AccountName)
    if ($AccountName -match '\ANT AUTHORITY\\LOCAL ?SERVICE\z') { return $script:ServiceSid }
    try {
        return (New-Object Security.Principal.NTAccount($AccountName)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Assert-PilotPreparedCodeMatches {
    param([string]$PreparedDirectory, [string]$CodeDirectory)
    $expected = @(Get-ChildItem -LiteralPath $PreparedDirectory -Recurse -File -Force)
    $actual = @(Get-ChildItem -LiteralPath $CodeDirectory -Recurse -File -Force)
    if ($expected.Count -ne $actual.Count) { throw 'Existing pilot code differs from the signed package; it is not overwritten.' }
    foreach ($file in $expected) {
        $relative = $file.FullName.Substring($PreparedDirectory.Length).TrimStart('\', '/')
        $installed = Join-Path $CodeDirectory $relative
        if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or
            (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash) {
            throw 'Existing pilot code differs from the signed package; it is not overwritten.'
        }
    }
}

function Invoke-PilotInstall {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ValidateSet('Core','Agent','UninstallAgent')][string]$Component,
          [string]$BundleDirectory, [string]$PublicKeyPath, [string]$KeyId,
          [ValidateSet('development','production')][string]$Environment,
          [ValidateSet('stable','pilot','beta')][string]$Channel,
          [string]$CodeDirectory, [string]$DataDirectory, [string]$CoreUrl = 'http://127.0.0.1:5000',
          [string]$CoreCertificateSha256, [ValidateRange(10,600)][int]$TimeoutSeconds = 180, [PSCredential]$AdminCredential,
          [string]$EnrollmentToken, [string]$LocalNetworkCertificateSha256)
    Assert-PilotSupportedHost
    if ($LocalNetworkCertificateSha256 -and ($Component -cne 'Core' -or $LocalNetworkCertificateSha256 -cnotmatch '\A[0-9A-F]{64}\z')) {
        throw 'A local-network certificate fingerprint applies only to Core and must be an uppercase SHA-256.'
    }
    # Validate supplied input explicitly so releasing the borrowed token below
    # cannot trigger parameter-variable validation during null cleanup.
    if ($PSBoundParameters.ContainsKey('EnrollmentToken') -and
        ($EnrollmentToken -cnotmatch '\A[0-9a-fA-F]{64}\z' -or $Component -cne 'Agent' -or $null -ne $AdminCredential)) {
        throw 'An explicit one-use token applies only to Agent enrollment and cannot be combined with administrator credentials.'
    }
    $kind = if ($Component -eq 'Core') { 'Core' } else { 'Agent' }
    if ($Environment) { $Environment = $Environment.ToLowerInvariant() }
    if ($Channel) { $Channel = $Channel.ToLowerInvariant() }
    if ([string]::IsNullOrWhiteSpace($CodeDirectory)) { $CodeDirectory = Join-Path $env:ProgramFiles ('SentinelAI\' + $kind) }
    if ([string]::IsNullOrWhiteSpace($DataDirectory)) { $DataDirectory = Join-Path $env:ProgramData ('SentinelAI\' + $kind) }
    $CodeDirectory = Assert-PilotPath -Path $CodeDirectory
    $DataDirectory = Assert-PilotPath -Path $DataDirectory
    Assert-PilotPathLayout -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory
    Assert-PilotTrustedPath -Path $CodeDirectory -Tree
    Assert-PilotTrustedPath -Path $DataDirectory -Tree -AllowServiceWrite:($kind -eq 'Agent')
    $configurationPath = Join-Path $DataDirectory 'pilot-config.json'
    $receiptPath = Join-Path $DataDirectory 'pilot-installation.json'
    $executable = Join-Path $CodeDirectory ('SentinelAI.' + $kind + '.exe')
    $receipt = Read-PilotInstallationReceipt -Path $receiptPath -Component $kind -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory
    $service = if ($kind -eq 'Agent') { Get-PilotService } else { $null }
    if ($null -ne $service) {
        if ($null -eq $receipt) { throw 'An existing SentinelAIAgent service has no matching pilot ownership receipt; it will not be changed.' }
        Assert-PilotOwnedService -Service $service -Receipt $receipt -ExecutablePath $executable -ConfigurationPath $configurationPath
    }
    if ($Component -eq 'UninstallAgent') {
        if ($null -eq $receipt) { throw 'A matching pilot installation receipt is required to uninstall the Agent service.' }
        if ($null -ne $service) { Stop-PilotService -TimeoutSeconds $TimeoutSeconds; Remove-PilotService }
        return [PSCustomObject]@{ component = 'Agent'; serviceRemoved = $true; dataPreserved = $true; codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory }
    }
    if ([string]::IsNullOrWhiteSpace($BundleDirectory) -or [string]::IsNullOrWhiteSpace($PublicKeyPath) -or
        $KeyId -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z' -or
        [string]::IsNullOrWhiteSpace($Environment) -or [string]::IsNullOrWhiteSpace($Channel)) {
        throw 'Specify the signed bundle, an out-of-band public key, key ID, environment and channel explicitly.'
    }
    $BundleDirectory = Assert-PilotPath -Path $BundleDirectory -MustExist
    $PublicKeyPath = Assert-PilotPath -Path $PublicKeyPath -MustExist -File
    Assert-PilotTrustedPath -Path $PublicKeyPath
    if ($PublicKeyPath.StartsWith($BundleDirectory.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Provision the trusted public key separately from the delivered bundle through an out-of-band channel.'
    }
    $coreUri = Assert-PilotCoreOrigin -CoreUrl $CoreUrl -CoreCertificateSha256 $CoreCertificateSha256
    $origin = $coreUri.GetLeftPart([UriPartial]::Authority)
    if ($kind -eq 'Core' -and (-not $coreUri.IsLoopback -or $coreUri.Scheme -ne 'http' -or $CoreCertificateSha256)) {
        throw 'The pilot Core configuration binds only to an explicit loopback HTTP origin. Remote TLS termination is provisioned separately.'
    }
    if ((Test-Path -LiteralPath $CodeDirectory) -and @(Get-ChildItem -LiteralPath $CodeDirectory -Force).Count -ne 0 -and $null -eq $receipt) {
        throw 'The code directory is nonempty and is not owned by this pilot installation.'
    }
    if ($null -eq $receipt -and (Test-Path -LiteralPath $configurationPath)) { throw 'An unknown existing pilot configuration will not be overwritten.' }
    if ($null -eq $receipt -and (Test-Path -LiteralPath $DataDirectory) -and @(Get-ChildItem -LiteralPath $DataDirectory -Force).Count -ne 0) {
        throw 'A fresh pilot install requires an empty data directory; existing state will not be migrated or deleted.'
    }
    Ensure-PilotProtectedParent -Path ([IO.Path]::GetDirectoryName($CodeDirectory))
    $prepared = Join-Path ([IO.Path]::GetDirectoryName($CodeDirectory)) ('.sentinelai-pilot-' + [Guid]::NewGuid().ToString('N'))
    $createdService = $false
    $createdToken = $false
    $tokenPath = Join-Path $DataDirectory 'pilot-enrollment-token'
    try {
        $metadata = Invoke-PilotPrepare -BundleDirectory $BundleDirectory -PublicKeyPath $PublicKeyPath -KeyId $KeyId -Environment $Environment -Channel $Channel -Component $kind -OutputDirectory $prepared
        Assert-PilotTrustedPath -Path $prepared -Tree
        if ($null -ne $receipt) {
            if ($receipt.version -cne $metadata.version -or $receipt.coreUrl -cne $origin -or
                $receipt.environment -cne $Environment -or $receipt.channel -cne $Channel) {
                throw 'This workflow supports initial installation or retry of the same signed package, not upgrades or Core/account changes.'
            }
            Assert-PilotPreparedCodeMatches -PreparedDirectory $prepared -CodeDirectory $CodeDirectory
            Assert-PilotExistingConfiguration -Path $configurationPath -Component $kind -DataDirectory $DataDirectory -CoreUrl $origin -CoreCertificateSha256 $CoreCertificateSha256 -LocalNetworkCertificateSha256 $LocalNetworkCertificateSha256
        }
        New-PilotProtectedDirectory -Path $DataDirectory -Kind ($kind + 'Data')
        if ($null -eq $receipt) {
            $config = if ($kind -eq 'Core') {
                $settings = @{ DataDirectory = $DataDirectory }
                if ($LocalNetworkCertificateSha256) {
                    # The central role: Core also serves Agents on the local network with its own pinned certificate.
                    $settings.LocalNetworkPort = [string]$script:PilotLocalNetworkPort
                    $settings.LocalNetworkCertificateSha256 = $LocalNetworkCertificateSha256
                }
                @{ urls = $origin; SentinelAI = $settings }
            } else {
                $settings = @{ CoreUrl = $origin; DataDirectory = $DataDirectory; EnrollmentTokenFile = $tokenPath }
                if ($CoreCertificateSha256) { $settings.CoreCertificateSha256 = $CoreCertificateSha256.ToUpperInvariant() }
                @{ Agent = $settings }
            }
            Write-PilotProtectedFile -Path $configurationPath -Content ($config | ConvertTo-Json -Depth 4) -Kind ($kind + 'Config')
            if (Test-Path -LiteralPath $CodeDirectory) { Remove-Item -LiteralPath $CodeDirectory -Force }
            Move-Item -LiteralPath $prepared -Destination $CodeDirectory
            Set-PilotDirectoryAcl -Path $CodeDirectory -Kind ($kind + 'Code')
            Set-PilotAdministratorsOwner -Path $CodeDirectory
            $newReceipt = @{ format = 'sentinelai-pilot-v1'; component = $kind; version = $metadata.version;
                codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory; coreUrl = $origin;
                environment = $Environment; channel = $Channel;
                serviceName = $(if ($kind -eq 'Agent') { $script:ServiceName } else { '' });
                serviceAccountSid = $(if ($kind -eq 'Agent') { $script:ServiceSid } else { '' }) }
            Write-PilotProtectedFile -Path $receiptPath -Content ($newReceipt | ConvertTo-Json -Compress) -Kind Receipt
        }
        if ($kind -eq 'Core') {
            return [PSCustomObject]@{ component = 'Core'; version = $metadata.version; codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory; configurationPath = $configurationPath; coreUrl = $origin }
        }
        if ($null -ne $service -and $service.State -eq 'Running') {
            $identity = Wait-PilotAgentEnrollment -DataDirectory $DataDirectory -TimeoutSeconds $TimeoutSeconds
        } else {
            if (-not (Test-Path -LiteralPath (Join-Path $DataDirectory 'enrollment-state'))) {
                if (Test-Path -LiteralPath $tokenPath) { throw 'A pending one-use enrollment file exists; inspect the previous attempt before retrying.' }
                $token = if ($EnrollmentToken) { $EnrollmentToken } else {
                    Request-PilotEnrollmentToken -CoreUrl $origin -CoreCertificateSha256 $CoreCertificateSha256 -AdminCredential $AdminCredential
                }
                try {
                    Write-PilotProtectedFile -Path $tokenPath -Content $token -Kind AgentToken
                    $createdToken = $true
                } finally { $token = $null; $EnrollmentToken = $null }
            }
            if ($null -eq $service) { Register-PilotService -ExecutablePath $executable -ConfigurationPath $configurationPath; $createdService = $true }
            Start-PilotService -TimeoutSeconds $TimeoutSeconds
            $identity = Wait-PilotAgentEnrollment -DataDirectory $DataDirectory -TimeoutSeconds $TimeoutSeconds
        }
        return [PSCustomObject]@{ component = 'Agent'; version = $metadata.version; serviceName = $script:ServiceName;
            serviceAccountSid = $script:ServiceSid; codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory;
            endpointId = $identity.endpointId; installationId = $identity.installationId; coreUrl = $origin }
    } catch {
        if ($createdService) {
            try {
                $owned = Get-PilotService
                if ($null -ne $owned) {
                    $proof = Read-PilotInstallationReceipt -Path $receiptPath -Component Agent -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory
                    Assert-PilotOwnedService -Service $owned -Receipt $proof -ExecutablePath $executable -ConfigurationPath $configurationPath
                    Stop-PilotService -TimeoutSeconds $TimeoutSeconds
                    Remove-PilotService
                }
            } catch { }
        }
        if ($createdToken -and (Test-Path -LiteralPath $tokenPath)) { Remove-Item -LiteralPath $tokenPath -Force }
        throw 'Pilot installation did not complete. Code, configuration and persistent state were retained; inspect the service status and retry with the same signed package.'
    } finally {
        if (Test-Path -LiteralPath $prepared) { Remove-Item -LiteralPath $prepared -Recurse -Force }
    }
}

Export-ModuleMember -Function *-Pilot*
