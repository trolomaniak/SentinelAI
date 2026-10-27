# Portable checks of the actual lifecycle/receipt adapter. Windows acceptance
# separately verifies real ACLs, SCM operations, DPAPI and executable health.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:checks = 0
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:ServiceName = 'SentinelAIAgent'
$script:ServiceSid = 'S-1-5-19'
$script:CoreServiceName = 'SentinelAICore'
$script:CoreServiceAccount = 'NT SERVICE\SentinelAICore'
$script:CoreServiceSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'
$script:PilotLocalNetworkPort = 5443
$script:fixture = $null
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-lifecycle-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null

function Assert-LifecycleTest([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw ('Lifecycle regression: ' + $Label) }
    $script:checks++
}
function Reject-LifecycleTest([scriptblock]$Operation, [string]$Label) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    Assert-LifecycleTest $rejected $Label
}

# Load the existing portable policy functions into this isolated test process,
# so they use the OS boundary stubs below rather than a module's Windows scope.
function Import-LifecycleTestFunctions([string]$Path, [string[]]$Names) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'The source policy could not be parsed.' }
    foreach ($name in $Names) {
        $node = $ast.Find({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -ceq $name }, $true)
        if ($null -eq $node) { throw ('Missing source policy: ' + $name) }
        # Defining the function at script scope keeps the implementation exact.
        Invoke-Expression ($node.Extent.Text.Replace(('function ' + $name), ('function script:' + $name)))
    }
}
Import-LifecycleTestFunctions (Join-Path $repo 'installer/pilot/PilotInstaller.psm1') @(
    'Read-PilotUtf8Document','Read-PilotStrictJson','Assert-PilotObjectProperties','Read-PilotInstallationReceipt',
    'Read-PilotGuidFile','Assert-PilotExistingConfiguration','Assert-PilotCoreOrigin',
    'Get-PilotAgentImagePath','Assert-PilotOwnedService','Get-PilotServiceAccountSid',
    'Get-PilotCoreLocalNetworkSettings','Get-PilotCoreLocalNetwork')
Import-LifecycleTestFunctions (Join-Path $repo 'installer/pilot/CoreServiceInstaller.psm1') @('Assert-CoreServiceOwned','Assert-CoreServiceDatabase',
    'Get-CoreServiceLocalNetwork','Get-CoreServiceLocalNetworkPort','Read-CoreServiceReceipt')
. (Join-Path $repo 'installer/setup/SetupLifecycle.ps1')

function Assert-PilotPath {
    param([string]$Path, [switch]$MustExist, [switch]$File)
    if ($MustExist -and -not (Test-Path -LiteralPath $Path)) { throw 'A fixture path is missing.' }
    if ($File -and (Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'A fixture regular file is required.' }
    return $Path
}
function Assert-PilotTrustedPath {
    param([string]$Path,[switch]$Tree,[switch]$AllowServiceWrite,[switch]$AllowServiceParent,[string]$ServiceWriteSid,[string]$ServiceWriteRoot)
    if (-not [string]::Equals($Path, $script:fixture.Root, [StringComparison]::OrdinalIgnoreCase) -and
        -not $Path.StartsWith($script:fixture.Root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'The operation escaped the fixture.' }
    $paths = @($Path)
    if ($Tree -and (Test-Path -LiteralPath $Path)) { $paths += @(Get-ChildItem -LiteralPath $Path -Recurse -Force | ForEach-Object { $_.FullName }) }
    foreach ($candidate in $paths) {
        if ((Test-Path -LiteralPath $candidate) -and
            (([IO.File]::GetAttributes($candidate) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'A fixture link is not trusted.' }
    }
}
function Assert-PilotSupportedHost { }
function Set-CoreServiceAcl { param($Path,$Kind); }
function Set-SetupCodeAcl { param($Path,[switch]$PublicRead); }
function Write-PilotProtectedFile {
    param([string]$Path,[string]$Content,[string]$Kind)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Content)
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function New-PilotDirectoryWithAcl { param($Path,$Kind); New-Item -ItemType Directory -Path $Path | Out-Null }
function Get-SetupLocations { return $script:fixture.Locations }
function Get-CoreService { return $script:fixture.CoreService }
function Get-PilotService { return $script:fixture.AgentService }
function Stop-CoreService { param($TimeoutSeconds); $script:events.Add('stop-core') }
function Stop-PilotService { param($TimeoutSeconds); $script:events.Add('stop-agent') }
function Remove-CoreService { $script:events.Add('remove-core'); $script:fixture.CoreService = $null }
function Remove-PilotService { $script:events.Add('remove-agent'); $script:fixture.AgentService = $null }
function Write-SetupProgress { param($Phase); }
# Windows Firewall and the LocalMachine certificate store are native boundaries; the policy around them is tested here.
function Get-CoreServiceFirewallRule { return $script:fixture.FirewallRule }
function Set-CoreServiceFirewallRule {
    param($ExecutablePath,$Port)
    $script:events.Add('firewall-set:' + $Port + ':' + [IO.Path]::GetFileName($ExecutablePath)); $script:fixture.FirewallRule = 'owned'
}
function Remove-CoreServiceFirewallRule { $script:events.Add('firewall-remove'); $script:fixture.FirewallRule = $null }
# The Windows Apps entry and installed Setup copy are removed with every uninstall (SetupWorker.ps1).
function Unregister-SetupFullApps { param($Locations); $script:events.Add('apps-remove') }
# MVP-7: the nightly central update task (SetupWorker.ps1) leaves first with every uninstall.
function Remove-SetupCentralUpdateTask { $script:events.Add('update-task-remove') }
function Remove-SetupCentralUpdateDownloads { param($Locations); $script:events.Add('update-downloads-remove') }
function Sync-SetupCentralUpdateTask { param($Locations); $script:events.Add('update-task') }
function Test-CoreServiceCertificate { param($Sha256); return $script:fixture.CertificatePresent -and $Sha256 -ceq $script:fixture.Pin }
function Remove-CoreServiceCertificate { param($Sha256); $script:events.Add('certificate-remove:' + $Sha256.Substring(0, 4)) }
function Set-SetupLifecycleCodeAcl { param($Locations); }
function Start-CoreService { param($TimeoutSeconds); $script:events.Add('start-core') }
function Start-PilotService { param($TimeoutSeconds); $script:events.Add('start-agent') }
# The Security log entry and audit policy are native Windows boundaries (Setup acceptance covers them).
function Grant-PilotSecurityLogAccess { $script:events.Add('grant-security-log') }
function Revoke-PilotSecurityLogAccess { $script:events.Add('revoke-security-log') }
function Register-CoreService { param($ExecutablePath,$ConfigurationPath); $script:events.Add('register-core') }
function Register-PilotService { param($ExecutablePath,$ConfigurationPath); $script:events.Add('register-agent') }
function Set-CoreServiceRecovery { }
function Wait-CoreServiceHealth { param($Origin,$TimeoutSeconds,$LocalNetworkPort); $script:events.Add('health:' + $LocalNetworkPort) }
function Wait-PilotAgentEnrollment { param($DataDirectory,$TimeoutSeconds); }
# Access control is a native boundary: the shared data root has a synthetic DACL, and removal records each change.
$script:dataRootRules = @()
$script:accessFailures = @{}
function New-LifecycleTestRule([string]$Sid, [Security.AccessControl.FileSystemRights]$Rights = 'FullControl',
    [Security.AccessControl.InheritanceFlags]$Inheritance = 'ContainerInherit, ObjectInherit', [Security.AccessControl.AccessControlType]$Type = 'Allow') {
    return [pscustomobject]@{ IdentityReference = [pscustomobject]@{ Value = $Sid }; FileSystemRights = $Rights; AccessControlType = $Type
        InheritanceFlags = $Inheritance; PropagationFlags = [Security.AccessControl.PropagationFlags]::None }
}
function Get-PilotAcl {
    param([string]$Path, [bool]$Container)
    if ($Path -cne $script:fixture.Locations.DataRoot -or -not $Container) { throw 'Only the shared data root identifies a legacy account.' }
    if ($null -eq $script:dataRootRules) { throw (New-Object UnauthorizedAccessException('Access to the path is denied.')) }
    $acl = [pscustomobject]@{ Rules = $script:dataRootRules }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($Explicit, $Inherited, $Type) $this.Rules }
    return $acl
}
function Set-PilotLegacyOperatorSid { param([AllowNull()][string]$Sid); $script:events.Add('legacy:' + $Sid) }
function Remove-PilotAccountAccess {
    param([string]$Path, [string]$Sid)
    if ($script:accessFailures.ContainsKey($Path)) { throw $script:accessFailures[$Path] }
    $script:events.Add('remove-access:' + $Sid + '|' + $Path)
}

function Write-LifecycleTestDocument([string]$Path, $Document) {
    [IO.File]::WriteAllText($Path, ($Document | ConvertTo-Json -Compress -Depth 8), (New-Object Text.UTF8Encoding($false)))
}
function Read-LifecycleTestDocument([string]$Path) { return Read-PilotStrictJson (Read-PilotUtf8Document $Path 65536) }
function New-LifecycleTestFixture([switch]$LocalNetwork) {
    $root = Join-Path $testRoot ([Guid]::NewGuid().ToString('N'))
    $pin = ('C' + [Guid]::NewGuid().ToString('N').ToUpperInvariant() + [Guid]::NewGuid().ToString('N').ToUpperInvariant()).Substring(0, 64)
    $locations = @{
        CodeRoot = Join-Path $root 'ProgramFiles/SentinelAI'; DataRoot = Join-Path $root 'ProgramData/SentinelAI';
        Menu = Join-Path $root 'StartMenu/SentinelAI'; InstallerCode = Join-Path $root 'ProgramFiles/SentinelAI Setup'
    }
    foreach ($component in @('Core','Agent','Desktop','Updater')) { $locations[$component + 'Code'] = Join-Path $locations.CodeRoot $component }
    foreach ($component in @('Core','Agent','Setup')) { $locations[$component + 'Data'] = Join-Path $locations.DataRoot $component }
    foreach ($name in @('CoreCode','AgentCode','DesktopCode','UpdaterCode','CoreData','AgentData','SetupData','Menu','InstallerCode')) {
        New-Item -ItemType Directory -Path $locations[$name] -Force | Out-Null
    }
    [IO.File]::WriteAllText((Join-Path $locations.InstallerCode 'SentinelAI-Setup.exe'), 'synthetic-installed-setup')
    # A current installation: Administrators, SYSTEM and LocalService (read), no Windows account.
    $script:dataRootRules = @((New-LifecycleTestRule 'S-1-5-32-544'), (New-LifecycleTestRule 'S-1-5-18'), (New-LifecycleTestRule 'S-1-5-19' 'ReadAndExecute'))
    $script:accessFailures = @{}
    foreach ($component in @('Core','Agent','Desktop','Updater')) {
        [IO.File]::WriteAllText((Join-Path $locations[$component + 'Code'] ('SentinelAI.' + $component + '.exe')), ('synthetic-owned-' + $component + '-1.0.0'))
    }
    [IO.File]::WriteAllText((Join-Path $locations.Menu 'SentinelAI.lnk'), 'synthetic-owned-shortcut')
    $origin = 'http://127.0.0.1:5000'
    $coreSettings = @{ DataDirectory = $locations.CoreData }
    if ($LocalNetwork) { $coreSettings.LocalNetworkPort = '5443'; $coreSettings.LocalNetworkCertificateSha256 = $pin }
    Write-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-config.json') @{ urls = $origin; SentinelAI = $coreSettings }
    Write-LifecycleTestDocument (Join-Path $locations.AgentData 'pilot-config.json') @{ Agent = @{ CoreUrl = $origin; DataDirectory = $locations.AgentData; EnrollmentTokenFile = Join-Path $locations.AgentData 'pilot-enrollment-token' } }
    foreach ($component in @('Core','Agent')) {
        Write-LifecycleTestDocument (Join-Path $locations[$component + 'Data'] 'pilot-installation.json') ([ordered]@{
            format = 'sentinelai-pilot-v1'; component = $component; version = '1.0.0';
            codeDirectory = $locations[$component + 'Code']; dataDirectory = $locations[$component + 'Data'];
            coreUrl = $origin; environment = 'development'; channel = 'pilot';
            serviceName = $(if ($component -ceq 'Agent') { 'SentinelAIAgent' } else { '' });
            serviceAccountSid = $(if ($component -ceq 'Agent') { 'S-1-5-19' } else { '' })
        })
    }
    Write-LifecycleTestDocument (Join-Path $locations.CoreData 'core-service-installation.json') ([ordered]@{
        format = 'sentinelai-core-service-v1'; serviceName = 'SentinelAICore'; serviceAccount = 'NT SERVICE\SentinelAICore';
        serviceAccountSid = Get-SetupLifecycleCoreSid; codeDirectory = $locations.CoreCode; dataDirectory = $locations.CoreData;
        configurationSha256 = (Get-FileHash (Join-Path $locations.CoreData 'pilot-config.json')).Hash;
        executableSha256 = (Get-FileHash (Join-Path $locations.CoreCode 'SentinelAI.Core.exe')).Hash; version = '1.0.0'
    })
    Write-LifecycleTestDocument (Join-Path $locations.SetupData 'setup-installation.json') ([ordered]@{
        format = 'sentinelai-setup-v1'; keyId = 'dev-lifecycle-test'; environment = 'development'; channel = 'pilot';
        desktopDirectory = $locations.DesktopCode; updaterDirectory = $locations.UpdaterCode;
        desktopSha256 = (Get-FileHash (Join-Path $locations.DesktopCode 'SentinelAI.Desktop.exe')).Hash;
        updaterSha256 = (Get-FileHash (Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe')).Hash
    })
    [IO.File]::WriteAllText((Join-Path $locations.SetupData 'public-key.pem'), 'synthetic-public-trust-placeholder')
    $database = New-Object byte[] 128
    [Text.Encoding]::ASCII.GetBytes(('SQLite format 3' + [char]0)).CopyTo($database, 0)
    [IO.File]::WriteAllBytes((Join-Path $locations.CoreData 'sentinelai.db'), $database)
    [IO.File]::WriteAllText((Join-Path $locations.CoreData 'license-state'), 'synthetic-retained-lease')
    foreach ($name in @('endpoint-id','installation-id')) { [IO.File]::WriteAllText((Join-Path $locations.AgentData $name), [Guid]::NewGuid().ToString('D')) }
    [IO.File]::WriteAllBytes((Join-Path $locations.AgentData 'enrollment-state'), [byte[]]@(10,20,30,40))
    $neighbor = Join-Path $root 'ProgramData/OtherApplication'
    New-Item -ItemType Directory -Path $neighbor | Out-Null
    [IO.File]::WriteAllText((Join-Path $neighbor 'state'), 'foreign-neighbor-state')
    $coreService = [pscustomobject]@{ Name = 'SentinelAICore'; StartName = 'NT SERVICE\SentinelAICore'; PathName = Get-PilotAgentImagePath (Join-Path $locations.CoreCode 'SentinelAI.Core.exe') (Join-Path $locations.CoreData 'pilot-config.json') }
    $agentService = [pscustomobject]@{ Name = 'SentinelAIAgent'; StartName = 'NT AUTHORITY\LocalService'; PathName = Get-PilotAgentImagePath (Join-Path $locations.AgentCode 'SentinelAI.Agent.exe') (Join-Path $locations.AgentData 'pilot-config.json') }
    $script:events.Clear()
    $script:fixture = [pscustomobject]@{ Root = $root; Locations = $locations; CoreService = $coreService; AgentService = $agentService; Neighbor = $neighbor;
        Pin = $pin; FirewallRule = $(if ($LocalNetwork) { 'owned' } else { $null }); CertificatePresent = $true }
    return $script:fixture
}
function Get-LifecycleTestDataHashes($Locations) {
    $hashes = @{}
    foreach ($path in @((Join-Path $Locations.CoreData 'sentinelai.db'),(Join-Path $Locations.CoreData 'license-state'),
        (Join-Path $Locations.CoreData 'pilot-config.json'),(Join-Path $Locations.AgentData 'pilot-config.json'),
        (Join-Path $Locations.AgentData 'endpoint-id'),(Join-Path $Locations.AgentData 'installation-id'),(Join-Path $Locations.AgentData 'enrollment-state'))) {
        $hashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    return $hashes
}
function Assert-LifecycleTestDataUnchanged($Hashes) {
    foreach ($path in $Hashes.Keys) { Assert-LifecycleTest ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $Hashes[$path]) 'persistent identity/config/history/license bytes preserved' }
}
function Set-LifecycleTestMarker($Locations, [string]$Version) {
    Write-LifecycleTestDocument (Join-Path $Locations.CodeRoot 'deployment-version.json') ([ordered]@{ format = 'sentinelai-deployment-v1'; version = $Version })
}
function Get-LifecycleTestCandidateBytes([string]$Component) {
    return (New-Object Text.UTF8Encoding($false)).GetBytes(('synthetic-candidate-' + $Component))
}
function New-LifecycleTestRequest($Fixture, [string]$Version) {
    $work = Join-Path $Fixture.Root ('Staging-' + [Guid]::NewGuid().ToString('N'))
    $bundle = Join-Path $work 'bundle'
    New-Item -ItemType Directory -Path $bundle | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open((Join-Path $bundle 'deployment.zip'), [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($component in @('Core','Agent','Desktop','Updater')) {
            $entry = $archive.CreateEntry(($component + '/SentinelAI.' + $component + '.exe'))
            $stream = $entry.Open()
            try { $bytes = Get-LifecycleTestCandidateBytes $component; $stream.Write($bytes, 0, $bytes.Length) }
            finally { $stream.Dispose() }
        }
        $entry = $archive.CreateEntry('deployment-version.json'); $stream = $entry.Open()
        try {
            $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((([ordered]@{ format = 'sentinelai-deployment-v1'; version = $Version }) | ConvertTo-Json -Compress))
            $stream.Write($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
    } finally { $archive.Dispose() }
    return [pscustomobject]@{ action = 'lifecycle-context'; workDirectory = $work; keyId = 'dev-lifecycle-test'; channel = 'pilot'; enrollmentToken = ''; version = $Version; preserveData = 'true' }
}
function Set-LifecycleTestCandidateCode($Locations, [string]$Version) {
    foreach ($component in @('Core','Agent','Desktop','Updater')) {
        [IO.File]::WriteAllBytes((Join-Path $Locations[$component + 'Code'] ('SentinelAI.' + $component + '.exe')), (Get-LifecycleTestCandidateBytes $component))
    }
    Set-LifecycleTestMarker $Locations $Version
}

try {
    # Upgrade commits ownership metadata only for the active signed code version.
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $hashes = Get-LifecycleTestDataHashes $locations
    Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Installed') 'owned legacy deployment inspected'
    New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.1.0')
    Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'RecoveryPending') 'snapshot exposes pending recovery'
    Set-LifecycleTestCandidateCode $locations '1.1.0'
    Sync-SetupLifecycleReceipts $locations
    $owned = Assert-SetupLifecycleOwnership $locations
    Assert-LifecycleTest ($owned.Core.version -ceq '1.1.0' -and $owned.Agent.version -ceq '1.1.0' -and $owned.Service.version -ceq '1.1.0') 'upgrade versions advance together'
    Assert-LifecycleTest ($owned.Service.executableSha256 -ceq (Get-FileHash (Join-Path $locations.CoreCode 'SentinelAI.Core.exe')).Hash) 'Core receipt binds active code'
    Assert-LifecycleTest ($owned.Setup.desktopSha256 -ceq (Get-FileHash (Join-Path $locations.DesktopCode 'SentinelAI.Desktop.exe')).Hash) 'Desktop receipt binds active code'
    Assert-LifecycleTest ($owned.Setup.updaterSha256 -ceq (Get-FileHash (Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe')).Hash) 'Updater receipt binds active code'
    Assert-LifecycleTest ($script:events.Count -eq 0) 'receipt reconciliation performs no service control'
    Assert-LifecycleTestDataUnchanged $hashes

    # Both legacy no-marker rollback and an explicit old marker restore the
    # original raw snapshot, including partially updated receipt files.
    foreach ($oldMarker in @($false,$true)) {
        $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
        $hashes = Get-LifecycleTestDataHashes $locations
        New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.1.0')
        $context = Read-SetupLifecycleContext $locations
        if ($oldMarker) { Set-LifecycleTestMarker $locations '1.0.0' }
        $changed = Read-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-installation.json'); $changed.version = '1.1.0'
        Write-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-installation.json') $changed
        Sync-SetupLifecycleReceipts $locations
        foreach ($pair in @(@('coreReceipt',$locations.CoreData,'pilot-installation.json'),@('agentReceipt',$locations.AgentData,'pilot-installation.json'),
            @('serviceReceipt',$locations.CoreData,'core-service-installation.json'),@('setupReceipt',$locations.SetupData,'setup-installation.json'))) {
            Assert-LifecycleTest ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $pair[1] $pair[2]))) -ceq $context.($pair[0])) 'rollback restores exact ownership snapshot'
        }
        Assert-LifecycleTestDataUnchanged $hashes
    }

    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $hashes = Get-LifecycleTestDataHashes $locations
    New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.0.0')
    $oldProof = (Read-LifecycleTestDocument (Join-Path $locations.CoreData 'core-service-installation.json')).executableSha256
    Set-LifecycleTestCandidateCode $locations '1.0.0'
    Sync-SetupLifecycleReceipts $locations
    $repaired = Assert-SetupLifecycleOwnership $locations
    Assert-LifecycleTest ($repaired.Core.version -ceq '1.0.0') 'same-version repair keeps identity version'
    Assert-LifecycleTest ($repaired.Service.executableSha256 -cne $oldProof -and $repaired.Service.executableSha256 -ceq (Get-FileHash (Join-Path $locations.CoreCode 'SentinelAI.Core.exe')).Hash) 'same-version repair reconciles only authenticated candidate executable proof'
    Assert-LifecycleTestDataUnchanged $hashes
    [IO.File]::WriteAllText((Join-Path $locations.CoreCode 'SentinelAI.Core.exe'), 'unrecognized-damaged-code')
    Sync-SetupLifecycleReceipts $locations
    $restoredProof = (Read-LifecycleTestDocument (Join-Path $locations.CoreData 'core-service-installation.json')).executableSha256
    Assert-LifecycleTest ($restoredProof -ceq $oldProof -and $restoredProof -cne (Get-FileHash (Join-Path $locations.CoreCode 'SentinelAI.Core.exe')).Hash) 'same-version repair never legitimizes arbitrary active executable bytes'
    Set-LifecycleTestMarker $locations '9.9.9'
    Reject-LifecycleTest { Sync-SetupLifecycleReceipts $locations } 'unrecognized active version refused'

    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $hashes = Get-LifecycleTestDataHashes $locations
    New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.1.0')
    Set-LifecycleTestCandidateCode $locations '1.1.0'
    [IO.File]::WriteAllText((Join-Path $locations.DesktopCode 'SentinelAI.Desktop.exe'), 'unrecognized-candidate-desktop')
    Reject-LifecycleTest { Sync-SetupLifecycleReceipts $locations } 'upgrade marker cannot replace authenticated candidate executable hashes'
    Assert-LifecycleTest ((Read-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-installation.json')).version -ceq '1.0.0') 'candidate proof refusal leaves installed version unchanged'
    Assert-LifecycleTestDataUnchanged $hashes

    # Retention is the normal wire request. Explicit false removes only the
    # proven SentinelAI data root; an adjacent application's data survives.
    foreach ($preserve in @('true','false')) {
        $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
        $hashes = Get-LifecycleTestDataHashes $locations
        $request = [pscustomobject]@{ action = 'uninstall'; workDirectory = $fixture.Root; preserveData = $preserve }
        # workDirectory is staging only; it cannot select an installation root.
        $request | Add-Member -NotePropertyName dataDirectory -NotePropertyValue $fixture.Neighbor
        Invoke-SetupLifecycleWorker $request | Out-Null
        Assert-LifecycleTest (-not (Test-Path -LiteralPath $locations.CodeRoot) -and -not (Test-Path -LiteralPath $locations.Menu)) 'uninstall removes only owned code and shortcut'
        Assert-LifecycleTest ($null -eq $fixture.CoreService -and $null -eq $fixture.AgentService) 'uninstall removes both owned services'
        Assert-LifecycleTest (($script:events -join ',') -ceq 'update-task-remove,stop-agent,stop-core,update-downloads-remove,remove-agent,remove-core,firewall-remove,apps-remove') 'ownership precedes ordered service removal, then the Windows Apps entry'
        Assert-LifecycleTest ([IO.File]::ReadAllText((Join-Path $fixture.Neighbor 'state')) -ceq 'foreign-neighbor-state') 'foreign neighboring data survives explicit deletion'
        if ($preserve -ceq 'true') {
            Assert-LifecycleTestDataUnchanged $hashes
            Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Retained') 'default uninstall is recoverable retained installation'
        } else { Assert-LifecycleTest (-not (Test-Path -LiteralPath $locations.DataRoot)) 'explicit false deletes proven owned data' }
    }

    # The central role: uninstall always removes the owned firewall rule; only confirmed data removal deletes
    # Core's certificate, which every Agent pins. A local-only installation has no certificate to remove.
    foreach ($preserve in @('true','false')) {
        foreach ($central in @($true,$false)) {
            $fixture = New-LifecycleTestFixture -LocalNetwork:$central; $locations = $fixture.Locations
            $hashes = Get-LifecycleTestDataHashes $locations
            Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'uninstall'; workDirectory = $fixture.Root; preserveData = $preserve }) | Out-Null
            $expected = 'update-task-remove,stop-agent,stop-core,update-downloads-remove,remove-agent,remove-core,firewall-remove,apps-remove'
            if ($central -and $preserve -ceq 'false') { $expected += ',certificate-remove:' + $fixture.Pin.Substring(0, 4) }
            Assert-LifecycleTest (($script:events -join ',') -ceq $expected) 'uninstall removes the rule and only confirmed data removal deletes the certificate'
            Assert-LifecycleTest ($null -eq $fixture.FirewallRule) 'uninstall leaves no Core firewall rule'
            if ($preserve -ceq 'true') {
                Assert-LifecycleTestDataUnchanged $hashes
                Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Retained') 'retained central installation keeps its configuration'
                # Restoring the retained installation (code extracted again by the transaction) registers
                # the services and restores the rule exactly.
                foreach ($component in @('Core','Agent','Desktop','Updater')) {
                    New-Item -ItemType Directory -Path $locations[$component + 'Code'] -Force | Out-Null
                    [IO.File]::WriteAllText((Join-Path $locations[$component + 'Code'] ('SentinelAI.' + $component + '.exe')), ('synthetic-owned-' + $component + '-1.0.0'))
                }
                $script:events.Clear()
                Start-SetupLifecycleServices $locations
                $rule = if ($central) { 'firewall-set:5443:SentinelAI.Core.exe' } else { 'firewall-remove' }
                Assert-LifecycleTest (($script:events -join ',') -ceq ('register-core,register-agent,' + $rule + ',grant-security-log,start-core,start-agent')) 'restoration recreates services and the owned rule before start'
            }
        }
    }

    # Repair and upgrade restore a removed or changed rule; health includes the listener only while the certificate exists.
    $fixture = New-LifecycleTestFixture -LocalNetwork; $locations = $fixture.Locations
    $fixture.FirewallRule = $null
    Start-SetupLifecycleServices $locations
    Assert-LifecycleTest (($script:events -join ',') -ceq 'firewall-set:5443:SentinelAI.Core.exe,grant-security-log,start-core,start-agent') 'repair restores the owned firewall rule and keeps the Security log access'
    $script:events.Clear(); Test-SetupLifecycleHealth $locations
    Assert-LifecycleTest (($script:events -join ',') -ceq 'health:5443') 'health requires the local-network listener'
    $script:events.Clear(); $fixture.CertificatePresent = $false; Test-SetupLifecycleHealth $locations
    Assert-LifecycleTest (($script:events -join ',') -ceq 'health:0') 'without its certificate Core is healthy on loopback only'
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $script:events.Clear(); Test-SetupLifecycleHealth $locations
    Assert-LifecycleTest (($script:events -join ',') -ceq 'health:0') 'a local-only installation has no local-network health'
    # Rollback of a retained restoration returns to the uninstalled state, including the rule.
    $fixture = New-LifecycleTestFixture -LocalNetwork; $locations = $fixture.Locations
    Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'uninstall'; workDirectory = $fixture.Root; preserveData = 'true' }) | Out-Null
    New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.0.0')
    $fixture.FirewallRule = 'owned'; $script:events.Clear()
    Start-SetupLifecycleServices $locations
    Assert-LifecycleTest (($script:events -join ',') -ceq 'revoke-security-log,firewall-remove' -and $null -eq $fixture.FirewallRule) 'retained rollback removes the Security log access and the rule again'

    # A changed local-network configuration is not an owned deployment; a lone rule is not a fresh computer.
    foreach ($network in @('port','pin','partial')) {
        $fixture = New-LifecycleTestFixture -LocalNetwork; $locations = $fixture.Locations
        $config = Read-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-config.json')
        switch ($network) {
            'port' { $config.SentinelAI.LocalNetworkPort = '5444' }
            'pin' { $config.SentinelAI.LocalNetworkCertificateSha256 = $fixture.Pin.ToLowerInvariant() }
            'partial' { $config.SentinelAI.PSObject.Properties.Remove('LocalNetworkCertificateSha256') }
        }
        Write-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-config.json') $config
        Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Foreign') 'changed local-network configuration is refused'
    }
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    Remove-Item -LiteralPath $locations.CodeRoot, $locations.DataRoot, $locations.Menu -Recurse -Force
    $fixture.CoreService = $null; $fixture.AgentService = $null; $fixture.FirewallRule = 'leftover'
    Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Foreign') 'a leftover Core firewall rule needs inspection'
    $fixture.FirewallRule = $null
    Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Fresh') 'an empty computer is fresh'

    foreach ($foreign in @('core-image','core-account','agent-image','agent-account','missing-core','foreign-code','foreign-data','foreign-setup','foreign-menu','mixed-version')) {
        $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
        switch ($foreign) {
            'core-image' { $fixture.CoreService.PathName = 'foreign.exe' }
            'core-account' { $fixture.CoreService.StartName = 'LocalSystem' }
            'agent-image' { $fixture.AgentService.PathName = 'foreign.exe' }
            'agent-account' { $fixture.AgentService.StartName = 'LocalSystem' }
            'missing-core' { $fixture.CoreService = $null }
            'foreign-code' { [IO.File]::WriteAllText((Join-Path $locations.CodeRoot 'foreign.dll'), 'foreign') }
            'foreign-data' { [IO.File]::WriteAllText((Join-Path $locations.DataRoot 'foreign-state'), 'foreign') }
            'foreign-setup' { [IO.File]::WriteAllText((Join-Path $locations.SetupData 'unknown.json'), '{}') }
            'foreign-menu' { [IO.File]::WriteAllText((Join-Path $locations.Menu 'foreign.lnk'), 'foreign') }
            'mixed-version' {
                $receipt = Read-LifecycleTestDocument (Join-Path $locations.AgentData 'pilot-installation.json'); $receipt.version = '1.1.0'
                Write-LifecycleTestDocument (Join-Path $locations.AgentData 'pilot-installation.json') $receipt
            }
        }
        Reject-LifecycleTest { Stop-SetupLifecycleServices $locations } 'foreign deployment refused before stop'
        Assert-LifecycleTest ($script:events.Count -eq 0) 'refusal causes no service mutation'
        Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Foreign') 'foreign ownership remains explicit'
        Assert-LifecycleTest (Test-Path -LiteralPath $locations.DataRoot) 'foreign data is never deleted'
    }

    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.1.0')
    Reject-LifecycleTest { New-SetupLifecycleContext $locations (New-LifecycleTestRequest $fixture '1.2.0') } 'pending context cannot be replaced'
    [IO.File]::WriteAllText((Get-SetupLifecycleJournal $locations), 'synthetic-pending-journal')
    Reject-LifecycleTest { Uninstall-SetupLifecycleInstallation $locations $false } 'pending transaction prevents destructive uninstall'
    Assert-LifecycleTest ($script:events.Count -eq 0) 'pending transaction refusal happens before stop'

    # Earlier central installations granted their installing account full control. Any administrator's first
    # change removes it after proving ownership with that account accepted; inspection alone changes nothing.
    $legacy = 'S-1-5-21-2000-2000-2000-1002'
    $builtIn = @((New-LifecycleTestRule 'S-1-5-32-544'), (New-LifecycleTestRule 'S-1-5-18'), (New-LifecycleTestRule 'S-1-5-19' 'ReadAndExecute'))
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    Assert-LifecycleTest ($null -eq (Get-SetupLifecycleLegacyOperatorSid $locations)) 'a current installation names no legacy account'
    foreach ($shape in @(
        @((New-LifecycleTestRule $legacy), (New-LifecycleTestRule 'S-1-5-21-3000-3000-3000-1003')),
        @(New-LifecycleTestRule 'S-1-5-32-545'), @(New-LifecycleTestRule 'S-1-1-0'), @(New-LifecycleTestRule 'S-1-5-11'),
        @(New-LifecycleTestRule $legacy 'Modify'), @(New-LifecycleTestRule $legacy 'FullControl' 'None'),
        @(New-LifecycleTestRule $legacy 'FullControl' 'ContainerInherit, ObjectInherit' 'Deny'))) {
        $script:dataRootRules = $builtIn + $shape
        Assert-LifecycleTest ($null -eq (Get-SetupLifecycleLegacyOperatorSid $locations)) 'only the exact single-account legacy shape is recognized'
    }
    $script:dataRootRules = $null
    Assert-LifecycleTest ($null -eq (Get-SetupLifecycleLegacyOperatorSid $locations)) 'an unreadable shared data root names no legacy account'
    $script:dataRootRules = $builtIn + @(New-LifecycleTestRule 'S-1-12-1-100-200-300-400')
    Assert-LifecycleTest ((Get-SetupLifecycleLegacyOperatorSid $locations) -ceq 'S-1-12-1-100-200-300-400') 'a Microsoft Entra installing account is recognized'
    $script:dataRootRules = $builtIn + @(New-LifecycleTestRule $legacy)
    Assert-LifecycleTest ((Get-SetupLifecycleLegacyOperatorSid $locations) -ceq $legacy) 'the legacy installing account is recognized'
    $output = @(Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'inspect'; workDirectory = $fixture.Root; preserveData = 'true' }))
    Assert-LifecycleTest ($output -contains 'STATE|Installed|1.0.0') 'a legacy installation is inspected as owned'
    Assert-LifecycleTest ($script:events.Count -eq 1 -and $script:events[0] -ceq ('legacy:' + $legacy)) 'inspection accepts but never removes the legacy account'

    $script:events.Clear()
    Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'lifecycle-stop'; workDirectory = $fixture.Root; preserveData = 'true' }) | Out-Null
    $recorded = @($script:events)
    $removed = @($recorded | Where-Object { $_.StartsWith('remove-access:') } | ForEach-Object { $_.Substring($_.IndexOf('|') + 1) })
    Assert-LifecycleTest (@($recorded | Where-Object { $_.StartsWith('remove-access:') -and -not $_.StartsWith('remove-access:' + $legacy + '|') }).Count -eq 0) 'only the legacy account is removed'
    $expected = @()
    foreach ($name in @('CodeRoot','Menu','InstallerCode','CoreData','AgentData','SetupData')) {
        $expected += $locations[$name]
        $expected += @(Get-ChildItem -LiteralPath $locations[$name] -Recurse -Force | ForEach-Object { $_.FullName })
    }
    foreach ($path in $expected) { Assert-LifecycleTest ($removed -contains $path) ('every owned entry loses the legacy account: ' + $path) }
    Assert-LifecycleTest ($removed.Count -eq $expected.Count + 1 -and $removed[-1] -ceq $locations.DataRoot) 'the shared data root that identifies the account changes last'
    Assert-LifecycleTest (@($removed | Where-Object { $_.StartsWith($fixture.Neighbor) }).Count -eq 0) 'foreign neighbors are never changed'
    $cleared = [array]::IndexOf($recorded, 'legacy:')
    Assert-LifecycleTest ($recorded[0] -ceq ('legacy:' + $legacy) -and $cleared -gt [array]::LastIndexOf($recorded, ('remove-access:' + $legacy + '|' + $locations.DataRoot)) -and
        $cleared -lt $recorded.IndexOf('stop-agent') -and $cleared -lt $recorded.IndexOf('stop-core')) 'the action itself runs only after the legacy account is no longer accepted'

    # A transient file a running service removed is skipped; any other failure stops before the shared data root.
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $script:dataRootRules = $builtIn + @(New-LifecycleTestRule $legacy)
    $script:accessFailures[(Get-Item -LiteralPath (Join-Path $locations.CoreData 'license-state')).FullName] = New-Object IO.FileNotFoundException('Could not find file.')
    Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'lifecycle-stop'; workDirectory = $fixture.Root; preserveData = 'true' }) | Out-Null
    Assert-LifecycleTest ($script:events.Contains('remove-access:' + $legacy + '|' + $locations.DataRoot) -and $script:events.Contains('stop-core')) 'a vanished transient file does not stop the removal'
    foreach ($failure in @('missing-root', 'denied')) {
        $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
        $script:dataRootRules = $builtIn + @(New-LifecycleTestRule $legacy)
        if ($failure -ceq 'missing-root') { $script:accessFailures[$locations.CoreData] = New-Object IO.DirectoryNotFoundException('missing root') }
        else { $script:accessFailures[(Get-Item -LiteralPath (Join-Path $locations.CoreData 'sentinelai.db')).FullName] = New-Object UnauthorizedAccessException('denied') }
        Reject-LifecycleTest { Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'lifecycle-stop'; workDirectory = $fixture.Root; preserveData = 'true' }) } 'an interrupted removal fails the action'
        Assert-LifecycleTest (-not $script:events.Contains('remove-access:' + $legacy + '|' + $locations.DataRoot) -and -not $script:events.Contains('stop-core')) 'an interrupted removal keeps the shared data root, so the next maintenance resumes it'
    }

    # An installation not proven owned is never changed, even with the legacy account accepted.
    $fixture = New-LifecycleTestFixture; $locations = $fixture.Locations
    $script:dataRootRules = $builtIn + @(New-LifecycleTestRule $legacy)
    [IO.File]::WriteAllText((Join-Path $locations.SetupData 'unknown.json'), '{}')
    Reject-LifecycleTest { Invoke-SetupLifecycleWorker ([pscustomobject]@{ action = 'uninstall'; workDirectory = $fixture.Root; preserveData = 'true' }) } 'a foreign legacy-looking installation is refused'
    Assert-LifecycleTest (@($script:events | Where-Object { $_.StartsWith('remove-access:') }).Count -eq 0 -and -not $script:events.Contains('stop-core')) 'a foreign installation keeps every access entry'
    Write-Output ('Setup lifecycle portable tests passed: ' + $script:checks + ' assertions.')
} finally {
    # The suite created this random directory and keeps every target below it.
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
