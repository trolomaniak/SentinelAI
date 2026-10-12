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
    'Get-PilotAgentImagePath','Assert-PilotOwnedService','Get-PilotServiceAccountSid')
Import-LifecycleTestFunctions (Join-Path $repo 'installer/pilot/CoreServiceInstaller.psm1') @('Assert-CoreServiceOwned','Assert-CoreServiceDatabase')
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

function Write-LifecycleTestDocument([string]$Path, $Document) {
    [IO.File]::WriteAllText($Path, ($Document | ConvertTo-Json -Compress -Depth 8), (New-Object Text.UTF8Encoding($false)))
}
function Read-LifecycleTestDocument([string]$Path) { return Read-PilotStrictJson (Read-PilotUtf8Document $Path 65536) }
function New-LifecycleTestFixture {
    $root = Join-Path $testRoot ([Guid]::NewGuid().ToString('N'))
    $locations = @{
        CodeRoot = Join-Path $root 'ProgramFiles/SentinelAI'; DataRoot = Join-Path $root 'ProgramData/SentinelAI';
        Menu = Join-Path $root 'StartMenu/SentinelAI'
    }
    foreach ($component in @('Core','Agent','Desktop','Updater')) { $locations[$component + 'Code'] = Join-Path $locations.CodeRoot $component }
    foreach ($component in @('Core','Agent','Setup')) { $locations[$component + 'Data'] = Join-Path $locations.DataRoot $component }
    foreach ($name in @('CoreCode','AgentCode','DesktopCode','UpdaterCode','CoreData','AgentData','SetupData','Menu')) {
        New-Item -ItemType Directory -Path $locations[$name] -Force | Out-Null
    }
    foreach ($component in @('Core','Agent','Desktop','Updater')) {
        [IO.File]::WriteAllText((Join-Path $locations[$component + 'Code'] ('SentinelAI.' + $component + '.exe')), ('synthetic-owned-' + $component + '-1.0.0'))
    }
    [IO.File]::WriteAllText((Join-Path $locations.Menu 'SentinelAI.lnk'), 'synthetic-owned-shortcut')
    $origin = 'http://127.0.0.1:5000'
    Write-LifecycleTestDocument (Join-Path $locations.CoreData 'pilot-config.json') @{ urls = $origin; SentinelAI = @{ DataDirectory = $locations.CoreData } }
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
    $script:fixture = [pscustomobject]@{ Root = $root; Locations = $locations; CoreService = $coreService; AgentService = $agentService; Neighbor = $neighbor }
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
        Assert-LifecycleTest (($script:events -join ',') -ceq 'stop-agent,stop-core,remove-agent,remove-core') 'ownership precedes ordered service removal'
        Assert-LifecycleTest ([IO.File]::ReadAllText((Join-Path $fixture.Neighbor 'state')) -ceq 'foreign-neighbor-state') 'foreign neighboring data survives explicit deletion'
        if ($preserve -ceq 'true') {
            Assert-LifecycleTestDataUnchanged $hashes
            Assert-LifecycleTest ((Inspect-SetupLifecycleInstallation $locations).Kind -ceq 'Retained') 'default uninstall is recoverable retained installation'
        } else { Assert-LifecycleTest (-not (Test-Path -LiteralPath $locations.DataRoot)) 'explicit false deletes proven owned data' }
    }

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
    Write-Output ('Setup lifecycle portable tests passed: ' + $script:checks + ' assertions.')
} finally {
    # The suite created this random directory and keeps every target below it.
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
