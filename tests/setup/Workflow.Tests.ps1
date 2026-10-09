# Portable tests of the actual Setup worker contract; native installation is separate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Import-Module (Join-Path $repo 'installer/pilot/PilotInstaller.psm1') -DisableNameChecking
. (Join-Path $repo 'installer/setup/SetupWorker.ps1')
$script:checks = 0
function Assert-SetupTest([bool]$Condition, [string]$Label) { if (-not $Condition) { throw ('Setup regression: ' + $Label) }; $script:checks++ }
function Reject-SetupTest([scriptblock]$Operation, [string]$Label) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    Assert-SetupTest $rejected $Label
}

$syntheticToken = '0123456789abcdef' * 4
function New-SetupTestRequest([string]$Action = 'prepare-core') {
    [pscustomobject]@{ action = $Action; workDirectory = Join-Path ([IO.Path]::GetTempPath()) 'synthetic-setup-worker';
        keyId = 'dev-setup-test'; channel = 'pilot'; enrollmentToken = $(if ($Action -eq 'complete') { $syntheticToken } else { $null }) }
}
Assert-SetupRequest (New-SetupTestRequest)
Assert-SetupRequest (New-SetupTestRequest 'complete')
Assert-SetupRequest (New-SetupTestRequest 'start-core')
$script:checks += 3
foreach ($action in @('Complete','repair','uninstall','')) {
    $request = New-SetupTestRequest; $request.action = $action
    Reject-SetupTest { Assert-SetupRequest $request } 'unsupported action'
}
foreach ($key in @('production-root','dev-','dev-key/other','DEV-test')) {
    $request = New-SetupTestRequest; $request.keyId = $key
    Reject-SetupTest { Assert-SetupRequest $request } 'untrusted policy'
}
$request = New-SetupTestRequest; $request.channel = 'Pilot'
Reject-SetupTest { Assert-SetupRequest $request } 'channel exactness'
foreach ($action in @('prepare-core','start-core')) {
    $request = New-SetupTestRequest $action; $request.enrollmentToken = $syntheticToken
    Reject-SetupTest { Assert-SetupRequest $request } 'non-enrollment stages cannot receive a token'
}
foreach ($token in @('short', ('a' * 65), ('z' * 64), 123, $null)) {
    $request = New-SetupTestRequest 'complete'; $request.enrollmentToken = $token
    Reject-SetupTest { Assert-SetupRequest $request } 'invalid one-use token'
}
$request = New-SetupTestRequest 'complete'; $request | Add-Member -NotePropertyName password -NotePropertyValue 'synthetic-password'
Reject-SetupTest { Assert-SetupRequest $request } 'reusable password forbidden in worker'
$request = New-SetupTestRequest 'complete'; $request | Add-Member -NotePropertyName username -NotePropertyValue 'synthetic-operator'
Reject-SetupTest { Assert-SetupRequest $request } 'administrator identity forbidden in worker'
$request = New-SetupTestRequest; $request | Add-Member -NotePropertyName destination -NotePropertyValue 'other'
Reject-SetupTest { Assert-SetupRequest $request } 'destination overrides forbidden'
Reject-SetupTest { Read-PilotStrictJson '{"action":"prepare-core","action":"complete"}' } 'duplicate JSON field'

# In-memory hosting must import the same pilot implementation into Core's own scope.
$pilotModule = New-Module -Name SetupPortablePilot -ScriptBlock ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $repo 'installer/pilot/PilotInstaller.psm1'))))
$coreModule = New-Module -Name SetupPortableCore -ArgumentList @($pilotModule) -ScriptBlock ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $repo 'installer/pilot/CoreServiceInstaller.psm1'))))
$binding = & $coreModule { (Get-Command Invoke-PilotInstall).ModuleName }
Assert-SetupTest ($binding -eq 'SetupPortablePilot') 'same trusted module object'
Remove-Module $coreModule; Remove-Module $pilotModule

$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:existing = $null
$script:agentService = $null
$script:coreService = $null
$script:failAgent = $false
$script:locations = @{}
foreach ($name in @('CoreCode','CoreData','AgentCode','AgentData','DesktopCode','UpdaterCode','SetupData','Menu')) {
    $script:locations[$name] = Join-Path ([IO.Path]::GetTempPath()) ('synthetic-setup-' + $name)
}
function Get-SetupLocations { $script:locations }
function Assert-PilotSupportedHost { }
function Assert-PilotPath { param($Path,[switch]$MustExist,[switch]$File); $Path }
function Assert-PilotTrustedPath { param($Path,[switch]$Tree); }
function Test-Path { param($LiteralPath); return $LiteralPath -eq $script:existing }
function Get-PilotService { $script:agentService }
function Get-CoreService { $script:coreService }
function Invoke-PilotInstall {
    param($Component,$BundleDirectory,$PublicKeyPath,$KeyId,$Environment,$Channel,$CodeDirectory,$DataDirectory,$AdminCredential,$TimeoutSeconds,$EnrollmentToken)
    [void]$script:events.Add('install-' + $Component)
    Assert-SetupTest ($Environment -ceq 'development' -and $Channel -ceq 'pilot' -and $KeyId -ceq 'dev-setup-test') 'fixed package policy'
    Assert-SetupTest (-not $PublicKeyPath.StartsWith($BundleDirectory + [IO.Path]::DirectorySeparatorChar)) 'independent trust resource'
    if ($Component -eq 'Agent') {
        Assert-SetupTest ($null -eq $AdminCredential -and $EnrollmentToken -ceq $syntheticToken) 'only one-use token reaches Agent installer'
        if ($script:failAgent) { throw 'Synthetic service failure.' }
    } else { Assert-SetupTest ($null -eq $AdminCredential) 'Core install has no password' }
    [pscustomobject]@{ component = $Component }
}
function Invoke-CoreServiceManagement {
    param($Action,$BundleDirectory,$PublicKeyPath,$KeyId,$Environment,$Channel,$CodeDirectory,$DataDirectory,$TimeoutSeconds)
    Assert-SetupTest ($Action -cin @('Install','Start')) 'Core service owned install or revalidation'
    [void]$script:events.Add('core-service-' + $Action)
    [pscustomobject]@{ component = 'Core' }
}
function Install-SetupAuxiliaryCode { param($Source,$Destination,$Executable,[switch]$PublicRead); [void]$script:events.Add($Executable + ':' + $PublicRead.IsPresent) }
function New-PilotProtectedDirectory { param($Path,$Kind); [void]$script:events.Add('private-receipt-directory') }
function Write-PilotProtectedFile {
    param($Path,$Content,$Kind)
    Assert-SetupTest (-not $Content.Contains($syntheticToken) -and -not $Content.Contains('"username":') -and -not $Content.Contains('"password":')) 'receipts contain no credentials'
    Assert-SetupTest ($Kind -ceq 'Receipt') 'protected public receipt'
    [void]$script:events.Add('receipt')
}
function Get-FileHash { param($LiteralPath,$Algorithm); [pscustomobject]@{ Hash = 'A' * 64 } }
function Install-SetupShortcut { param($Directory,$DesktopDirectory); [void]$script:events.Add('shortcut') }

foreach ($name in $script:locations.Keys) {
    $script:existing = $script:locations[$name]
    Reject-SetupTest { Assert-SetupFreshTargets $script:locations } 'unknown existing targets preserved'
}
$script:existing = $null
$script:agentService = [pscustomobject]@{ Name = 'SentinelAIAgent' }
Reject-SetupTest { Assert-SetupFreshTargets $script:locations } 'existing Agent service preserved'
$script:agentService = $null; $script:coreService = [pscustomobject]@{ Name = 'SentinelAICore' }
Reject-SetupTest { Assert-SetupFreshTargets $script:locations } 'existing Core service preserved'
$script:coreService = $null
$output = @(Invoke-SetupInstallation (New-SetupTestRequest))
Assert-SetupTest (($script:events -join ',') -ceq 'install-Core') 'prepare installs only Core'
Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|core,DONE') 'prepare protocol'
$script:events.Clear()
$output = @(Invoke-SetupInstallation (New-SetupTestRequest 'start-core'))
Assert-SetupTest (($script:events -join ',') -ceq 'core-service-Install') 'start stage installs only Core service'
Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|services,DONE') 'Core start protocol'
$script:events.Clear()
$script:coreService = [pscustomobject]@{ Name = 'SentinelAICore'; State = 'Running' }

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-setup-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'trust'))
[IO.File]::WriteAllText((Join-Path $fixture 'trust/root.pem'), 'synthetic-public-only-root')
try {
    $request = New-SetupTestRequest 'complete'; $request.workDirectory = $fixture
    $output = @(Invoke-SetupInstallation $request)
    Assert-SetupTest (($script:events -join ',') -ceq 'core-service-Start,install-Agent,SentinelAI.Desktop.exe:True,SentinelAI.Updater.exe:False,private-receipt-directory,receipt,receipt,shortcut') 'complete phase ordering and permissions'
    Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|services,PROGRESS|agent,PROGRESS|desktop,PROGRESS|shortcut,DONE') 'complete progress protocol'
    Assert-SetupTest ($null -eq $request.enrollmentToken) 'enrollment request token released'
    Assert-SetupTest (-not ($output -join ',').Contains($syntheticToken)) 'output excludes credentials'
    $script:events.Clear(); $script:failAgent = $true
    $request = New-SetupTestRequest 'complete'; $request.workDirectory = $fixture
    Reject-SetupTest { Invoke-SetupInstallation $request } 'Agent failure stops remaining mutation'
    Assert-SetupTest (($script:events -join ',') -ceq 'core-service-Start,install-Agent') 'failed Agent cannot install shortcuts or claim success'
    Assert-SetupTest ($null -eq $request.enrollmentToken) 'failure releases token'
} finally { [IO.Directory]::Delete($fixture, $true); $syntheticToken = $null }

Write-Output ('Setup worker assertions passed: ' + $script:checks)
