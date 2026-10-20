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
        keyId = 'dev-setup-test'; channel = 'pilot'; enrollmentToken = $(if ($Action -eq 'complete') { $syntheticToken } else { '' }); version = '1.0.0'; preserveData = 'true'
        localNetworkCertificateSha256 = '' }
}
$syntheticPin = 'AB' * 32
Assert-SetupRequest (New-SetupTestRequest)
Assert-SetupRequest (New-SetupTestRequest 'complete')
Assert-SetupRequest (New-SetupTestRequest 'start-core')
$script:checks += 3
# Exercise the actual serialization boundary rather than only passing an object
# directly to the worker. Prepare/start must survive the existing strict grammar.
foreach ($action in @('prepare-core','start-core','complete')) {
    $json = New-SetupTestRequest $action | ConvertTo-Json -Compress
    $decoded = Read-PilotStrictJson -Json $json
    Assert-SetupRequest $decoded
    Assert-SetupTest ($decoded.action -ceq $action) 'serialized action survives strict parser'
    if ($action -eq 'complete') {
        Assert-SetupTest ($decoded.enrollmentToken -ceq $syntheticToken) 'serialized completion carries exact one-use token'
    } else {
        Assert-SetupTest ($decoded.enrollmentToken -is [string] -and $decoded.enrollmentToken.Length -eq 0) 'serialized preparation has exact empty token'
    }
}
foreach ($action in @('prepare-core','start-core')) {
    foreach ($invalidToken in @($null, 0, ' ', $syntheticToken)) {
        $request = New-SetupTestRequest $action; $request.enrollmentToken = $invalidToken
        Reject-SetupTest { Assert-SetupRequest $request } 'preparation rejects nonempty or non-string token'
    }
}
$nullWire = New-SetupTestRequest; $nullWire.enrollmentToken = $null
Reject-SetupTest { Read-PilotStrictJson -Json ($nullWire | ConvertTo-Json -Compress) } 'strict pilot JSON still rejects null primitives'
foreach ($action in @('Complete','repair','Uninstall','')) {
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
foreach ($action in @('inspect','lifecycle-stop','lifecycle-start','lifecycle-health','lifecycle-context','lifecycle-cleanup','lifecycle-reconcile','uninstall')) {
    $request = New-SetupTestRequest $action
    $decoded = Read-PilotStrictJson -Json ($request | ConvertTo-Json -Compress)
    Assert-SetupRequest $decoded
    Assert-SetupTest ($decoded.version -ceq '1.0.0' -and $decoded.preserveData -ceq 'true') 'maintenance wire retains version and explicit preserve-data policy'
    $request.enrollmentToken = $syntheticToken
    Reject-SetupTest { Assert-SetupRequest $request } 'maintenance never receives enrollment credentials'
}
foreach ($value in @($null, $true, 'True', 'FALSE', '', '0')) {
    $request = New-SetupTestRequest 'uninstall'; $request.preserveData = $value
    Reject-SetupTest { Assert-SetupRequest $request } 'preserve-data wire is exact string enum'
}
$request = New-SetupTestRequest 'uninstall'; $request.preserveData = 'false'
Assert-SetupRequest $request; $script:checks++
foreach ($action in @('prepare-core','start-core','complete','inspect','lifecycle-stop','lifecycle-start','lifecycle-health','lifecycle-context','lifecycle-cleanup','lifecycle-reconcile')) {
    $request = New-SetupTestRequest $action; $request.preserveData = 'false'
    Reject-SetupTest { Assert-SetupRequest $request } 'data deletion forbidden outside explicit uninstall'
}
# Only the fresh Core preparation carries the public SHA-256 of the certificate the Setup host created.
$request = New-SetupTestRequest; $request.localNetworkCertificateSha256 = $syntheticPin
Assert-SetupRequest (Read-PilotStrictJson -Json ($request | ConvertTo-Json -Compress)); $script:checks++
foreach ($pin in @($null, 0, ('ab' * 32), ('A' * 63), ('A' * 65), ('G' * 64), (' ' + ('A' * 63)))) {
    $request = New-SetupTestRequest; $request.localNetworkCertificateSha256 = $pin
    Reject-SetupTest { Assert-SetupRequest $request } 'local-network pin is an exact uppercase SHA-256 string'
}
foreach ($action in @('start-core','complete','inspect','lifecycle-start','lifecycle-health','uninstall')) {
    $request = New-SetupTestRequest $action; $request.localNetworkCertificateSha256 = $syntheticPin
    Reject-SetupTest { Assert-SetupRequest $request } 'only fresh Core preparation receives a certificate pin'
}
$request = New-SetupTestRequest; $request.PSObject.Properties.Remove('localNetworkCertificateSha256')
Reject-SetupTest { Assert-SetupRequest $request } 'the local-network field is mandatory on the wire'
foreach ($version in @('01.0.0','1.0','-1.0.0','1.0.0-beta','65536.0.0',$null,123)) {
    $request = New-SetupTestRequest; $request.version = $version
    Reject-SetupTest { Assert-SetupRequest $request } 'unsupported setup version'
}

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
$script:firewallRule = $null
$script:certificatePresent = $true
$script:network = $null
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
function Get-CoreServiceFirewallRule { $script:firewallRule }
function Test-CoreServiceCertificate { param($Sha256); [void]$script:events.Add('certificate-' + $Sha256.Substring(0, 4)); $script:certificatePresent }
function Get-CoreServiceLocalNetwork { param($DataDirectory); $script:network }
function Set-CoreServiceFirewallRule {
    param($ExecutablePath,$Port)
    Assert-SetupTest ($ExecutablePath -ceq (Join-Path $script:locations.CoreCode 'SentinelAI.Core.exe') -and $Port -eq 5443) 'firewall rule scoped to installed Core and its port'
    [void]$script:events.Add('firewall')
}
function Invoke-PilotInstall {
    param($Component,$BundleDirectory,$PublicKeyPath,$KeyId,$Environment,$Channel,$CodeDirectory,$DataDirectory,$AdminCredential,$TimeoutSeconds,$EnrollmentToken,$LocalNetworkCertificateSha256)
    [void]$script:events.Add('install-' + $Component + $(if ($LocalNetworkCertificateSha256) { ':' + $LocalNetworkCertificateSha256.Substring(0, 4) } else { '' }))
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
$script:firewallRule = [pscustomobject]@{ Name = 'SentinelAI-Core-LocalNetwork' }
Reject-SetupTest { Assert-SetupFreshTargets $script:locations } 'existing Core firewall rule preserved'
$script:firewallRule = $null
$output = @(Invoke-SetupInstallation (New-SetupTestRequest))
Assert-SetupTest (($script:events -join ',') -ceq 'install-Core') 'local-only prepare installs only Core'
Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|core,DONE') 'prepare protocol'
$script:events.Clear()
$request = New-SetupTestRequest; $request.localNetworkCertificateSha256 = $syntheticPin
$output = @(Invoke-SetupInstallation $request)
Assert-SetupTest (($script:events -join ',') -ceq 'certificate-ABAB,install-Core:ABAB') 'central prepare checks the created certificate and configures its pin'
$script:events.Clear(); $script:certificatePresent = $false
Reject-SetupTest { Invoke-SetupInstallation $request } 'central prepare refuses a pin without its machine certificate'
Assert-SetupTest (($script:events -join ',') -ceq 'certificate-ABAB') 'a missing certificate stops before Core is installed'
$script:events.Clear(); $script:certificatePresent = $true
$output = @(Invoke-SetupInstallation (New-SetupTestRequest 'start-core'))
Assert-SetupTest (($script:events -join ',') -ceq 'core-service-Install') 'local-only start installs only Core service'
Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|services,DONE') 'Core start protocol'
$script:events.Clear(); $script:network = [pscustomobject]@{ Port = 5443; CertificateSha256 = $syntheticPin }
$output = @(Invoke-SetupInstallation (New-SetupTestRequest 'start-core'))
Assert-SetupTest (($script:events -join ',') -ceq 'core-service-Install,firewall') 'central start adds the firewall rule after healthy Core'
Assert-SetupTest (($output -join ',') -ceq 'PROGRESS|validate,PROGRESS|services,PROGRESS|network,DONE') 'central Core start protocol'
$script:events.Clear(); $script:network = $null
$script:firewallRule = [pscustomobject]@{ Name = 'SentinelAI-Core-LocalNetwork' }
Reject-SetupTest { Invoke-SetupInstallation (New-SetupTestRequest 'start-core') } 'start refuses a firewall rule it did not add'
$script:events.Clear()
$script:coreService = [pscustomobject]@{ Name = 'SentinelAICore'; State = 'Running' }
# The central start phase added the owned rule; completion must not treat it as foreign state.
$script:firewallRule = [pscustomobject]@{ Name = 'SentinelAI-Core-LocalNetwork' }

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
