# Portable policy tests for the Agent Setup worker (MVP-2). Native boundaries are stubbed; synthetic values only.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $repo 'installer/setup/SetupWorker.ps1')
. (Join-Path $repo 'installer/setup/AgentSetupWorker.ps1')
Import-Module (Join-Path $repo 'installer/pilot/PilotInstaller.psm1') -Force -DisableNameChecking
$script:checks = 0
function Assert-AgentTest([bool]$Condition, [string]$Label) { $script:checks++; if (-not $Condition) { throw ('Agent worker regression: ' + $Label) } }
function Reject-AgentTest([scriptblock]$Action, [string]$Label) {
    $script:checks++
    try { & $Action | Out-Null } catch { return }
    throw ('Agent worker accepted: ' + $Label)
}
$script:work = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-agent-worker-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $script:work 'trust'))
[IO.File]::WriteAllText((Join-Path $script:work 'trust/root.pem'), 'synthetic-public-only-root')
$syntheticToken = 'C' * 64
$syntheticPin = 'AB' * 32
function New-AgentTestRequest([string]$Action = 'agent-install') {
    $install = $Action -ceq 'agent-install'
    return [pscustomobject]@{ action = $Action; workDirectory = $script:work;
        keyId = 'dev-agent-test'; channel = 'pilot'; version = '1.0.0'
        coreUrl = $(if ($install) { 'https://central-pc.example.test:5443' } else { '' })
        coreCertificateSha256 = $(if ($install) { $syntheticPin } else { '' })
        enrollmentToken = $(if ($install) { $syntheticToken } else { '' }) }
}

# The private wire: only the install request carries the code's Core, pin and one-use token.
foreach ($action in @('agent-inspect','agent-install','agent-uninstall')) {
    Assert-AgentSetupRequest (Read-PilotStrictJson -Json ((New-AgentTestRequest $action) | ConvertTo-Json -Compress)); $script:checks++
}
foreach ($action in @('agent-inspect','agent-uninstall')) {
    foreach ($field in @('coreUrl','coreCertificateSha256','enrollmentToken')) {
        $request = New-AgentTestRequest $action; $request.$field = (New-AgentTestRequest).$field
        Reject-AgentTest { Assert-AgentSetupRequest $request } ($action + ' never carries ' + $field)
    }
}
foreach ($case in @(
    @('coreUrl', 'http://central-pc.example.test:5443'), @('coreUrl', 'https://central-pc.example.test:5443/path'), @('coreUrl', 'https://user@central-pc:5443'),
    @('coreUrl', 'https://CENTRAL-PC:5443'), @('coreUrl', ''), @('coreCertificateSha256', $syntheticPin.ToLowerInvariant()), @('coreCertificateSha256', 'A' * 63),
    @('enrollmentToken', 'z' * 64), @('enrollmentToken', ''), @('enrollmentToken', $null), @('action', 'complete'), @('action', 'Agent-Install'),
    @('keyId', 'production'), @('channel', 'nightly'), @('version', '01.0.0'), @('version', '65536.0.0'))) {
    $request = New-AgentTestRequest; $request.($case[0]) = $case[1]
    Reject-AgentTest { Assert-AgentSetupRequest $request } ('invalid ' + $case[0])
}
$request = New-AgentTestRequest; $request | Add-Member -NotePropertyName password -NotePropertyValue 'synthetic-password'
Reject-AgentTest { Assert-AgentSetupRequest $request } 'administrator credentials never reach the Agent worker'
$request = New-AgentTestRequest; $request.PSObject.Properties.Remove('coreUrl')
Reject-AgentTest { Assert-AgentSetupRequest $request } 'every field is mandatory'

if ($IsWindows -or $PSVersionTable.PSEdition -ceq 'Desktop') {
    $locations = Get-AgentSetupLocations
    Assert-AgentTest ($locations.CodeRoot -ceq (Join-Path $env:ProgramFiles 'SentinelAI Agent') -and $locations.DataRoot -ceq (Join-Path $env:ProgramData 'SentinelAI Agent') -and
        $locations.AgentCode -ceq (Join-Path $locations.CodeRoot 'Agent') -and $locations.InstallerCode -ceq (Join-Path $locations.CodeRoot 'Setup')) 'own roots, separate from the full installation'
} else {
    # Windows known folders do not exist here; the same layout under synthetic roots.
    $locations = @{ CodeRoot = '/synthetic/Program Files/SentinelAI Agent'; DataRoot = '/synthetic/ProgramData/SentinelAI Agent'
        AgentCode = '/synthetic/Program Files/SentinelAI Agent/Agent'; UpdaterCode = '/synthetic/Program Files/SentinelAI Agent/Updater'
        InstallerCode = '/synthetic/Program Files/SentinelAI Agent/Setup'; AgentData = '/synthetic/ProgramData/SentinelAI Agent/Agent'
        SetupData = '/synthetic/ProgramData/SentinelAI Agent/Setup' }
    function Get-AgentSetupLocations { return $script:locations }
}

# State: this product's receipt means Installed; any other trace of an Agent means Blocked and is never changed.
$script:receipt = $null; $script:receiptFails = $false; $script:present = @(); $script:service = $null
function Read-AgentSetupReceipt { param($Locations); if ($script:receiptFails) { throw 'Synthetic receipt failure.' }; return $script:receipt }
function Test-Path { param($LiteralPath); return $script:present -contains $LiteralPath }
function Get-PilotService { return $script:service }
Assert-AgentTest ((Get-AgentSetupState $locations).Kind -ceq 'Fresh') 'fresh computer'
foreach ($path in @($locations.CodeRoot, $locations.DataRoot, (Get-SetupAppsKeyPath SentinelAIAgent))) {
    $script:present = @($path); Assert-AgentTest ((Get-AgentSetupState $locations).Kind -ceq 'Blocked') ('unknown ' + $path)
}
$script:present = @(); $script:service = [pscustomobject]@{ Name = 'SentinelAIAgent' }
Assert-AgentTest ((Get-AgentSetupState $locations).Kind -ceq 'Blocked') 'the central installation''s Agent service'
$script:receipt = [pscustomobject]@{ version = '1.2.3' }
$state = Get-AgentSetupState $locations
Assert-AgentTest ($state.Kind -ceq 'Installed' -and $state.Version -ceq '1.2.3') 'installed Agent Setup'
$script:receiptFails = $true
Assert-AgentTest ((Get-AgentSetupState $locations).Kind -ceq 'Blocked') 'an unreadable receipt is never treated as owned'
$script:receiptFails = $false; $script:receipt = $null; $script:service = $null

# Install: Updater, installed Setup, receipt and Apps entry, then the enrolled Agent; any failure removes all of it.
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:fail = ''; $script:fresh = $true; $script:rollbackFails = $false
function Get-AgentSetupState { param($Locations); return @{ Kind = $(if ($script:fresh) { 'Fresh' } else { 'Installed' }); Version = '' } }
$script:trustedPaths = New-Object 'System.Collections.Generic.List[string]'
function Assert-PilotTrustedPath { param($Path,[switch]$Tree,[switch]$AllowServiceWrite); $script:trustedPaths.Add($Path) }
function Ensure-PilotProtectedParent { param($Path); $script:events.Add('code-root') }
function Install-SetupAuxiliaryCode {
    param($Source,$Destination,$Executable,[switch]$PublicRead)
    if ($script:fail -ceq 'updater') { throw 'Synthetic Updater failure.' }
    Assert-AgentTest ($Destination -ceq $locations.UpdaterCode -and -not $PublicRead) 'Updater in the Agent product root, administrator-only'
    $script:events.Add('updater')
}
function Install-SetupCachedInstaller {
    param($Source,$Directory,$Name)
    Assert-AgentTest ($Source -ceq (Join-Path (New-AgentTestRequest).workDirectory 'installer\setup.exe') -and $Directory -ceq $locations.InstallerCode -and $Name -ceq 'SentinelAI-Agent-Setup.exe') 'installed Setup copy'
    $script:events.Add('installer'); return (Join-Path $Directory $Name)
}
function New-PilotProtectedDirectory { param($Path,$Kind); $script:events.Add('setup-data') }
function Write-PilotProtectedFile {
    param($Path,$Content,$Kind)
    Assert-AgentTest ($Kind -ceq 'Receipt' -and -not $Content.Contains($syntheticToken)) 'receipts never contain the token'
    $script:events.Add('receipt')
}
function Register-SetupApps {
    param($Key,$DisplayName,$Version,$Installer,$InstallLocation,$Icon,[switch]$QuietUninstall)
    Assert-AgentTest ($Key -ceq 'SentinelAIAgent' -and $DisplayName -ceq 'SentinelAI Agent' -and $Version -ceq '1.0.0' -and $QuietUninstall) 'Windows Apps entry with quiet uninstall'
    $script:events.Add('apps')
}
function Invoke-PilotInstall {
    param($Component,$BundleDirectory,$PublicKeyPath,$KeyId,$Environment,$Channel,$CodeDirectory,$DataDirectory,$TimeoutSeconds,$EnrollmentToken,$CoreUrl,$CoreCertificateSha256)
    Assert-AgentTest ($Component -ceq 'Agent' -and $CoreUrl -ceq 'https://central-pc.example.test:5443' -and $CoreCertificateSha256 -ceq $syntheticPin -and
        $EnrollmentToken -ceq $syntheticToken -and $CodeDirectory -ceq $locations.AgentCode -and $DataDirectory -ceq $locations.AgentData -and
        $Environment -ceq 'development' -and $KeyId -ceq 'dev-agent-test') 'Agent service with the code''s Core, pin and one-use token'
    $script:events.Add('install-Agent')
    if ($script:fail -ceq 'agent') { throw 'Synthetic enrollment timeout.' }
    return [pscustomobject]@{ component = 'Agent'; dataDirectory = $DataDirectory }
}
$removeAgentSetupInstallation = ${function:Remove-AgentSetupInstallation}
function Remove-AgentSetupInstallation { param($Locations); $script:events.Add('rollback'); if ($script:rollbackFails) { throw 'Synthetic rollback failure.' } }
function Invoke-AgentInstallTest {
    $script:events.Clear(); $script:SetupPhase = 'validate'
    $request = New-AgentTestRequest
    $failed = $false
    try { $script:output = @(Install-AgentSetupInstallation -Request $request) } catch { $failed = $true }
    Assert-AgentTest ($null -eq $request.enrollmentToken) 'the token is released'
    return $failed
}
Assert-AgentTest (-not (Invoke-AgentInstallTest)) 'install succeeds'
# The product roots themselves are checked (their existing ancestors then get the ancestor rules); never the shared
# Program Files or ProgramData folders as targets, which grant standard users file creation.
Assert-AgentTest ($script:trustedPaths -ccontains $locations.CodeRoot -and $script:trustedPaths -ccontains $locations.DataRoot -and
    -not ($script:trustedPaths -ccontains [IO.Path]::GetDirectoryName($locations.CodeRoot)) -and
    -not ($script:trustedPaths -ccontains [IO.Path]::GetDirectoryName($locations.DataRoot))) 'the product roots are checked as targets, not their shared parents'
Assert-AgentTest (($script:events -join ',') -ceq 'code-root,updater,installer,setup-data,receipt,receipt,apps,install-Agent') 'install order'
Assert-AgentTest (($script:output -join ',') -ceq 'PROGRESS|validate,PROGRESS|updater,PROGRESS|apps,PROGRESS|agent,DONE') 'install progress protocol'
$script:fail = 'updater'
Assert-AgentTest ((Invoke-AgentInstallTest) -and ($script:events -join ',') -ceq 'code-root,rollback' -and $script:SetupPhase -ceq 'updater') 'an Updater failure removes everything'
$script:fail = 'agent'; $script:present = @()
Assert-AgentTest ((Invoke-AgentInstallTest) -and ($script:events -join ',').EndsWith('install-Agent,rollback') -and $script:SetupPhase -ceq 'agent') 'an Agent failure before its receipt removes everything'
$script:present = @(Join-Path $locations.AgentData 'pilot-installation.json')
Assert-AgentTest ((Invoke-AgentInstallTest) -and $script:SetupPhase -ceq 'enroll') 'Core never acknowledged the enrollment'
$script:rollbackFails = $true
Assert-AgentTest ((Invoke-AgentInstallTest) -and $script:SetupPhase -ceq 'rollback') 'a failed removal is reported as such'
$script:rollbackFails = $false; $script:fail = ''; $script:present = @(); $script:fresh = $false
Assert-AgentTest ((Invoke-AgentInstallTest) -and $script:events.Count -eq 0) 'an existing installation is refused before any change and never removed'
$script:fresh = $true

# Uninstall: the pilot proves the service is this product's before anything is deleted.
${function:Remove-AgentSetupInstallation} = $removeAgentSetupInstallation
$script:services = New-Object 'System.Collections.Generic.Queue[object]'
function Get-PilotService { if ($script:services.Count -gt 0) { return $script:services.Dequeue() }; return $null }
function Invoke-PilotInstall {
    param($Component,$CodeDirectory,$DataDirectory,$TimeoutSeconds)
    Assert-AgentTest ($Component -ceq 'UninstallAgent' -and $DataDirectory -ceq $locations.AgentData) 'owned Agent service removal'
    $script:events.Add('remove-service'); if ($script:fail -ceq 'foreign') { throw 'Synthetic foreign service.' }
}
function Unregister-SetupApps { param($Key); Assert-AgentTest ($Key -ceq 'SentinelAIAgent') 'own Apps entry'; $script:events.Add('apps-remove') }
function Remove-SetupOwnedTree { param($Path); Assert-AgentTest ($Path -ceq $locations.CodeRoot) 'own code root'; $script:events.Add('code-remove') }
function Remove-Item { param($LiteralPath,[switch]$Recurse,[switch]$Force); Assert-AgentTest ($LiteralPath -ceq $locations.DataRoot) 'own data root'; $script:events.Add('data-remove') }
$script:present = @($locations.DataRoot)
$script:events.Clear(); $script:services.Enqueue([pscustomobject]@{ Name = 'SentinelAIAgent' })
Remove-AgentSetupInstallation $locations
Assert-AgentTest (($script:events -join ',') -ceq 'remove-service,apps-remove,code-remove,data-remove') 'uninstall removes service, Apps entry, code and data with the credential'
$script:events.Clear(); $script:fail = 'foreign'
foreach ($index in 1..2) { $script:services.Enqueue([pscustomobject]@{ Name = 'SentinelAIAgent' }) }
Reject-AgentTest { Remove-AgentSetupInstallation $locations } 'a service the pilot cannot prove owned'
Assert-AgentTest (($script:events -join ',') -ceq 'remove-service') 'nothing is deleted while an unproven Agent service remains'

[IO.Directory]::Delete($script:work, $true)
Write-Output ('Agent Setup worker assertions passed: ' + $script:checks)
