# This is an opt-in, real Windows integration test. Portable workflow tests do not
# exercise the Service Control Manager, Windows ACLs, or DPAPI under LocalService.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDirectory,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$KeyId,
    [ValidateSet('development', 'production')][string]$Environment = 'development',
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [string]$WorkDirectory,
    [ValidateRange(30, 600)][int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installerDirectory = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'installer/pilot'
Import-Module (Join-Path $installerDirectory 'PilotInstaller.psm1') -Force -DisableNameChecking
Assert-PilotSupportedHost

# Never adopt or remove an existing installation during an acceptance test.
if ($null -ne (Get-PilotService)) {
    throw 'The acceptance test requires a Windows test machine without SentinelAIAgent installed.'
}
if ([string]::IsNullOrWhiteSpace($WorkDirectory)) {
    $WorkDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('SentinelAI-Pilot-Acceptance-' + [Guid]::NewGuid().ToString('N'))
}
$WorkDirectory = Assert-PilotPath -Path $WorkDirectory
if (Test-Path -LiteralPath $WorkDirectory) {
    throw 'The acceptance test work directory must be new; existing data will not be reused.'
}
New-PilotProtectedDirectory -Path $WorkDirectory -Kind Container

$coreCode = Join-Path $WorkDirectory 'Core Code'
$coreData = Join-Path $WorkDirectory 'Core Data'
$agentCode = Join-Path $WorkDirectory 'Agent Code'
$agentData = Join-Path $WorkDirectory 'Agent Data'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
} finally {
    $listener.Stop()
}
$coreUrl = 'http://127.0.0.1:' + $port
$passwordBytes = [byte[]]::new(32)
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($passwordBytes) } finally { $random.Dispose() }
$passwordText = [Convert]::ToBase64String($passwordBytes)
$securePassword = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
$credential = [PSCredential]::new('pilot-test-' + [Guid]::NewGuid().ToString('N'), $securePassword)
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
$passwordText = $null
$coreProcess = $null
$agentInstalled = $false
$assertionCount = 0

function Assert-Acceptance {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}

function Read-StateDigest {
    param([string]$Path)
    Assert-Acceptance (Test-Path -LiteralPath $Path -PathType Leaf) 'Expected persistent test state is missing.'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-LocalServiceAllowRights {
    param([string]$Path)
    $rights = 0
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -eq 'S-1-5-19' -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) {
            $rights = $rights -bor [int]$rule.FileSystemRights
        }
    }
    return $rights
}

$installOptions = @{
    BundleDirectory = $BundleDirectory; PublicKeyPath = $PublicKeyPath; KeyId = $KeyId
    Environment = $Environment; Channel = $Channel; CoreUrl = $coreUrl
    TimeoutSeconds = $TimeoutSeconds
}
try {
    Invoke-PilotInstall -Component Core -CodeDirectory $coreCode -DataDirectory $coreData @installOptions | Out-Null
    $core = & (Join-Path $installerDirectory 'Start-SentinelAICore.ps1') -CodeDirectory $coreCode -DataDirectory $coreData -AdminCredential $credential -TimeoutSeconds ([Math]::Min(180, $TimeoutSeconds))
    $coreProcess = [Diagnostics.Process]::GetProcessById($core.ProcessId)
    # Open and retain the exact child handle rather than trusting a reusable PID.
    $null = $coreProcess.StartTime
    Assert-Acceptance ($core.CoreUrl.TrimEnd('/') -eq $coreUrl) 'Core did not start at the configured local origin.'

    $firstObservation = [DateTimeOffset]::UtcNow
    Invoke-PilotInstall -Component Agent -CodeDirectory $agentCode -DataDirectory $agentData -AdminCredential $credential @installOptions | Out-Null
    $agentInstalled = $true
    $service = Get-PilotService
    Assert-Acceptance ($service.State -eq 'Running') 'The actual Agent Windows Service is not running.'
    Assert-Acceptance ($service.StartName -in @('NT AUTHORITY\LocalService', 'NT AUTHORITY\LOCAL SERVICE')) 'The Agent service uses an unexpected account.'
    $expectedImagePath = Get-PilotAgentImagePath -ExecutablePath (Join-Path $agentCode 'SentinelAI.Agent.exe') -ConfigurationPath (Join-Path $agentData 'pilot-config.json')
    Assert-Acceptance ($service.PathName -ceq $expectedImagePath) 'The SCM ImagePath did not preserve quoted code and configuration paths.'
    $codeRights = Get-LocalServiceAllowRights $agentCode
    Assert-Acceptance (($codeRights -band [int][Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [int][Security.AccessControl.FileSystemRights]::ReadAndExecute) 'LocalService cannot read and execute Agent code.'
    Assert-Acceptance (($codeRights -band [int][Security.AccessControl.FileSystemRights]::Write) -eq 0) 'LocalService can modify Agent code.'
    $dataRights = Get-LocalServiceAllowRights $agentData
    Assert-Acceptance (($dataRights -band [int][Security.AccessControl.FileSystemRights]::Modify) -eq [int][Security.AccessControl.FileSystemRights]::Modify) 'LocalService cannot maintain its persistent Agent data.'
    # Check the one-use ACL directly with a synthetic file; the live handoff must
    # also have been deleted by the actual LocalService Agent after enrollment.
    $aclFixture = Join-Path $agentData 'synthetic-token-acl-fixture'
    [IO.File]::WriteAllText($aclFixture, 'synthetic fixture only')
    try {
        Set-PilotFileAcl -Path $aclFixture -Kind AgentToken
        $tokenRights = Get-LocalServiceAllowRights $aclFixture
        Assert-Acceptance (($tokenRights -band [int][Security.AccessControl.FileSystemRights]::Read) -eq [int][Security.AccessControl.FileSystemRights]::Read) 'LocalService cannot read its one-use token handoff.'
        Assert-Acceptance (($tokenRights -band [int][Security.AccessControl.FileSystemRights]::Delete) -ne 0) 'LocalService cannot delete its consumed one-use token handoff.'
        Assert-Acceptance (($tokenRights -band [int][Security.AccessControl.FileSystemRights]::WriteData) -eq 0) 'LocalService can replace the one-use token handoff.'
    } finally {
        Remove-Item -LiteralPath $aclFixture -Force
    }
    $verifyArguments = @{
        CoreUrl = $coreUrl; AgentDataDirectory = $agentData; AdminCredential = $credential
        TimeoutSeconds = $TimeoutSeconds
    }
    $verified = & (Join-Path $installerDirectory 'Verify-SentinelAIPilot.ps1') -SinceUtc $firstObservation @verifyArguments
    $endpointId = $verified.EndpointId
    Assert-Acceptance ($null -ne $endpointId) 'Verification did not confirm this Agent endpoint in Core.'
    Assert-Acceptance (-not (Test-Path -LiteralPath (Join-Path $agentData 'pilot-enrollment-token'))) 'The consumed enrollment handoff was retained.'

    $installationDigest = Read-StateDigest (Join-Path $agentData 'installation-id')
    $enrollmentDigest = Read-StateDigest (Join-Path $agentData 'enrollment-state')
    $receiptDigest = Read-StateDigest (Join-Path $agentData 'endpoint-id')
    Assert-Acceptance (Test-Path -LiteralPath (Join-Path $coreData 'sentinelai.db') -PathType Leaf) 'Core did not retain its local database.'

    # A real service restart must send new heartbeat AND inventory for the same endpoint.
    Stop-PilotService -TimeoutSeconds $TimeoutSeconds
    $restartObservation = [DateTimeOffset]::UtcNow
    Start-PilotService -TimeoutSeconds $TimeoutSeconds
    $restarted = & (Join-Path $installerDirectory 'Verify-SentinelAIPilot.ps1') -SinceUtc $restartObservation @verifyArguments
    Assert-Acceptance ($restarted.EndpointId -eq $endpointId) 'A service restart changed endpoint identity.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'installation-id')) -eq $installationDigest) 'A restart changed installation identity.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'enrollment-state')) -eq $enrollmentDigest) 'A restart changed protected enrollment state.'

    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -CoreUrl $coreUrl -TimeoutSeconds $TimeoutSeconds | Out-Null
    $agentInstalled = $false
    Assert-Acceptance ($null -eq (Get-PilotService)) 'Uninstallation did not remove the actual Windows Service.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'installation-id')) -eq $installationDigest) 'Uninstallation deleted installation identity.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'enrollment-state')) -eq $enrollmentDigest) 'Uninstallation deleted protected enrollment state.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'endpoint-id')) -eq $receiptDigest) 'Uninstallation deleted the endpoint receipt.'
    Assert-Acceptance (Test-Path -LiteralPath (Join-Path $coreData 'sentinelai.db') -PathType Leaf) 'Agent uninstallation affected Core data.'

    $reinstallObservation = [DateTimeOffset]::UtcNow
    Invoke-PilotInstall -Component Agent -CodeDirectory $agentCode -DataDirectory $agentData @installOptions | Out-Null
    $agentInstalled = $true
    $reinstalled = & (Join-Path $installerDirectory 'Verify-SentinelAIPilot.ps1') -SinceUtc $reinstallObservation @verifyArguments
    Assert-Acceptance ($reinstalled.EndpointId -eq $endpointId) 'Reinstallation did not preserve the enrolled endpoint.'
    Assert-Acceptance ((Read-StateDigest (Join-Path $agentData 'enrollment-state')) -eq $enrollmentDigest) 'Reinstallation replaced existing protected credentials.'

    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -CoreUrl $coreUrl -TimeoutSeconds $TimeoutSeconds | Out-Null
    $agentInstalled = $false
    [PSCustomObject]@{ Result = 'Passed'; Assertions = $assertionCount; TestArtifactsDirectory = $WorkDirectory }
} finally {
    # Only the service created by this isolated test and its exact Core child may be stopped.
    try {
        if ($agentInstalled) {
            Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -CoreUrl $coreUrl -TimeoutSeconds $TimeoutSeconds | Out-Null
        }
    } finally {
        try {
            if ($null -ne $coreProcess) {
                try {
                    if (-not $coreProcess.HasExited) { $coreProcess.Kill(); [void]$coreProcess.WaitForExit(10000) }
                } finally {
                    $coreProcess.Dispose()
                }
            }
        } finally {
            $credential = $null
            if ($null -ne $securePassword) { $securePassword.Dispose() }
        }
    }
    # Retain this newly created test directory for inspection; never delete state implicitly.
}
