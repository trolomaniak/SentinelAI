# SentinelAI-Agent-Setup.exe worker (MVP-2), loaded as an in-memory ScriptBlock after SetupWorker.ps1 defined the
# shared, already authenticated functions. The Agent product owns its own roots, separate from the full SentinelAI
# installation: one Agent service per computer, so a computer with the central installation's Agent is refused.

function Get-AgentSetupLocations {
    $code = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'SentinelAI Agent'
    $data = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI Agent'
    return @{ CodeRoot = $code; DataRoot = $data; AgentCode = Join-Path $code 'Agent'; UpdaterCode = Join-Path $code 'Updater';
        InstallerCode = Join-Path $code 'Setup'; AgentData = Join-Path $data 'Agent'; SetupData = Join-Path $data 'Setup' }
}

function Read-AgentSetupReceipt {
    param($Locations)
    $path = Join-Path $Locations.SetupData 'agent-setup-installation.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Assert-PilotTrustedPath -Path $Locations.DataRoot
    Assert-PilotTrustedPath -Path $Locations.SetupData -Tree
    $receipt = Read-PilotStrictJson -Json (Read-PilotUtf8Document -Path $path -MaximumBytes 4096)
    Assert-PilotObjectProperties -Object $receipt -Names @('format','version','keyId','environment','channel','coreUrl')
    if ($receipt.format -cne 'sentinelai-agent-setup-v1' -or $receipt.environment -cne 'development' -or
        $receipt.version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
        $receipt.coreUrl -cnotmatch '\Ahttps://[0-9a-z._-]{1,253}(:[0-9]{1,5})?\z') { throw 'Invalid Agent Setup receipt.' }
    return $receipt
}

# MVP-7: an hourly task, and 5 minutes after startup, runs the installed Updater as SYSTEM. It installs a newer signed Agent
# that the Agent fetched from Core, after verifying it with this installation's pinned key and policy.
$script:AgentUpdateTaskFolder = 'SentinelAI'
$script:AgentUpdateTaskName = 'SentinelAI Agent Update'

function Get-AgentSetupTaskRoot {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    return $scheduler.GetFolder('\')
}

function Register-AgentSetupUpdateTask {
    param($Locations)
    # Quoted: the path has spaces, and an unquoted one could start another program as SYSTEM.
    $updater = [Security.SecurityElement]::Escape('"' + (Join-Path $Locations.UpdaterCode 'SentinelAI.Updater.exe') + '"')
    # SYSTEM by SID, on battery too, a missed run caught up, never two at once, at most one hour per run.
    $definition = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Installs SentinelAI Agent updates offered by the central SentinelAI computer.</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><RandomDelay>PT10M</RandomDelay><Enabled>true</Enabled></TimeTrigger>
    <BootTrigger><Delay>PT5M</Delay><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="System"><Exec><Command>$updater</Command><Arguments>apply-agent-update</Arguments></Exec></Actions>
</Task>
"@
    $root = Get-AgentSetupTaskRoot
    try { $folder = $root.GetFolder($script:AgentUpdateTaskFolder) } catch { $folder = $root.CreateFolder($script:AgentUpdateTaskFolder, $null) }
    # TASK_CREATE_OR_UPDATE (6) with TASK_LOGON_SERVICE_ACCOUNT (5).
    [void]$folder.RegisterTask($script:AgentUpdateTaskName, $definition, 6, $null, $null, 5)
}

function Get-AgentSetupUpdateTask {
    $root = Get-AgentSetupTaskRoot
    try { return $root.GetFolder($script:AgentUpdateTaskFolder).GetTask($script:AgentUpdateTaskName) } catch { return $null }
}

# No new run starts; a running update gets two minutes to finish or roll back before it is stopped (state 4 = running).
function Suspend-AgentSetupUpdateTask {
    $task = Get-AgentSetupUpdateTask
    if ($null -eq $task) { return $false }
    $task.Enabled = $false
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    while ((Get-AgentSetupUpdateTask).State -eq 4 -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if ((Get-AgentSetupUpdateTask).State -eq 4) { $task.Stop(0) }
    return $true
}

function Resume-AgentSetupUpdateTask {
    $task = Get-AgentSetupUpdateTask
    if ($null -ne $task) { $task.Enabled = $true }
}

function Unregister-AgentSetupUpdateTask {
    $root = Get-AgentSetupTaskRoot
    try { $folder = $root.GetFolder($script:AgentUpdateTaskFolder) } catch { return }
    if ($null -ne (Get-AgentSetupUpdateTask)) { $folder.DeleteTask($script:AgentUpdateTaskName, 0) }
    if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) { $root.DeleteFolder($script:AgentUpdateTaskFolder, 0) }
}

# Fresh: nothing of SentinelAI Agent and no Agent service. Installed: this product's receipt. Anything else is never touched.
function Get-AgentSetupState {
    param($Locations)
    try { $receipt = Read-AgentSetupReceipt $Locations } catch { return @{ Kind = 'Blocked'; Version = '' } }
    if ($null -ne $receipt) { return @{ Kind = 'Installed'; Version = $receipt.version } }
    foreach ($path in @($Locations.CodeRoot, $Locations.DataRoot, (Get-SetupAppsKeyPath SentinelAIAgent))) {
        if (Test-Path -LiteralPath $path) { return @{ Kind = 'Blocked'; Version = '' } }
    }
    if ($null -ne (Get-PilotService)) { return @{ Kind = 'Blocked'; Version = '' } }
    return @{ Kind = 'Fresh'; Version = '' }
}

# Removes the service, code, the DPAPI-protected credential with all Agent data, the installed Setup and the Apps entry.
function Remove-AgentSetupInstallation {
    param($Locations)
    $failed = $false
    # The SYSTEM update task is held first, so it never replaces the Agent while its service and code are removed.
    $suspended = Suspend-AgentSetupUpdateTask
    if ($null -ne (Get-PilotService)) {
        # The pilot uninstall proves the registered service is the one its receipt in this data directory owns.
        try { [void](Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $Locations.AgentCode -DataDirectory $Locations.AgentData -TimeoutSeconds 60) }
        catch { $failed = $true }
    }
    if ($null -ne (Get-PilotService)) {
        if ($suspended) { Resume-AgentSetupUpdateTask }
        throw 'The Agent service could not be removed.'
    }
    Unregister-AgentSetupUpdateTask
    Unregister-SetupApps -Key SentinelAIAgent
    Assert-PilotTrustedPath -Path $Locations.CodeRoot -Tree
    Assert-PilotTrustedPath -Path $Locations.DataRoot -Tree -AllowServiceWrite
    Remove-SetupOwnedTree -Path $Locations.CodeRoot
    if (Test-Path -LiteralPath $Locations.DataRoot) { Remove-Item -LiteralPath $Locations.DataRoot -Recurse -Force }
    if ($failed) { throw 'The Agent service removal did not complete.' }
}

function Install-AgentSetupInstallation {
    param($Request)
    $locations = Get-AgentSetupLocations
    $changing = $false
    $completed = $false
    try {
        $bundle = Join-Path $Request.workDirectory 'bundle'
        $root = Join-Path $Request.workDirectory 'trust\root.pem'
        $policy = @{ BundleDirectory = $bundle; PublicKeyPath = $root; KeyId = $Request.keyId; Environment = 'development'; Channel = $Request.channel }
        Write-SetupProgress 'validate'
        if ((Get-AgentSetupState $locations).Kind -cne 'Fresh') { throw 'Existing installation.' }
        # The roots do not exist yet: this checks every existing ancestor with the ancestor rules (ProgramData lets Users create names).
        foreach ($path in @($locations.CodeRoot, $locations.DataRoot)) { Assert-PilotTrustedPath -Path $path }
        $changing = $true
        # Own roots without any entry for the installing account, so any administrator or SYSTEM can later
        # verify and uninstall them. The ownership receipt comes first: an interrupted install stays uninstallable.
        foreach ($path in @($locations.CodeRoot, $locations.DataRoot, $locations.SetupData)) { New-PilotDirectoryWithAcl -Path $path -Kind AgentRoot }
        $receipt = [ordered]@{ format = 'sentinelai-agent-setup-v1'; version = $Request.version; keyId = $Request.keyId; environment = 'development';
            channel = $Request.channel; coreUrl = $Request.coreUrl }
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'agent-setup-installation.json') -Content ($receipt | ConvertTo-Json -Compress) -Kind Receipt
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'public-key.pem') -Content ([IO.File]::ReadAllText($root)) -Kind Receipt
        Write-SetupProgress 'updater'
        Install-SetupAuxiliaryCode -Source (Join-Path $bundle 'updater') -Destination $locations.UpdaterCode -Executable 'SentinelAI.Updater.exe'
        # Registered before the Agent first starts, so the task's own creation is not reported as a finding.
        Register-AgentSetupUpdateTask $locations
        Write-SetupProgress 'apps'
        $installer = Install-SetupCachedInstaller -Source (Join-Path $Request.workDirectory 'installer\setup.exe') -Directory $locations.InstallerCode -Name 'SentinelAI-Agent-Setup.exe'
        Register-SetupApps -Key SentinelAIAgent -DisplayName 'SentinelAI Agent' -Version $Request.version -Installer $installer `
            -InstallLocation $locations.CodeRoot -Icon $installer -QuietUninstall
        Write-SetupProgress 'agent'
        # LocalService, automatic start, Agent:CoreUrl and the pin; the token goes through the protected one-use handoff file.
        # Success means the Agent stored the identity Core returned for this token.
        $agent = Invoke-PilotInstall -Component Agent @policy -CoreUrl $Request.coreUrl -CoreCertificateSha256 $Request.coreCertificateSha256 `
            -EnrollmentToken $Request.enrollmentToken -CodeDirectory $locations.AgentCode -DataDirectory $locations.AgentData -TimeoutSeconds 120
        if ($agent.component -cne 'Agent' -or $agent.dataDirectory -cne $locations.AgentData) { throw 'Agent installation failed.' }
        $completed = $true
        Write-Output 'DONE'
    } finally {
        $Request.enrollmentToken = $null
        if ($changing -and -not $completed) {
            # The Agent creates its installation ID when it starts with the handed-over token: then it ran, and only
            # Core's acknowledgement of the enrollment was missing.
            $phase = $script:SetupPhase
            if ($phase -ceq 'agent' -and (Test-Path -LiteralPath (Join-Path $locations.AgentData 'installation-id'))) { $phase = 'enroll' }
            # Everything above was created by this attempt on a computer proven fresh, so all of it is removed.
            try { Remove-AgentSetupInstallation $locations } catch { $phase = 'rollback' }
            $script:SetupPhase = $phase
        }
    }
}

function Assert-AgentSetupRequest {
    param($Request)
    Assert-PilotObjectProperties -Object $Request -Names @('action','workDirectory','keyId','channel','version','coreUrl','coreCertificateSha256','enrollmentToken')
    if ($Request.action -cnotin @('agent-inspect','agent-install','agent-uninstall') -or $Request.keyId -isnot [string] -or
        $Request.keyId -cnotmatch '\Adev-[A-Za-z0-9_-]{1,48}\z' -or $Request.channel -cnotin @('stable','pilot','beta') -or
        $Request.version -isnot [string] -or $Request.version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
        @($Request.version.Split('.') | Where-Object { [int]$_ -gt 65535 }).Count -ne 0) { throw 'Invalid policy.' }
    foreach ($name in @('coreUrl','coreCertificateSha256','enrollmentToken')) { if ($Request.$name -isnot [string]) { throw 'Invalid request.' } }
    if ($Request.action -cne 'agent-install') {
        # Only the install request carries the code's Core, pin and one-use token.
        if ($Request.coreUrl.Length -ne 0 -or $Request.coreCertificateSha256.Length -ne 0 -or $Request.enrollmentToken.Length -ne 0) { throw 'Unexpected enrollment code.' }
    } elseif ($Request.coreUrl -cnotmatch '\Ahttps://[0-9a-z._-]{1,253}(:[0-9]{1,5})?\z' -or
        $Request.coreCertificateSha256 -cnotmatch '\A[0-9A-F]{64}\z' -or $Request.enrollmentToken -cnotmatch '\A[0-9a-fA-F]{64}\z') { throw 'Invalid enrollment code.' }
}

function Invoke-AgentSetupWorkerMain {
    $raw = $null
    $request = $null
    try {
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Unsupported execution policy.' }
        $raw = Read-SetupRequest
        $locator = $raw | ConvertFrom-Json
        if ($locator.workDirectory -isnot [string]) { throw 'Invalid request.' }
        Assert-SetupBootstrapDirectory -Path $locator.workDirectory
        Import-SetupInstallerModules -WorkDirectory $locator.workDirectory
        $request = Read-PilotStrictJson -Json $raw
        Assert-AgentSetupRequest -Request $request
        Assert-PilotSupportedHost
        Assert-PilotTrustedPath -Path $request.workDirectory -Tree
        $locations = Get-AgentSetupLocations
        switch -CaseSensitive ($request.action) {
            'agent-inspect' {
                Write-SetupProgress 'inspect'
                $state = Get-AgentSetupState $locations
                Write-Output ('STATE|' + $state.Kind + '|' + $state.Version)
                Write-Output 'DONE'
            }
            'agent-install' { Install-AgentSetupInstallation -Request $request }
            'agent-uninstall' {
                Write-SetupProgress 'uninstall'
                if ((Get-AgentSetupState $locations).Kind -cne 'Installed') { throw 'Not installed.' }
                Remove-AgentSetupInstallation $locations
                Write-Output 'DONE'
            }
        }
        exit 0
    } catch {
        # Component output, exception text, paths and the code are never UI/log data.
        Write-Output ('FAILED|' + $script:SetupPhase)
        exit 1
    } finally { if ($null -ne $request -and $null -ne $request.PSObject.Properties['enrollmentToken']) { $request.enrollmentToken = $null }; $raw = $null }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-AgentSetupWorkerMain }
