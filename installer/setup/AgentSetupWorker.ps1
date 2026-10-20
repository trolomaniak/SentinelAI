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
    if ($null -ne (Get-PilotService)) {
        # The pilot uninstall proves the registered service is the one its receipt in this data directory owns.
        try { [void](Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $Locations.AgentCode -DataDirectory $Locations.AgentData -TimeoutSeconds 60) }
        catch { $failed = $true }
    }
    if ($null -ne (Get-PilotService)) { throw 'The Agent service could not be removed.' }
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
        Write-SetupProgress 'updater'
        Ensure-PilotProtectedParent -Path $locations.CodeRoot
        Install-SetupAuxiliaryCode -Source (Join-Path $bundle 'updater') -Destination $locations.UpdaterCode -Executable 'SentinelAI.Updater.exe'
        Write-SetupProgress 'apps'
        $installer = Install-SetupCachedInstaller -Source (Join-Path $Request.workDirectory 'installer\setup.exe') -Directory $locations.InstallerCode -Name 'SentinelAI-Agent-Setup.exe'
        New-PilotProtectedDirectory -Path $locations.SetupData -Kind Container
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'public-key.pem') -Content ([IO.File]::ReadAllText($root)) -Kind Receipt
        $receipt = [ordered]@{ format = 'sentinelai-agent-setup-v1'; version = $Request.version; keyId = $Request.keyId; environment = 'development';
            channel = $Request.channel; coreUrl = $Request.coreUrl }
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'agent-setup-installation.json') -Content ($receipt | ConvertTo-Json -Compress) -Kind Receipt
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
            # The Agent's own receipt exists once its code and configuration were placed: then only enrollment remained.
            $phase = $script:SetupPhase
            if ($phase -ceq 'agent' -and (Test-Path -LiteralPath (Join-Path $locations.AgentData 'pilot-installation.json'))) { $phase = 'enroll' }
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
