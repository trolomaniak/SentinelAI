# Embedded maintenance adapter. Code replacement and recovery are performed by
# the existing signed TransactionalUpdater, never by these service commands.
Set-StrictMode -Version Latest

function Get-SetupLifecycleCoreSid { return 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900' }

function Read-SetupLifecycleDocument {
    param([string]$Path, [string]$DataDirectory, [string]$ServiceSid, [int]$MaximumBytes = 4096)
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    Assert-PilotTrustedPath -Path $Path -AllowServiceParent:([bool]$ServiceSid) -ServiceWriteSid $ServiceSid -ServiceWriteRoot $DataDirectory
    return Read-PilotStrictJson -Json (Read-PilotUtf8Document -Path $Path -MaximumBytes $MaximumBytes)
}

function Read-SetupLifecycleContext {
    param($Locations)
    $path = Join-Path $Locations.SetupData 'lifecycle-context.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $context = Read-SetupLifecycleDocument -Path $path -MaximumBytes 65536
    Assert-PilotObjectProperties -Object $context -Names @('format','oldVersion','candidateVersion','retained','coreReceipt','agentReceipt','serviceReceipt','setupReceipt','candidateCoreSha256','candidateDesktopSha256','candidateUpdaterSha256')
    if ($context.format -cne 'sentinelai-setup-lifecycle-v1' -or $context.retained -cnotin @('true','false')) { throw 'Invalid lifecycle context.' }
    foreach ($version in @($context.oldVersion, $context.candidateVersion)) {
        if ($version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z') { throw 'Invalid lifecycle version.' }
    }
    foreach ($name in @('candidateCoreSha256','candidateDesktopSha256','candidateUpdaterSha256')) {
        if ($context.$name -cnotmatch '\A[0-9A-F]{64}\z') { throw 'Invalid candidate code proof.' }
    }
    foreach ($name in @('coreReceipt','agentReceipt','serviceReceipt','setupReceipt')) {
        $bytes = [Convert]::FromBase64String($context.$name)
        if ($bytes.Length -le 0 -or $bytes.Length -gt 4096) { throw 'Invalid lifecycle snapshot.' }
        [void](Read-PilotStrictJson -Json ((New-Object Text.UTF8Encoding($false, $true)).GetString($bytes)))
    }
    return $context
}

function Read-SetupLifecycleSnapshot {
    param($Context, [string]$Name)
    return Read-PilotStrictJson -Json ((New-Object Text.UTF8Encoding($false, $true)).GetString([Convert]::FromBase64String($Context.$Name)))
}

function Test-SetupLifecycleRetainedBaseline {
    param($Locations, $Owned)
    return $Owned.Retained -and (-not (Test-Path -LiteralPath $Locations.CodeRoot) -or
        @(Get-ChildItem -LiteralPath $Locations.CodeRoot -Force).Count -eq 0)
}

function Assert-SetupLifecycleOwnership {
    param($Locations, [switch]$UseContext)
    $coreSid = Get-SetupLifecycleCoreSid
    Assert-PilotTrustedPath -Path $Locations.DataRoot
    foreach ($entry in @(Get-ChildItem -LiteralPath $Locations.DataRoot -Force)) {
        if (-not $entry.PSIsContainer -or $entry.Name -cnotin @('Core','Agent','Setup')) { throw 'Foreign persistent data.' }
    }
    Assert-PilotTrustedPath -Path $Locations.SetupData -Tree
    foreach ($entry in @(Get-ChildItem -LiteralPath $Locations.SetupData -Force)) {
        $receiptTemporary = $entry.Name -cmatch '\A(?:setup-installation|lifecycle-context|retained-installation)\.json\.[0-9a-f]{32}\.tmp\z'
        if ($entry.PSIsContainer -or ($entry.Name -cnotin @('public-key.pem','setup-installation.json','lifecycle-context.json','retained-installation.json') -and -not $receiptTemporary)) { throw 'Foreign Setup state.' }
    }
    Assert-PilotTrustedPath -Path $Locations.CoreData -Tree -AllowServiceWrite -ServiceWriteSid $coreSid -ServiceWriteRoot $Locations.CoreData
    Assert-PilotTrustedPath -Path $Locations.AgentData -Tree -AllowServiceWrite
    $context = if ($UseContext) { Read-SetupLifecycleContext $Locations } else { $null }
    if ($null -ne $context) {
        $core = Read-SetupLifecycleSnapshot $context 'coreReceipt'
        $agent = Read-SetupLifecycleSnapshot $context 'agentReceipt'
        $service = Read-SetupLifecycleSnapshot $context 'serviceReceipt'
        $setup = Read-SetupLifecycleSnapshot $context 'setupReceipt'
    } else {
        $core = Read-PilotInstallationReceipt -Path (Join-Path $Locations.CoreData 'pilot-installation.json') -Component Core -CodeDirectory $Locations.CoreCode -DataDirectory $Locations.CoreData -ServiceWriteSid $coreSid -ServiceWriteRoot $Locations.CoreData
        $agent = Read-PilotInstallationReceipt -Path (Join-Path $Locations.AgentData 'pilot-installation.json') -Component Agent -CodeDirectory $Locations.AgentCode -DataDirectory $Locations.AgentData
        $service = Read-SetupLifecycleDocument -Path (Join-Path $Locations.CoreData 'core-service-installation.json') -DataDirectory $Locations.CoreData -ServiceSid $coreSid
        $setup = Read-SetupLifecycleDocument -Path (Join-Path $Locations.SetupData 'setup-installation.json')
    }
    foreach ($pair in @(@('Core',$core),@('Agent',$agent))) {
        $component = $pair[0]; $receipt = $pair[1]
        if ($null -eq $receipt) { throw 'Missing ownership receipt.' }
        Assert-PilotObjectProperties -Object $receipt -Names @('format','component','version','codeDirectory','dataDirectory','coreUrl','environment','channel','serviceName','serviceAccountSid')
        if ($receipt.format -cne 'sentinelai-pilot-v1' -or $receipt.component -cne $component -or
            $receipt.codeDirectory -cne $Locations[($component + 'Code')] -or $receipt.dataDirectory -cne $Locations[($component + 'Data')] -or
            $receipt.environment -cne 'development' -or $receipt.channel -cnotin @('stable','pilot','beta') -or
            $receipt.version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
            $receipt.serviceName -cne $(if ($component -ceq 'Agent') { 'SentinelAIAgent' } else { '' }) -or
            $receipt.serviceAccountSid -cne $(if ($component -ceq 'Agent') { 'S-1-5-19' } else { '' })) { throw 'Invalid component ownership.' }
    }
    if ($core.version -cne $agent.version -or $core.channel -cne $agent.channel -or $core.coreUrl -cne $agent.coreUrl) { throw 'Mixed installation receipts.' }
    if ($null -ne $context -and ($context.oldVersion -cne $core.version -or [version]$context.candidateVersion -lt [version]$context.oldVersion)) { throw 'Invalid lifecycle version floor.' }
    $origin = Assert-PilotCoreOrigin -CoreUrl $core.coreUrl
    if (-not $origin.IsLoopback -or $origin.Scheme -cne 'http') { throw 'Unsupported Setup Core origin.' }
    Assert-PilotExistingConfiguration -Path (Join-Path $Locations.CoreData 'pilot-config.json') -Component Core -DataDirectory $Locations.CoreData -CoreUrl $core.coreUrl -ServiceWriteSid $coreSid -ServiceWriteRoot $Locations.CoreData
    Assert-PilotExistingConfiguration -Path (Join-Path $Locations.AgentData 'pilot-config.json') -Component Agent -DataDirectory $Locations.AgentData -CoreUrl $core.coreUrl
    Assert-PilotObjectProperties -Object $service -Names @('format','serviceName','serviceAccount','serviceAccountSid','codeDirectory','dataDirectory','configurationSha256','executableSha256','version')
    if ($service.format -cne 'sentinelai-core-service-v1' -or $service.serviceName -cne 'SentinelAICore' -or
        $service.serviceAccount -cne 'NT SERVICE\SentinelAICore' -or $service.serviceAccountSid -cne $coreSid -or
        $service.codeDirectory -cne $Locations.CoreCode -or $service.dataDirectory -cne $Locations.CoreData -or
        $service.version -cne $core.version -or $service.executableSha256 -cnotmatch '\A[0-9A-F]{64}\z' -or
        $service.configurationSha256 -cne (Get-FileHash -LiteralPath (Join-Path $Locations.CoreData 'pilot-config.json') -Algorithm SHA256).Hash) { throw 'Invalid Core ownership.' }
    Assert-PilotObjectProperties -Object $setup -Names @('format','keyId','environment','channel','desktopDirectory','updaterDirectory','desktopSha256','updaterSha256')
    if ($setup.format -cne 'sentinelai-setup-v1' -or $setup.keyId -cnotmatch '\Adev-[A-Za-z0-9_-]{1,48}\z' -or
        $setup.environment -cne 'development' -or $setup.channel -cne $core.channel -or
        $setup.desktopDirectory -cne $Locations.DesktopCode -or $setup.updaterDirectory -cne $Locations.UpdaterCode -or
        $setup.desktopSha256 -cnotmatch '\A[0-9A-F]{64}\z' -or $setup.updaterSha256 -cnotmatch '\A[0-9A-F]{64}\z') { throw 'Invalid Setup ownership.' }
    [void](Read-SetupLifecycleDocument -Path (Join-Path $Locations.SetupData 'setup-installation.json'))
    [void](Assert-PilotPath -Path (Join-Path $Locations.SetupData 'public-key.pem') -MustExist -File)
    Assert-PilotTrustedPath -Path (Join-Path $Locations.SetupData 'public-key.pem')
    Assert-CoreServiceDatabase -Path (Join-Path $Locations.CoreData 'sentinelai.db')
    foreach ($name in @('endpoint-id','installation-id')) {
        if (-not (Read-PilotGuidFile -Path (Join-Path $Locations.AgentData $name))) { throw 'Missing retained endpoint identity.' }
    }
    [void](Assert-PilotPath -Path (Join-Path $Locations.AgentData 'enrollment-state') -MustExist -File)
    $retained = Test-Path -LiteralPath (Join-Path $Locations.SetupData 'retained-installation.json')
    if ($retained) {
        $marker = Read-SetupLifecycleDocument -Path (Join-Path $Locations.SetupData 'retained-installation.json')
        Assert-PilotObjectProperties -Object $marker -Names @('format','version')
        if ($marker.format -cne 'sentinelai-setup-retained-v1' -or $marker.version -cne $core.version) { throw 'Invalid retained ownership.' }
    }
    if ($null -ne $context -and $context.retained -ceq 'true') { $retained = $true }
    foreach ($component in @('Core','Agent')) {
        $registered = if ($component -ceq 'Core') { Get-CoreService } else { Get-PilotService }
        if ($null -eq $registered) {
            if (-not $retained) { throw 'Missing owned service.' }
        } elseif ($component -ceq 'Core') {
            Assert-CoreServiceOwned -Service $registered -Receipt $service -ExecutablePath (Join-Path $Locations.CoreCode 'SentinelAI.Core.exe') -ConfigurationPath (Join-Path $Locations.CoreData 'pilot-config.json')
        } else {
            Assert-PilotOwnedService -Service $registered -Receipt $agent -ExecutablePath (Join-Path $Locations.AgentCode 'SentinelAI.Agent.exe') -ConfigurationPath (Join-Path $Locations.AgentData 'pilot-config.json')
        }
    }
    if (Test-Path -LiteralPath $Locations.CodeRoot) {
        Assert-PilotTrustedPath -Path $Locations.CodeRoot -Tree
        foreach ($entry in @(Get-ChildItem -LiteralPath $Locations.CodeRoot -Force)) {
            if (($entry.PSIsContainer -and $entry.Name -cnotin @('Core','Agent','Desktop','Updater')) -or
                (-not $entry.PSIsContainer -and $entry.Name -cnotin @('deployment-version.json','.sentinelai-update-receipt.json'))) { throw 'Foreign code deployment.' }
        }
    } elseif (-not $retained -and $null -eq $context) { throw 'Missing owned code root.' }
    Assert-PilotTrustedPath -Path $Locations.Menu -Tree
    if (Test-Path -LiteralPath $Locations.Menu) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $Locations.Menu -Force)) {
            if ($entry.PSIsContainer -or $entry.Name -cne 'SentinelAI.lnk') { throw 'Foreign Start Menu entry.' }
        }
    }
    return @{ Core = $core; Agent = $agent; Service = $service; Setup = $setup; Context = $context; Retained = $retained }
}

function Get-SetupLifecycleJournal {
    param($Locations)
    return Join-Path ([IO.Path]::GetDirectoryName($Locations.CodeRoot)) '.SentinelAI.sentinelai-update.json'
}

function Inspect-SetupLifecycleInstallation {
    param($Locations)
    $hasInstallation = $false
    foreach ($name in @('CodeRoot','DataRoot','Menu')) { if (Test-Path -LiteralPath $Locations[$name]) { $hasInstallation = $true } }
    if ($null -ne (Get-CoreService) -or $null -ne (Get-PilotService)) { $hasInstallation = $true }
    if (-not $hasInstallation) { return @{ Kind = 'Fresh'; Version = '' } }
    try {
        $owned = Assert-SetupLifecycleOwnership $Locations -UseContext
        $journal = Get-SetupLifecycleJournal $Locations
        Assert-PilotTrustedPath -Path $journal
        if ($null -ne $owned.Context -or (Test-Path -LiteralPath $journal)) { return @{ Kind = 'RecoveryPending'; Version = $owned.Core.version } }
        return @{ Kind = $(if ($owned.Retained) { 'Retained' } else { 'Installed' }); Version = $owned.Core.version }
    } catch { return @{ Kind = 'Foreign'; Version = '' } }
}

function Set-SetupLifecycleReceipt {
    param([string]$Path, [string]$Content, [switch]$Core)
    # Adjacent atomic replacement leaves either complete ownership document.
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        Write-PilotProtectedFile -Path $temporary -Content $Content -Kind Receipt
        if ($Core) { Set-CoreServiceAcl -Path $temporary -Kind ProtectedFile }
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function New-SetupLifecycleContext {
    param($Locations, $Request)
    $owned = Assert-SetupLifecycleOwnership $Locations
    $path = Join-Path $Locations.SetupData 'lifecycle-context.json'
    if (Test-Path -LiteralPath $path) { throw 'A lifecycle operation must first be recovered.' }
    $context = @{ format = 'sentinelai-setup-lifecycle-v1'; oldVersion = $owned.Core.version; candidateVersion = $Request.version;
        retained = $(if ($owned.Retained) { 'true' } else { 'false' }) }
    foreach ($pair in @(@('coreReceipt',$Locations.CoreData,'pilot-installation.json'), @('agentReceipt',$Locations.AgentData,'pilot-installation.json'),
        @('serviceReceipt',$Locations.CoreData,'core-service-installation.json'), @('setupReceipt',$Locations.SetupData,'setup-installation.json'))) {
        $context[$pair[0]] = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $pair[1] $pair[2])))
    }
    # This command runs only after C# signature/hash/layout preflight. Keep the
    # candidate's public executable proofs in the durable protected snapshot.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $Request.workDirectory 'bundle\deployment.zip'))
    try {
        foreach ($pair in @(@('Core/SentinelAI.Core.exe','candidateCoreSha256'), @('Desktop/SentinelAI.Desktop.exe','candidateDesktopSha256'), @('Updater/SentinelAI.Updater.exe','candidateUpdaterSha256'))) {
            $entry = $archive.GetEntry($pair[0])
            if ($null -eq $entry -or $entry.Length -le 0 -or $entry.Length -gt 512MB) { throw 'Invalid authenticated candidate.' }
            $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
            try { $context[$pair[1]] = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
            finally { $sha.Dispose(); $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
    Set-SetupLifecycleReceipt -Path $path -Content ($context | ConvertTo-Json -Compress)
    if (-not (Test-Path -LiteralPath $Locations.CodeRoot)) { New-PilotDirectoryWithAcl -Path $Locations.CodeRoot -Kind Container }
}

function Set-SetupLifecycleCodeAcl {
    param($Locations)
    # The new tree is initially private. Services receive execute access only;
    # application state and writable runtime paths remain in ProgramData.
    Set-SetupCodeAcl -Path $Locations.CodeRoot -PublicRead
    foreach ($component in @('Core','Agent','Desktop','Updater')) {
        $directory = $Locations[($component + 'Code')]
        [void](Assert-PilotPath -Path $directory -MustExist)
        $entries = @((Get-Item -LiteralPath $directory -Force)) + @(Get-ChildItem -LiteralPath $directory -Recurse -Force)
        foreach ($entry in $entries) {
            if ($component -ceq 'Core') { Set-CoreServiceAcl -Path $entry.FullName -Kind Code }
            else {
                Set-SetupCodeAcl -Path $entry.FullName -PublicRead:($component -ceq 'Desktop')
                if ($component -ceq 'Agent') {
                    $acl = Get-Acl -LiteralPath $entry.FullName
                    $args = if ($entry.PSIsContainer) { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow') }
                        else { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')), 'ReadAndExecute', 'Allow') }
                    [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList $args))
                    Set-Acl -LiteralPath $entry.FullName -AclObject $acl
                }
            }
        }
    }
    foreach ($name in @('deployment-version.json','.sentinelai-update-receipt.json')) {
        $path = Join-Path $Locations.CodeRoot $name
        if (Test-Path -LiteralPath $path) { Set-SetupCodeAcl -Path $path }
    }
    Assert-PilotTrustedPath -Path $Locations.CodeRoot -Tree
}

function Sync-SetupLifecycleReceipts {
    param($Locations)
    $owned = Assert-SetupLifecycleOwnership $Locations -UseContext
    if ($null -eq $owned.Context) { return }
    $context = $owned.Context
    $markerPath = Join-Path $Locations.CodeRoot 'deployment-version.json'
    $version = $context.oldVersion
    if (Test-Path -LiteralPath $markerPath) {
        $marker = Read-SetupLifecycleDocument -Path $markerPath
        Assert-PilotObjectProperties -Object $marker -Names @('format','version')
        if ($marker.format -cne 'sentinelai-deployment-v1' -or $marker.version -cnotin @($context.oldVersion,$context.candidateVersion)) { throw 'Unexpected active deployment.' }
        $version = $marker.version
    }
    $candidateMatches = $true
    foreach ($pair in @(@($Locations.CoreCode,'SentinelAI.Core.exe','candidateCoreSha256'),
        @($Locations.DesktopCode,'SentinelAI.Desktop.exe','candidateDesktopSha256'), @($Locations.UpdaterCode,'SentinelAI.Updater.exe','candidateUpdaterSha256'))) {
        $executable = Join-Path $pair[0] $pair[1]
        if (-not (Test-Path -LiteralPath $executable) -or (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -cne $context.($pair[2])) { $candidateMatches = $false }
    }
    if ($version -ceq $context.candidateVersion -and $candidateMatches) {
        $owned.Core.version = $version; $owned.Agent.version = $version; $owned.Service.version = $version
        $owned.Service.executableSha256 = $context.candidateCoreSha256
        $owned.Setup.desktopSha256 = $context.candidateDesktopSha256
        $owned.Setup.updaterSha256 = $context.candidateUpdaterSha256
        Set-SetupLifecycleReceipt -Path (Join-Path $Locations.CoreData 'pilot-installation.json') -Content ($owned.Core | ConvertTo-Json -Compress) -Core
        Set-SetupLifecycleReceipt -Path (Join-Path $Locations.AgentData 'pilot-installation.json') -Content ($owned.Agent | ConvertTo-Json -Compress)
        Set-SetupLifecycleReceipt -Path (Join-Path $Locations.CoreData 'core-service-installation.json') -Content ($owned.Service | ConvertTo-Json -Compress) -Core
        Set-SetupLifecycleReceipt -Path (Join-Path $Locations.SetupData 'setup-installation.json') -Content ($owned.Setup | ConvertTo-Json -Compress)
    } elseif ($version -ceq $context.oldVersion) {
        # A rollback restores original proofs byte-for-byte; damaged baseline
        # bytes never become newly trusted merely because they can be hashed.
        foreach ($pair in @(@('coreReceipt',$Locations.CoreData,'pilot-installation.json'), @('agentReceipt',$Locations.AgentData,'pilot-installation.json'),
            @('serviceReceipt',$Locations.CoreData,'core-service-installation.json'), @('setupReceipt',$Locations.SetupData,'setup-installation.json'))) {
            $text = (New-Object Text.UTF8Encoding($false, $true)).GetString([Convert]::FromBase64String($context.($pair[0])))
            Set-SetupLifecycleReceipt -Path (Join-Path $pair[1] $pair[2]) -Content $text -Core:($pair[1] -ceq $Locations.CoreData)
        }
    } else { throw 'Active code does not match the authenticated candidate or prior version.' }
}

function Stop-SetupLifecycleServices {
    param($Locations)
    [void](Assert-SetupLifecycleOwnership $Locations -UseContext)
    if ($null -ne (Get-PilotService)) { Stop-PilotService -TimeoutSeconds 30 }
    if ($null -ne (Get-CoreService)) { Stop-CoreService -TimeoutSeconds 30 }
}

function Start-SetupLifecycleServices {
    param($Locations)
    $owned = Assert-SetupLifecycleOwnership $Locations -UseContext
    if (Test-SetupLifecycleRetainedBaseline $Locations $owned) {
        # Rollback of a retained-data reinstall restores the uninstalled state,
        # including removal of registrations created only for the failed candidate.
        if ($null -ne (Get-PilotService)) { Remove-PilotService }
        if ($null -ne (Get-CoreService)) { Remove-CoreService }
        Sync-SetupLifecycleReceipts $Locations
        return
    }
    Set-SetupLifecycleCodeAcl $Locations
    Sync-SetupLifecycleReceipts $Locations
    $pilot = Read-PilotInstallationReceipt -Path (Join-Path $Locations.CoreData 'pilot-installation.json') -Component Core -CodeDirectory $Locations.CoreCode -DataDirectory $Locations.CoreData -ServiceWriteSid (Get-SetupLifecycleCoreSid) -ServiceWriteRoot $Locations.CoreData
    [void](Read-CoreServiceReceipt -Path (Join-Path $Locations.CoreData 'core-service-installation.json') -CodeDirectory $Locations.CoreCode -DataDirectory $Locations.CoreData -PilotReceipt $pilot)
    $proof = Read-SetupLifecycleDocument -Path (Join-Path $Locations.SetupData 'setup-installation.json')
    if ($proof.desktopSha256 -cne (Get-FileHash -LiteralPath (Join-Path $Locations.DesktopCode 'SentinelAI.Desktop.exe') -Algorithm SHA256).Hash -or
        $proof.updaterSha256 -cne (Get-FileHash -LiteralPath (Join-Path $Locations.UpdaterCode 'SentinelAI.Updater.exe') -Algorithm SHA256).Hash) { throw 'Active auxiliary code does not match ownership proof.' }
    if ($null -eq (Get-CoreService)) {
        if (-not $owned.Retained) { throw 'Missing owned service.' }
        Register-CoreService -ExecutablePath (Join-Path $Locations.CoreCode 'SentinelAI.Core.exe') -ConfigurationPath (Join-Path $Locations.CoreData 'pilot-config.json')
        Set-CoreServiceRecovery
    }
    if ($null -eq (Get-PilotService)) {
        if (-not $owned.Retained) { throw 'Missing owned service.' }
        Register-PilotService -ExecutablePath (Join-Path $Locations.AgentCode 'SentinelAI.Agent.exe') -ConfigurationPath (Join-Path $Locations.AgentData 'pilot-config.json')
    }
    # Data/configuration/DPAPI files are never replaced or re-enrolled.
    Start-CoreService -TimeoutSeconds 30
    Start-PilotService -TimeoutSeconds 30
}

function Test-SetupLifecycleHealth {
    param($Locations)
    $owned = Assert-SetupLifecycleOwnership $Locations -UseContext
    if (Test-SetupLifecycleRetainedBaseline $Locations $owned) {
        if ($null -ne (Get-CoreService) -or $null -ne (Get-PilotService)) { throw 'Retained baseline still has service registrations.' }
        return
    }
    Wait-CoreServiceHealth -Origin ([Uri]$owned.Core.coreUrl) -TimeoutSeconds 20
    [void](Wait-PilotAgentEnrollment -DataDirectory $Locations.AgentData -TimeoutSeconds 15)
}

function Clear-SetupLifecycleContext {
    param($Locations)
    if (Test-Path -LiteralPath (Get-SetupLifecycleJournal $Locations)) { throw 'The update journal still requires recovery.' }
    $owned = Assert-SetupLifecycleOwnership $Locations -UseContext
    $retainedBaseline = Test-SetupLifecycleRetainedBaseline $Locations $owned
    Sync-SetupLifecycleReceipts $Locations
    foreach ($name in @('lifecycle-context.json','retained-installation.json')) {
        if ($retainedBaseline -and $name -ceq 'retained-installation.json') { continue }
        $path = Join-Path $Locations.SetupData $name
        Assert-PilotTrustedPath -Path $path
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    # Only protected, fixed-prefix receipt temporaries are owned by this adapter.
    foreach ($directory in @($Locations.CoreData,$Locations.AgentData,$Locations.SetupData)) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if (-not $entry.PSIsContainer -and $entry.Name -cmatch '\A(?:pilot-installation|core-service-installation|setup-installation|lifecycle-context|retained-installation)\.json\.[0-9a-f]{32}\.tmp\z') {
                if ($directory -ceq $Locations.CoreData) {
                    Assert-PilotTrustedPath -Path $entry.FullName -AllowServiceParent -ServiceWriteSid (Get-SetupLifecycleCoreSid) -ServiceWriteRoot $directory
                } elseif ($directory -ceq $Locations.AgentData) {
                    Assert-PilotTrustedPath -Path $entry.FullName -AllowServiceParent
                } else { Assert-PilotTrustedPath -Path $entry.FullName }
                Remove-Item -LiteralPath $entry.FullName -Force
            }
        }
    }
    if ($retainedBaseline) {
        if (Test-Path -LiteralPath $Locations.CodeRoot) { Remove-Item -LiteralPath $Locations.CodeRoot -Force }
        return
    }
    if (-not (Test-Path -LiteralPath $Locations.Menu)) { Install-SetupShortcut -Directory $Locations.Menu -DesktopDirectory $Locations.DesktopCode }
}

function Uninstall-SetupLifecycleInstallation {
    param($Locations, [bool]$PreserveData)
    $owned = Assert-SetupLifecycleOwnership $Locations
    if (Test-Path -LiteralPath (Get-SetupLifecycleJournal $Locations)) { throw 'Recover the pending transaction before uninstalling.' }
    $marker = @{ format = 'sentinelai-setup-retained-v1'; version = $owned.Core.version }
    Set-SetupLifecycleReceipt -Path (Join-Path $Locations.SetupData 'retained-installation.json') -Content ($marker | ConvertTo-Json -Compress)
    Stop-SetupLifecycleServices $Locations
    if ($null -ne (Get-PilotService)) { Remove-PilotService }
    if ($null -ne (Get-CoreService)) { Remove-CoreService }
    # All roots were fixed, bounded, link-free and proven owned before stopping.
    foreach ($path in @($Locations.Menu,$Locations.CodeRoot)) {
        Assert-PilotTrustedPath -Path $path -Tree
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    if (-not $PreserveData) {
        # Reachable only through explicit UI opt-in plus DELETE confirmation.
        [void](Assert-SetupLifecycleOwnership $Locations)
        Remove-Item -LiteralPath $Locations.DataRoot -Recurse -Force
    }
}

function Invoke-SetupLifecycleWorker {
    param($Request)
    Assert-PilotSupportedHost
    Assert-PilotTrustedPath -Path $Request.workDirectory -Tree
    $locations = Get-SetupLocations
    Write-SetupProgress 'inspect'
    if ($Request.action -ceq 'inspect') {
        $state = Inspect-SetupLifecycleInstallation $locations
        Write-Output ('STATE|' + $state.Kind + '|' + $state.Version)
    } else {
        [void](Assert-SetupLifecycleOwnership $locations -UseContext)
        switch -CaseSensitive ($Request.action) {
            'lifecycle-context' { New-SetupLifecycleContext $locations $Request }
            'lifecycle-stop' { Write-SetupProgress 'services'; Stop-SetupLifecycleServices $locations }
            'lifecycle-start' { Write-SetupProgress 'replace'; Start-SetupLifecycleServices $locations }
            'lifecycle-health' { Write-SetupProgress 'health'; Test-SetupLifecycleHealth $locations }
            'lifecycle-reconcile' { Sync-SetupLifecycleReceipts $locations }
            'lifecycle-cleanup' { Clear-SetupLifecycleContext $locations }
            'uninstall' { Write-SetupProgress 'uninstall'; Uninstall-SetupLifecycleInstallation $locations ($Request.preserveData -ceq 'true') }
            default { throw 'Invalid lifecycle action.' }
        }
    }
    Write-Output 'DONE'
}
