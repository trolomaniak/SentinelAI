# Trusted Setup bootstrap, loaded as an in-memory ScriptBlock by the Setup EXE.
# It does not change PowerShell execution, application-control or language policy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# The installer reports its own fixed progress markers. Suppress PowerShell's
# module-initialization progress, which WinPS can otherwise serialize to stderr.
$ProgressPreference = 'SilentlyContinue'
$script:SetupPhase = 'validate'

function Write-SetupProgress {
    param([ValidateSet('validate','core','services','agent','desktop','shortcut','inspect','replace','health','rollback','uninstall')][string]$Phase)
    $script:SetupPhase = $Phase
    Write-Output ('PROGRESS|' + $Phase)
}

function Read-SetupRequest {
    $builder = New-Object Text.StringBuilder
    while ($true) {
        $next = [Console]::In.Read()
        if ($next -eq -1 -or $next -eq 10) { break }
        if ($builder.Length -ge 8192) { throw 'Invalid request.' }
        [void]$builder.Append([char]$next)
    }
    if ($builder.Length -eq 0) { throw 'Invalid request.' }
    return $builder.ToString()
}

function Assert-SetupBootstrapDirectory {
    param([string]$Path)
    $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI-Setup'
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -cne [IO.Path]::GetFullPath($Path) -or
        [IO.Path]::GetDirectoryName($Path) -ine $root -or [IO.Path]::GetFileName($Path) -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Invalid staging path.' }
    foreach ($current in @($root, $Path)) {
        $item = Get-Item -LiteralPath $current -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid staging path.' }
        $acl = Get-Acl -LiteralPath $current
        if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Invalid staging owner.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Invalid staging ACL.' }
        }
    }
}

function Import-SetupInstallerModules {
    param([string]$WorkDirectory)
    foreach ($part in @('bundle\installer\PilotInstaller.psm1', 'bundle\installer\CoreServiceInstaller.psm1')) {
        $path = Join-Path $WorkDirectory $part
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or $item.Length -gt 262144 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid bootstrap module.' }
    }
    $pilotSource = [IO.File]::ReadAllText((Join-Path $WorkDirectory 'bundle\installer\PilotInstaller.psm1'))
    $pilot = New-Module -Name SentinelAISetupPilot -ScriptBlock ([ScriptBlock]::Create($pilotSource))
    Import-Module $pilot -Global -DisableNameChecking
    # Pass the already authenticated bootstrap module object, not a file-selected import.
    $coreSource = [IO.File]::ReadAllText((Join-Path $WorkDirectory 'bundle\installer\CoreServiceInstaller.psm1'))
    $core = New-Module -Name SentinelAISetupCore -ArgumentList @($pilot) -ScriptBlock ([ScriptBlock]::Create($coreSource))
    Import-Module $core -Global -DisableNameChecking
    $lifecyclePath = Join-Path $WorkDirectory 'setup\SetupLifecycle.ps1'
    $item = Get-Item -LiteralPath $lifecyclePath -Force
    if ($item.PSIsContainer -or $item.Length -gt 262144 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid lifecycle worker.' }
    # This script is embedded with the same authenticated payload as the modules.
    . ([ScriptBlock]::Create([IO.File]::ReadAllText($lifecyclePath)))
    foreach ($command in Get-Command -Name '*-SetupLifecycle*') { Set-Item -Path ('Function:global:' + $command.Name) -Value $command.ScriptBlock }
}

function Get-SetupLocations {
    $code = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'SentinelAI'
    $data = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI'
    $menu = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'SentinelAI'
    return @{ CodeRoot = $code; DataRoot = $data; CoreCode = Join-Path $code 'Core'; CoreData = Join-Path $data 'Core';
        AgentCode = Join-Path $code 'Agent'; AgentData = Join-Path $data 'Agent';
        DesktopCode = Join-Path $code 'Desktop'; UpdaterCode = Join-Path $code 'Updater';
        SetupData = Join-Path $data 'Setup'; Menu = $menu }
}

function Assert-SetupFreshTargets {
    param($Locations, [switch]$AllowPreparedCore, [switch]$AllowStartedCore)
    foreach ($name in @('CoreCode','CoreData','AgentCode','AgentData','DesktopCode','UpdaterCode','SetupData','Menu')) {
        if ($AllowPreparedCore -and $name -in @('CoreCode','CoreData')) { continue }
        $path = Assert-PilotPath -Path $Locations[$name]
        Assert-PilotTrustedPath -Path $path -Tree
        if (Test-Path -LiteralPath $path) { throw 'Existing installation requires separate inspection.' }
    }
    if ($null -ne (Get-PilotService)) { throw 'Existing Agent service.' }
    $core = Get-CoreService
    if (-not $AllowStartedCore -and $null -ne $core) { throw 'Existing Core service.' }
    if ($AllowStartedCore -and ($null -eq $core -or $core.State -cne 'Running')) { throw 'Prepared Core service unavailable.' }
}

function Set-SetupCodeAcl {
    param([string]$Path, [switch]$PublicRead)
    $item = Get-Item -LiteralPath $Path -Force
    $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-32-544','S-1-5-18')) {
        $args = if ($item.PSIsContainer) { @((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow') }
                else { @((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow') }
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList $args))
    }
    if ($PublicRead) {
        $args = if ($item.PSIsContainer) { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow') }
                else { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'Allow') }
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList $args))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Install-SetupAuxiliaryCode {
    param([string]$Source, [string]$Destination, [string]$Executable, [switch]$PublicRead)
    $Source = Assert-PilotPath -Path $Source -MustExist
    Assert-PilotTrustedPath -Path $Source -Tree
    [void](Assert-PilotPath -Path (Join-Path $Source $Executable) -MustExist -File)
    Assert-PilotTrustedPath -Path $Destination
    if (Test-Path -LiteralPath $Destination) { throw 'Existing code will not be overwritten.' }
    Ensure-PilotProtectedParent -Path ([IO.Path]::GetDirectoryName($Destination))
    New-PilotDirectoryWithAcl -Path $Destination -Kind Container
    foreach ($entry in @(Get-ChildItem -LiteralPath $Source -Recurse -Force | Sort-Object { $_.FullName.Length })) {
        $relative = $entry.FullName.Substring($Source.TrimEnd('\').Length + 1)
        $target = Join-Path $Destination $relative
        if ($entry.PSIsContainer) { New-PilotDirectoryWithAcl -Path $target -Kind Container; continue }
        $input = [IO.File]::Open($entry.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
        } finally { $input.Dispose() }
    }
    # Copy content only. Source/inherited ACLs never become installation authority.
    Set-SetupCodeAcl -Path $Destination -PublicRead:$PublicRead
    foreach ($entry in @(Get-ChildItem -LiteralPath $Destination -Recurse -Force)) { Set-SetupCodeAcl -Path $entry.FullName -PublicRead:$PublicRead }
    Assert-PilotTrustedPath -Path $Destination -Tree
}

function Install-SetupShortcut {
    param([string]$Directory, [string]$DesktopDirectory)
    Assert-PilotTrustedPath -Path $Directory
    if (Test-Path -LiteralPath $Directory) { throw 'Existing Start Menu entry.' }
    New-PilotDirectoryWithAcl -Path $Directory -Kind Container
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $path = Join-Path $Directory 'SentinelAI.lnk'
        $shortcut = $shell.CreateShortcut($path)
        $shortcut.TargetPath = Join-Path $DesktopDirectory 'SentinelAI.Desktop.exe'
        $shortcut.Arguments = ''
        $shortcut.WorkingDirectory = $DesktopDirectory
        $shortcut.Description = 'SentinelAI'
        $shortcut.Save()
        Set-SetupCodeAcl -Path $path -PublicRead
        Set-SetupCodeAcl -Path $Directory -PublicRead
        Assert-PilotTrustedPath -Path $Directory -Tree
    } finally {
        if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
}

function Invoke-SetupInstallation {
    param($Request)
    $locations = Get-SetupLocations
    $bundle = Join-Path $Request.workDirectory 'bundle'
    $root = Join-Path $Request.workDirectory 'trust\root.pem'
    Assert-PilotSupportedHost
    Assert-PilotTrustedPath -Path $Request.workDirectory -Tree
    $policy = @{ BundleDirectory = $bundle; PublicKeyPath = $root; KeyId = $Request.keyId; Environment = 'development'; Channel = $Request.channel }
    Write-SetupProgress 'validate'
    Assert-SetupFreshTargets -Locations $locations -AllowPreparedCore:($Request.action -ne 'prepare-core') -AllowStartedCore:($Request.action -eq 'complete')
    if ($Request.action -eq 'prepare-core') {
        Write-SetupProgress 'core'
        $installed = Invoke-PilotInstall -Component Core @policy -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData
        if ($installed.component -cne 'Core') { throw 'Core preparation failed.' }
        Write-Output 'DONE'
        return
    }
    if ($Request.action -eq 'start-core') {
        Write-SetupProgress 'services'
        $started = Invoke-CoreServiceManagement -Action Install @policy -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData -TimeoutSeconds 60
        if ($started.component -cne 'Core') { throw 'Core service failed.' }
        Write-Output 'DONE'
        return
    }
    try {
        # Recheck the exact owned registration and PID-bound health after token
        # issuance. No reusable administrator credential enters this process.
        Write-SetupProgress 'services'
        $started = Invoke-CoreServiceManagement -Action Start -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData -TimeoutSeconds 60
        if ($started.component -cne 'Core') { throw 'Core service failed.' }
        Write-SetupProgress 'agent'
        $agent = Invoke-PilotInstall -Component Agent @policy -CodeDirectory $locations.AgentCode -DataDirectory $locations.AgentData -EnrollmentToken $Request.enrollmentToken -TimeoutSeconds 180
        if ($agent.component -cne 'Agent') { throw 'Agent service failed.' }
        Write-SetupProgress 'desktop'
        Install-SetupAuxiliaryCode -Source (Join-Path $Request.workDirectory 'desktop') -Destination $locations.DesktopCode -Executable 'SentinelAI.Desktop.exe' -PublicRead
        Install-SetupAuxiliaryCode -Source (Join-Path $bundle 'updater') -Destination $locations.UpdaterCode -Executable 'SentinelAI.Updater.exe'
        New-PilotProtectedDirectory -Path $locations.SetupData -Kind Container
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'public-key.pem') -Content ([IO.File]::ReadAllText($root)) -Kind Receipt
        $receipt = @{ format = 'sentinelai-setup-v1'; keyId = $Request.keyId; environment = 'development'; channel = $Request.channel;
            desktopDirectory = $locations.DesktopCode; updaterDirectory = $locations.UpdaterCode;
            desktopSha256 = (Get-FileHash -LiteralPath (Join-Path $locations.DesktopCode 'SentinelAI.Desktop.exe') -Algorithm SHA256).Hash;
            updaterSha256 = (Get-FileHash -LiteralPath (Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe') -Algorithm SHA256).Hash }
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'setup-installation.json') -Content ($receipt | ConvertTo-Json -Compress) -Kind Receipt
        Write-SetupProgress 'shortcut'
        Install-SetupShortcut -Directory $locations.Menu -DesktopDirectory $locations.DesktopCode
        Write-Output 'DONE'
    } finally { $Request.enrollmentToken = $null }
}

function Assert-SetupRequest {
    param($Request)
    Assert-PilotObjectProperties -Object $Request -Names @('action','workDirectory','keyId','channel','enrollmentToken','version','preserveData')
    if ($Request.action -cnotin @('prepare-core','start-core','complete','inspect','lifecycle-stop','lifecycle-start','lifecycle-health','lifecycle-context','lifecycle-cleanup','lifecycle-reconcile','uninstall') -or $Request.keyId -isnot [string] -or
        $Request.keyId -cnotmatch '\Adev-[A-Za-z0-9_-]{1,48}\z' -or $Request.channel -cnotin @('stable','pilot','beta')) { throw 'Invalid policy.' }
    if ($Request.version -isnot [string] -or $Request.version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
        @($Request.version.Split('.') | Where-Object { [int]$_ -gt 65535 }).Count -ne 0 -or
        $Request.preserveData -cnotin @('true','false') -or ($Request.action -cne 'uninstall' -and $Request.preserveData -cne 'true')) { throw 'Invalid lifecycle policy.' }
    if ($Request.action -ne 'complete') {
        # The private wire uses an empty string, keeping the existing strict
        # Pilot JSON grammar limited to strings/objects without accepting null.
        if ($Request.enrollmentToken -isnot [string] -or $Request.enrollmentToken.Length -ne 0) { throw 'Unexpected enrollment token.' }
    } elseif ($Request.enrollmentToken -isnot [string] -or $Request.enrollmentToken -cnotmatch '\A[0-9a-fA-F]{64}\z') { throw 'Invalid enrollment token.' }
}

function Invoke-SetupWorkerMain {
    $raw = $null
    $request = $null
    try {
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Unsupported execution policy.' }
        [Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        $raw = Read-SetupRequest
        # Locate trusted resources before importing any in-memory module; strict JSON
        # is applied again using the existing parser before any installation mutation.
        $locator = $raw | ConvertFrom-Json
        if ($locator.workDirectory -isnot [string]) { throw 'Invalid request.' }
        Assert-SetupBootstrapDirectory -Path $locator.workDirectory
        Import-SetupInstallerModules -WorkDirectory $locator.workDirectory
        $request = Read-PilotStrictJson -Json $raw
        Assert-SetupRequest -Request $request
        if ($request.action -cin @('prepare-core','start-core','complete')) { Invoke-SetupInstallation -Request $request }
        else { Invoke-SetupLifecycleWorker -Request $request }
        exit 0
    } catch {
        # Component output, exception text, paths and credentials are never UI/log data.
        Write-Output ('FAILED|' + $script:SetupPhase)
        exit 1
    } finally { if ($null -ne $request -and $null -ne $request.PSObject.Properties['enrollmentToken']) { $request.enrollmentToken = $null }; $raw = $null }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-SetupWorkerMain }
