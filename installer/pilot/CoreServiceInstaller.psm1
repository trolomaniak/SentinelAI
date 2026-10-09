param([System.Management.Automation.PSModuleInfo]$PilotInstallerModule)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($null -ne $PilotInstallerModule) {
    Import-Module $PilotInstallerModule -DisableNameChecking
} else {
    Import-Module (Join-Path $PSScriptRoot 'PilotInstaller.psm1') -DisableNameChecking
}
$script:CoreServiceName = 'SentinelAICore'
$script:CoreServiceAccount = 'NT SERVICE\SentinelAICore'
# Windows derives a service SID from SHA-1 of the uppercase UTF-16 service name.
# Registration additionally verifies the native account-to-SID translation.
$script:CoreServiceSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'

function Get-CoreServiceAclRules {
    param([ValidateSet('Code','DataDirectory','DataFile','ProtectedFile','RetainedFile')][string]$Kind, [bool]$Directory = $false)
    $inheritance = if ($Directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    foreach ($sid in @('S-1-5-32-544','S-1-5-18',(Get-PilotCurrentOperatorSid)) | Select-Object -Unique) {
        [pscustomobject]@{ Sid = $sid; Rights = 'FullControl'; Inheritance = $inheritance; Propagation = 'None' }
    }
    if ($Kind -eq 'RetainedFile') { return }
    if ($Kind -eq 'DataDirectory') {
        # Create SQLite sidecars without granting deletion of protected metadata.
        [pscustomobject]@{ Sid = $script:CoreServiceSid; Rights = 'ReadAndExecute, CreateFiles'; Inheritance = 'None'; Propagation = 'None' }
        [pscustomobject]@{ Sid = $script:CoreServiceSid; Rights = 'Modify'; Inheritance = 'ObjectInherit'; Propagation = 'InheritOnly' }
    } else {
        $rights = switch ($Kind) { Code { 'ReadAndExecute' }; DataFile { 'Modify' }; ProtectedFile { 'Read' } }
        [pscustomobject]@{ Sid = $script:CoreServiceSid; Rights = $rights; Inheritance = $inheritance; Propagation = 'None' }
    }
}

function Set-CoreServiceAcl {
    param([string]$Path, [ValidateSet('Code','DataDirectory','DataFile','ProtectedFile','RetainedFile')][string]$Kind)
    $directory = (Get-Item -LiteralPath $Path -Force).PSIsContainer
    $acl = if ($directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($rule in Get-CoreServiceAclRules -Kind $Kind -Directory $directory) {
        $sid = New-Object Security.Principal.SecurityIdentifier($rule.Sid)
        if ($directory) {
            $entry = New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule.Rights, $rule.Inheritance, $rule.Propagation, 'Allow')
        } else { $entry = New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule.Rights, 'Allow') }
        [void]$acl.AddAccessRule($entry)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-CoreServiceInstallationAcl {
    param([string]$CodeDirectory, [string]$DataDirectory, [switch]$RestoreConsole)
    if ($RestoreConsole) {
        Set-PilotDirectoryAcl -Path $CodeDirectory -Kind CoreCode
        foreach ($item in @(Get-ChildItem -LiteralPath $CodeDirectory -Recurse -Force)) {
            if ($item.PSIsContainer) { Set-PilotDirectoryAcl -Path $item.FullName -Kind CoreCode }
            else { Set-CoreServiceAcl -Path $item.FullName -Kind RetainedFile }
        }
        Set-PilotDirectoryAcl -Path $DataDirectory -Kind CoreData
    } else {
        Set-CoreServiceAcl -Path $CodeDirectory -Kind Code
        foreach ($item in @(Get-ChildItem -LiteralPath $CodeDirectory -Recurse -Force)) { Set-CoreServiceAcl -Path $item.FullName -Kind Code }
        Set-CoreServiceAcl -Path $DataDirectory -Kind DataDirectory
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $DataDirectory -Force)) {
        $kind = if ($RestoreConsole) { 'RetainedFile' } elseif ($item.Name -match '\Asentinelai\.db(?:-wal|-shm|-journal)?\z') { 'DataFile' } else { 'ProtectedFile' }
        Set-CoreServiceAcl -Path $item.FullName -Kind $kind
    }
}

function Get-CoreService { Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'" }

function Assert-CoreServiceOwned {
    param($Service, $Receipt, [string]$ExecutablePath, [string]$ConfigurationPath)
    $image = Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath
    if ($null -eq $Receipt -or $Service.Name -cne $script:CoreServiceName -or
        -not [string]::Equals($Service.PathName, $image, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($Service.StartName, $script:CoreServiceAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The existing Core service has no matching ownership proof; it will not be changed.'
    }
}

function Register-CoreService {
    param([string]$ExecutablePath, [string]$ConfigurationPath)
    $image = Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath
    Invoke-PilotSc -Arguments @('create', $script:CoreServiceName, 'binPath=', $image, 'start=', 'delayed-auto',
        'obj=', $script:CoreServiceAccount, 'DisplayName=', 'SentinelAI Local Core')
    Assert-CoreServiceAccountSid
}

function Assert-CoreServiceAccountSid {
    $sid = (New-Object Security.Principal.NTAccount($script:CoreServiceAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -cne $script:CoreServiceSid) { throw 'The fixed Core service identity could not be verified.' }
}

function Set-CoreServiceRecovery {
    Invoke-PilotSc -Arguments @('config', $script:CoreServiceName, 'start=', 'delayed-auto')
    Invoke-PilotSc -Arguments @('failure', $script:CoreServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000')
    Invoke-PilotSc -Arguments @('failureflag', $script:CoreServiceName, '1')
}

function Start-CoreService {
    param([int]$TimeoutSeconds = 60)
    $controller = Get-Service -Name $script:CoreServiceName
    try {
        if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { $controller.Start() }
        $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds($TimeoutSeconds))
    } finally { $controller.Dispose() }
}

function Stop-CoreService {
    param([int]$TimeoutSeconds = 60)
    $controller = Get-Service -Name $script:CoreServiceName
    try {
        if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            $controller.Stop()
            $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($TimeoutSeconds))
        }
    } finally { $controller.Dispose() }
}

function Remove-CoreService {
    Invoke-PilotSc -Arguments @('delete', $script:CoreServiceName)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($null -eq (Get-CoreService)) { return }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt 15)
    throw 'The Core service remains marked for deletion. Close service-management handles before retrying.'
}

function Assert-CoreServiceListenerAvailable {
    param([Uri]$Origin)
    $address = if ($Origin.Host -in '[::1]', '::1') { [Net.IPAddress]::IPv6Loopback } else { [Net.IPAddress]::Loopback }
    $listener = New-Object Net.Sockets.TcpListener($address, $Origin.Port)
    try { $listener.Start() } finally { $listener.Stop() }
}

function Wait-CoreServiceHealth {
    param([Uri]$Origin, [int]$TimeoutSeconds = 60)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $service = Get-CoreService
        if ($null -eq $service -or $service.State -ne 'Running') { throw 'The Core service stopped before becoming ready.' }
        try {
            if (Test-CoreServiceListener -Origin $Origin -Service $service) {
                $remaining = [Math]::Max(1, [Math]::Min(5000, [int](($TimeoutSeconds - $watch.Elapsed.TotalSeconds) * 1000)))
                $health = Read-CoreServiceHealth -Origin $Origin -TimeoutMilliseconds $remaining
                $current = Get-CoreService
                if ($health.status -ceq 'healthy' -and $null -ne $current -and $current.State -eq 'Running' -and
                    $current.ProcessId -eq $service.ProcessId -and (Test-CoreServiceListener -Origin $Origin -Service $current)) { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw 'The Core service did not become healthy within its deadline.'
}

function Test-CoreServiceListener {
    param([Uri]$Origin, $Service)
    if ($Service.ProcessId -le 0) { return $false }
    [string[]]$addresses = if ($Origin.Host -eq 'localhost') { @('127.0.0.1','::1') } elseif ($Origin.Host -in '[::1]', '::1') { @('::1') } else { @($Origin.Host) }
    $listeners = @(Get-NetTCPConnection -LocalPort $Origin.Port -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in ($addresses + @('0.0.0.0','::')) })
    if ($listeners.Count -eq 0) { return $false }
    foreach ($listener in $listeners) {
        if ($listener.LocalAddress -notin $addresses -or $listener.OwningProcess -ne $Service.ProcessId) { return $false }
    }
    return $true
}

function Read-CoreServiceHealth {
    param([Uri]$Origin, [ValidateRange(1,5000)][int]$TimeoutMilliseconds)
    if (-not $Origin.IsLoopback -or $Origin.Scheme -cne 'http') { throw 'Core service health requires the configured loopback origin.' }
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMilliseconds)
    $client.MaxResponseContentBufferSize = 1024
    $deadline = New-Object Threading.CancellationTokenSource($TimeoutMilliseconds)
    $response = $null
    try {
        $uri = New-Object Uri($Origin, '/api/health')
        # ResponseContentRead completes only after the bounded body has arrived.
        # A single cancellation/timeout covers the full operation on .NET Framework
        # (Windows PowerShell 5.1) as well as modern PowerShell.
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $request = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseContentRead, $deadline.Token)
        $remaining = [Math]::Max(1, $TimeoutMilliseconds - [int]$watch.ElapsedMilliseconds)
        # .NET Framework's body stream cancellation behavior differs from modern
        # .NET. Never wait unboundedly on that task: disposal/Cancel below aborts
        # an unfinished request after this caller's absolute deadline.
        if (-not $request.Wait($remaining)) {
            $deadline.Cancel()
            throw 'Core health exceeded its total request deadline.'
        }
        $response = $request.GetAwaiter().GetResult()
        if ([int]$response.StatusCode -ne 200 -or $null -eq $response.Content.Headers.ContentType -or
            $response.Content.Headers.ContentType.MediaType -cne 'application/json' -or $response.Content.Headers.ContentLength -gt 1024) {
            throw 'Core health response is invalid.'
        }
        $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $health = Read-PilotStrictJson -Json ((New-Object Text.UTF8Encoding($false, $true)).GetString($bytes))
        Assert-PilotObjectProperties -Object $health -Names @('status')
        return $health
    } finally {
        $deadline.Cancel()
        if ($null -ne $response) { $response.Dispose() }
        $deadline.Dispose(); $client.Dispose()
    }
}

function Assert-CoreServiceDatabase {
    param([string]$Path)
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $header = New-Object byte[] 16
        if ($stream.Length -lt 100 -or $stream.Read($header, 0, 16) -ne 16 -or
            [Text.Encoding]::ASCII.GetString($header) -cne ("SQLite format 3" + [char]0)) {
            throw 'An existing initialized SQLite database is required. Complete console bootstrap first.'
        }
    } finally { $stream.Dispose() }
}

function Read-CoreServiceReceipt {
    param([string]$Path, [string]$CodeDirectory, [string]$DataDirectory, $PilotReceipt)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    [void](Assert-PilotPath -Path $Path -MustExist -File)
    Assert-PilotTrustedPath -Path $Path -AllowServiceParent -ServiceWriteSid $script:CoreServiceSid -ServiceWriteRoot $DataDirectory
    $receipt = Read-PilotStrictJson -Json (Read-PilotUtf8Document -Path $Path -MaximumBytes 4096)
    Assert-PilotObjectProperties -Object $receipt -Names @('format','serviceName','serviceAccount','serviceAccountSid','codeDirectory','dataDirectory','configurationSha256','executableSha256','version')
    if ($receipt.format -cne 'sentinelai-core-service-v1' -or $receipt.serviceName -cne $script:CoreServiceName -or
        $receipt.serviceAccount -cne $script:CoreServiceAccount -or $receipt.serviceAccountSid -cne $script:CoreServiceSid -or
        $receipt.codeDirectory -cne $CodeDirectory -or $receipt.dataDirectory -cne $DataDirectory -or $receipt.version -cne $PilotReceipt.version -or
        $receipt.configurationSha256 -cne (Get-FileHash -LiteralPath (Join-Path $DataDirectory 'pilot-config.json') -Algorithm SHA256).Hash -or
        $receipt.executableSha256 -cne (Get-FileHash -LiteralPath (Join-Path $CodeDirectory 'SentinelAI.Core.exe') -Algorithm SHA256).Hash) {
        throw 'The Core service ownership receipt does not match the protected installation.'
    }
    return $receipt
}

function Invoke-CoreServiceManagement {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ValidateSet('Install','Start','Stop','Restart','Uninstall')][string]$Action,
        [string]$CodeDirectory, [string]$DataDirectory, [string]$BundleDirectory, [string]$PublicKeyPath, [string]$KeyId,
        [ValidateSet('development','production')][string]$Environment, [ValidateSet('stable','pilot','beta')][string]$Channel,
        [ValidateRange(10,600)][int]$TimeoutSeconds = 60)
    Assert-PilotSupportedHost
    if (-not $CodeDirectory) { $CodeDirectory = Join-Path $env:ProgramFiles 'SentinelAI\Core' }
    if (-not $DataDirectory) { $DataDirectory = Join-Path $env:ProgramData 'SentinelAI\Core' }
    $CodeDirectory = Assert-PilotPath -Path $CodeDirectory -MustExist
    $DataDirectory = Assert-PilotPath -Path $DataDirectory -MustExist
    Assert-PilotPathLayout -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory
    Assert-PilotTrustedPath -Path $CodeDirectory -Tree
    Assert-PilotTrustedPath -Path $DataDirectory -Tree -AllowServiceWrite -ServiceWriteSid $script:CoreServiceSid -ServiceWriteRoot $DataDirectory
    if ($Action -in 'Install','Start','Restart') {
        foreach ($item in @(Get-ChildItem -LiteralPath $DataDirectory -Force)) {
            if ($item.PSIsContainer -or $item.Name -cnotin @('pilot-config.json','pilot-installation.json','core-service-installation.json','sentinelai.db','sentinelai.db-wal','sentinelai.db-shm','sentinelai.db-journal')) {
                throw 'The Core data directory contains unsupported files; no state will be moved or deleted.'
            }
        }
    }
    $pilot = Read-PilotInstallationReceipt -Path (Join-Path $DataDirectory 'pilot-installation.json') -Component Core -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory -ServiceWriteSid $script:CoreServiceSid -ServiceWriteRoot $DataDirectory
    if ($null -eq $pilot) { throw 'An existing signed pilot Core ownership receipt is required.' }
    $origin = Assert-PilotCoreOrigin -CoreUrl $pilot.coreUrl
    if (-not $origin.IsLoopback -or $origin.Scheme -cne 'http') { throw 'This service workflow supports the existing loopback pilot configuration only.' }
    $configuration = Join-Path $DataDirectory 'pilot-config.json'
    $executable = Join-Path $CodeDirectory 'SentinelAI.Core.exe'
    [void](Assert-PilotPath -Path $executable -MustExist -File)
    Assert-PilotExistingConfiguration -Path $configuration -Component Core -DataDirectory $DataDirectory -CoreUrl $pilot.coreUrl -ServiceWriteSid $script:CoreServiceSid -ServiceWriteRoot $DataDirectory
    if ($Action -in 'Install','Start','Restart') { Assert-CoreServiceDatabase -Path (Join-Path $DataDirectory 'sentinelai.db') }
    $receiptPath = Join-Path $DataDirectory 'core-service-installation.json'
    $receipt = Read-CoreServiceReceipt -Path $receiptPath -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory -PilotReceipt $pilot
    $service = Get-CoreService
    if ($null -ne $service) { Assert-CoreServiceOwned -Service $service -Receipt $receipt -ExecutablePath $executable -ConfigurationPath $configuration }
    if ($Action -ne 'Install' -and $null -eq $receipt) { throw 'A matching service ownership receipt is required.' }
    if ($Action -ne 'Install' -and $Action -ne 'Uninstall' -and $null -eq $service) { throw 'The installer-owned Core service is not registered.' }
    $prepared = $null
    $createdService = $false
    try {
        if ($Action -eq 'Install') {
            if (-not $BundleDirectory -or -not $PublicKeyPath -or $KeyId -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z' -or -not $Environment -or -not $Channel) {
                throw 'Install requires an explicitly trusted signed bundle, public key, key ID, environment and channel.'
            }
            $BundleDirectory = Assert-PilotPath -Path $BundleDirectory -MustExist
            $PublicKeyPath = Assert-PilotPath -Path $PublicKeyPath -MustExist -File
            Assert-PilotTrustedPath -Path $PublicKeyPath
            if ($PublicKeyPath.StartsWith($BundleDirectory.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Provision the public trust key separately from the delivered bundle.'
            }
            $Environment = $Environment.ToLowerInvariant(); $Channel = $Channel.ToLowerInvariant()
            $prepared = Join-Path ([IO.Path]::GetDirectoryName($CodeDirectory)) ('.sentinelai-core-service-' + [Guid]::NewGuid().ToString('N'))
            $metadata = Invoke-PilotPrepare -BundleDirectory $BundleDirectory -PublicKeyPath $PublicKeyPath -KeyId $KeyId -Environment $Environment -Channel $Channel -Component Core -OutputDirectory $prepared
            Assert-PilotTrustedPath -Path $prepared -Tree
            if ($metadata.version -cne $pilot.version -or $Environment -cne $pilot.environment -or $Channel -cne $pilot.channel) { throw 'The service installer requires the exact existing signed pilot package.' }
            Assert-PilotPreparedCodeMatches -PreparedDirectory $prepared -CodeDirectory $CodeDirectory
            if ($null -eq $service -or $service.State -ne 'Running') { Assert-CoreServiceListenerAvailable -Origin $origin }
            Set-CoreServiceInstallationAcl -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory
            if ($null -eq $receipt) {
                $receipt = [pscustomobject]@{ format = 'sentinelai-core-service-v1'; serviceName = $script:CoreServiceName;
                    serviceAccount = $script:CoreServiceAccount; serviceAccountSid = $script:CoreServiceSid;
                    codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory; version = $pilot.version;
                    configurationSha256 = (Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash;
                    executableSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash }
                Write-PilotProtectedFile -Path $receiptPath -Content ($receipt | ConvertTo-Json -Compress) -Kind Receipt
                Set-CoreServiceAcl -Path $receiptPath -Kind ProtectedFile
            }
            if ($null -eq $service) {
                $createdService = $true
                Register-CoreService -ExecutablePath $executable -ConfigurationPath $configuration
            }
            Set-CoreServiceRecovery
        }
        if ($Action -in 'Stop','Restart','Uninstall' -and $null -ne $service) { Stop-CoreService -TimeoutSeconds $TimeoutSeconds }
        if ($Action -eq 'Uninstall') {
            if ($null -ne $service) { Remove-CoreService }
            Set-CoreServiceInstallationAcl -CodeDirectory $CodeDirectory -DataDirectory $DataDirectory -RestoreConsole
        } elseif ($Action -in 'Install','Start','Restart') {
            if ($Action -eq 'Restart' -or ($Action -eq 'Start' -and $service.State -ne 'Running')) { Assert-CoreServiceListenerAvailable -Origin $origin }
            Start-CoreService -TimeoutSeconds $TimeoutSeconds
            Wait-CoreServiceHealth -Origin $origin -TimeoutSeconds $TimeoutSeconds
        }
        [pscustomobject]@{ component = 'Core'; serviceName = $script:CoreServiceName; serviceAccount = $script:CoreServiceAccount;
            action = $Action; codeDirectory = $CodeDirectory; dataDirectory = $DataDirectory; dataPreserved = $true }
    } catch {
        if ($createdService) {
            try {
                $owned = Get-CoreService
                if ($null -ne $owned) {
                    Assert-CoreServiceOwned -Service $owned -Receipt $receipt -ExecutablePath $executable -ConfigurationPath $configuration
                    Stop-CoreService -TimeoutSeconds $TimeoutSeconds
                    Remove-CoreService
                }
            } catch { }
        }
        throw 'Core service management did not complete. Existing code, configuration and SQLite state were preserved; inspect the owned service before retrying.'
    } finally {
        if ($prepared -and (Test-Path -LiteralPath $prepared)) {
            Assert-PilotTrustedPath -Path $prepared -Tree
            Remove-Item -LiteralPath $prepared -Recurse -Force
        }
    }
}

Export-ModuleMember -Function *-CoreService*
