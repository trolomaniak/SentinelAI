# Portable workflow tests replace native Windows SCM/ACL facts, while preserving
# configuration/receipt parsing, signed-code comparison, hashes and state guards.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'installer/pilot/CoreServiceInstaller.psm1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-core-service-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:assertionCount = 0; $script:fixtureNumber = 0
function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}
function Assert-Rejected {
    param([scriptblock]$Action, [string]$Message)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Test $rejected $Message
}
function New-Fixture {
    param([switch]$LocalNetwork)
    Remove-Module CoreServiceInstaller -ErrorAction SilentlyContinue
    $module = Import-Module $modulePath -Force -DisableNameChecking -PassThru
    $script:fixtureNumber++
    $root = Join-Path $testRoot ('case-' + $script:fixtureNumber)
    $state = @{ Root = $root; Code = (Join-Path $root 'Core Code'); Data = (Join-Path $root 'Core Data');
        Bundle = (Join-Path $root 'Bundle'); Key = (Join-Path $root 'public.pem'); Service = $null;
        Events = [Collections.Generic.List[string]]::new(); ScArguments = [Collections.Generic.List[object]]::new(); Listeners = @();
        FailPrepare = $false; FailRegister = $false; FailStart = $false; FailHealth = $false; BusyListener = $false;
        BusyNetwork = $false; CertificatePresent = $true; HealthPort = $null; ExcludedRanges = @() }
    foreach ($path in @($state.Code,$state.Data,$state.Bundle)) { [void][IO.Directory]::CreateDirectory($path) }
    [IO.File]::WriteAllText($state.Key, 'synthetic public trust fixture')
    [IO.File]::WriteAllText((Join-Path $state.Code 'SentinelAI.Core.exe'), 'verified-core-fixture')
    $settings = @{ DataDirectory = $state.Data }
    if ($LocalNetwork) { $settings.LocalNetworkPort = '5443'; $settings.LocalNetworkCertificateSha256 = 'D' * 64 }
    [IO.File]::WriteAllText((Join-Path $state.Data 'pilot-config.json'), (@{ urls = 'http://127.0.0.1:5017'; SentinelAI = $settings } | ConvertTo-Json -Depth 4))
    $pilot = @{ format = 'sentinelai-pilot-v1'; component = 'Core'; version = '1.0.0'; codeDirectory = $state.Code;
        dataDirectory = $state.Data; coreUrl = 'http://127.0.0.1:5017'; environment = 'development'; channel = 'pilot'; serviceName = ''; serviceAccountSid = '' }
    [IO.File]::WriteAllText((Join-Path $state.Data 'pilot-installation.json'), ($pilot | ConvertTo-Json -Compress))
    $database = New-Object byte[] 100
    [Text.Encoding]::ASCII.GetBytes("SQLite format 3$([char]0)").CopyTo($database, 0)
    [IO.File]::WriteAllBytes((Join-Path $state.Data 'sentinelai.db'), $database)
    & $module {
        param($state)
        $script:TestState = $state
        function script:Assert-PilotSupportedHost { }
        function script:Assert-PilotPath {
            param([string]$Path, [switch]$MustExist, [switch]$File)
            if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Invalid test path.' }
            if ($MustExist -and -not (Test-Path -LiteralPath $Path)) { throw 'Missing test path.' }
            if (Test-Path -LiteralPath $Path) {
                $item = Get-Item -LiteralPath $Path -Force
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links are refused.' }
                if ($File -and $item.PSIsContainer) { throw 'A file is required.' }
            }
            return [IO.Path]::GetFullPath($Path)
        }
        function script:Assert-PilotTrustedPath { $script:TestState.Events.Add('trusted-path') }
        function script:Set-PilotFileAcl { $script:TestState.Events.Add('protected-file') }
        function script:Set-CoreServiceAcl { param($Path,$Kind); $script:TestState.Events.Add('acl-' + $Kind) }
        function script:Set-PilotDirectoryAcl { param($Path,$Kind); $script:TestState.Events.Add('restore-' + $Kind) }
        function script:Invoke-PilotPrepare {
            param($BundleDirectory,$PublicKeyPath,$KeyId,$Environment,$Channel,$Component,$OutputDirectory)
            $script:TestState.Events.Add('verify-package')
            if ($script:TestState.FailPrepare) { throw 'Rejected synthetic package.' }
            [void][IO.Directory]::CreateDirectory($OutputDirectory)
            [IO.File]::WriteAllText((Join-Path $OutputDirectory 'SentinelAI.Core.exe'), 'verified-core-fixture')
            [pscustomobject]@{ version = '1.0.0'; artifactId = 'sentinelai-core-win-x64'; environment = $Environment; channel = $Channel }
        }
        function script:Get-CoreService { $script:TestState.Service }
        function script:Get-NetTCPConnection {
            [CmdletBinding()]
            param($LocalPort,$State)
            $script:TestState.Listeners
        }
        function script:Register-CoreService {
            param($ExecutablePath,$ConfigurationPath)
            $script:TestState.Events.Add('register')
            if ($script:TestState.FailRegister) { throw 'Synthetic registration failure.' }
            $script:TestState.Service = [pscustomobject]@{ Name = 'SentinelAICore'; StartName = 'NT SERVICE\SentinelAICore';
                PathName = (Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath); State = 'Stopped'; ProcessId = 0 }
        }
        function script:Invoke-PilotSc { param([string[]]$Arguments); $script:TestState.ScArguments.Add($Arguments) }
        function script:Start-CoreService {
            $script:TestState.Events.Add('start')
            if ($script:TestState.FailStart) { throw 'Synthetic start failure.' }
            $script:TestState.Service.State = 'Running'
            $script:TestState.Service.ProcessId = 1717
        }
        function script:Stop-CoreService { $script:TestState.Events.Add('stop'); $script:TestState.Service.State = 'Stopped'; $script:TestState.Service.ProcessId = 0 }
        function script:Remove-CoreService { $script:TestState.Events.Add('remove'); $script:TestState.Service = $null }
        function script:Assert-CoreServiceListenerAvailable {
            $script:TestState.Events.Add('probe-listener')
            if ($script:TestState.BusyListener) { throw 'The loopback listener is occupied.' }
        }
        function script:Wait-CoreServiceHealth {
            param($Origin,$TimeoutSeconds,$LocalNetworkPort)
            $script:TestState.Events.Add('health'); $script:TestState.HealthPort = $LocalNetworkPort
            if ($script:TestState.FailHealth) { throw 'Synthetic health failure.' }
        }
        function script:Assert-CoreServiceLocalNetworkPortAvailable {
            param($Port)
            $script:TestState.Events.Add('probe-network-' + $Port)
            if ($script:TestState.BusyNetwork) { throw 'The local-network port is occupied.' }
        }
        function script:Test-CoreServiceCertificate { param($Sha256); $script:TestState.CertificatePresent -and $Sha256 -ceq ('D' * 64) }
        function script:Get-CoreServiceExcludedPortRanges { $script:TestState.ExcludedRanges }
    } $state
    # Receipt/configuration helper internals execute in their nested Pilot module.
    $pilotModule = $module.NestedModules | Where-Object Name -eq 'PilotInstaller'
    & $pilotModule {
        param($state)
        $script:TestState = $state
        function script:Assert-PilotPath {
            param([string]$Path, [switch]$MustExist, [switch]$File)
            if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Invalid test path.' }
            if ($MustExist -and -not (Test-Path -LiteralPath $Path)) { throw 'Missing test path.' }
            if (Test-Path -LiteralPath $Path) {
                $item = Get-Item -LiteralPath $Path -Force
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Links are refused.' }
                if ($File -and $item.PSIsContainer) { throw 'A file is required.' }
            }
            return [IO.Path]::GetFullPath($Path)
        }
        function script:Assert-PilotTrustedPath { }
        function script:Set-PilotFileAcl { }
    } $state
    [pscustomobject]@{ Module = $module; State = $state }
}
function Invoke-Action {
    param($Fixture, [string]$Action = 'Install')
    $options = @{ Action = $Action; CodeDirectory = $Fixture.State.Code; DataDirectory = $Fixture.State.Data; TimeoutSeconds = 10 }
    if ($Action -eq 'Install') {
        $options.BundleDirectory = $Fixture.State.Bundle; $options.PublicKeyPath = $Fixture.State.Key;
        $options.KeyId = 'synthetic-development'; $options.Environment = 'development'; $options.Channel = 'pilot'
    }
    Invoke-CoreServiceManagement @options
}
function Get-PreservedState {
    param($Fixture)
    $result = @{}
    foreach ($name in @('pilot-config.json','pilot-installation.json','sentinelai.db')) {
        $result[$name] = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Fixture.State.Data $name)))
    }
    $result
}
function Assert-Preserved {
    param($Fixture, $Expected)
    foreach ($name in $Expected.Keys) {
        Assert-Test ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Fixture.State.Data $name))) -ceq $Expected[$name]) ('Persistent state changed: ' + $name)
    }
}

try {
    $fixture = New-Fixture
    foreach ($kind in @('Code','DataDirectory','BackupDirectory','DataFile','ProtectedFile')) {
        $rules = @(Get-CoreServiceAclRules -Kind $kind -Directory:($kind -in 'Code','DataDirectory','BackupDirectory'))
        $serviceRules = @($rules | Where-Object { $_.Sid -like 'S-1-5-80-*' })
        Assert-Test ($serviceRules.Count -gt 0) ('Missing explicit virtual identity ACL: ' + $kind)
        foreach ($rule in $serviceRules) {
            $rights = [Security.AccessControl.FileSystemRights]$rule.Rights
            Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::ChangePermissions) -eq 0) 'Service can change filesystem permissions.'
            Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::TakeOwnership) -eq 0) 'Service can take filesystem ownership.'
            if ($kind -ne 'BackupDirectory') {
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -eq 0) 'Service can delete protected directory children.'
            }
            if ($kind -eq 'ProtectedFile' -or $kind -eq 'Code') {
                Assert-Test (($rights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete)) -eq 0) 'Service can overwrite/delete trusted code or metadata.'
            }
            if ($kind -eq 'DataDirectory' -and $rule.Propagation -ne 'InheritOnly') {
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::Delete) -eq 0) 'Service can delete its data directory.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0) 'Service cannot create SQLite sidecars.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::CreateDirectories) -eq 0) 'Service can create directories outside its backup subtree.'
            }
            if ($kind -eq 'BackupDirectory' -and $rule.Propagation -ne 'InheritOnly') {
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::Delete) -eq 0) 'Service can replace its backup root.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::WriteAttributes) -eq 0) 'Service can change backup-root reparse attributes.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::CreateDirectories) -ne 0) 'Service cannot create isolated backup work directories.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ne 0) 'Service cannot retire its backup work.'
            }
        }
    }
    $preserved = Get-PreservedState $fixture
    $output = Invoke-Action $fixture
    $backupDirectory = Join-Path $fixture.State.Data 'backups'
    Assert-Test (Test-Path -LiteralPath $backupDirectory -PathType Container) 'Install did not provision private backup storage.'
    Assert-Test ($fixture.State.Events.Contains('acl-BackupDirectory')) 'Backup storage did not receive its scoped service ACL.'
    $archive = Join-Path $backupDirectory ('a' * 32 + '.sab')
    [IO.File]::WriteAllText($archive, 'synthetic-encrypted-archive-fixture')
    $archiveDigest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'Installation did not start Core.'
    Assert-Test ($fixture.State.Service.StartName -ceq 'NT SERVICE\SentinelAICore') 'Core did not select its fixed virtual account.'
    Assert-Test ($fixture.State.Events.IndexOf('verify-package') -lt $fixture.State.Events.IndexOf('acl-Code')) 'ACLs changed before signed verification.'
    Assert-Test ($fixture.State.Events.IndexOf('register') -lt $fixture.State.Events.IndexOf('start')) 'Core started before SCM registration.'
    Assert-Test ($fixture.State.Service.PathName -ceq ('"' + (Join-Path $fixture.State.Code 'SentinelAI.Core.exe') + '" --config "' + (Join-Path $fixture.State.Data 'pilot-config.json') + '"')) 'SCM ImagePath contains unexpected arguments.'
    Assert-Test (-not (($output | Out-String) -match 'password|bootstrap|token')) 'Management output contains credential-like fields.'
    $sc = @($fixture.State.ScArguments | ForEach-Object { $_ -join ' ' })
    Assert-Test ($sc -contains 'config SentinelAICore start= delayed-auto') 'Core startup policy is not delayed automatic.'
    Assert-Test ($sc -contains 'failure SentinelAICore reset= 86400 actions= restart/5000/restart/15000/restart/60000') 'Recovery schedule changed.'
    Assert-Test ($sc -contains 'failureflag SentinelAICore 1') 'Non-crash failures do not use recovery.'
    Assert-Preserved $fixture $preserved
    $serviceReceipt = [IO.File]::ReadAllText((Join-Path $fixture.State.Data 'core-service-installation.json'))
    $fixture.State.Events.Clear(); $fixture.State.BusyListener = $true
    Invoke-Action $fixture 'Start' | Out-Null
    Assert-Test (-not $fixture.State.Events.Contains('probe-listener')) 'Idempotent start treats the owned listener as a conflict.'
    Assert-Test (-not $fixture.State.Events.Contains('acl-DataFile')) 'Online Start rewrites writable backup child ACLs.'
    foreach ($state in @('StartPending','StopPending','ContinuePending','PausePending','Paused','Stopped')) {
        $fixture.State.Service.State = $state
        $fixture.State.Service.ProcessId = 1717
        $fixture.State.Events.Clear()
        Initialize-CoreServiceBackupStorage -DataDirectory $fixture.State.Data
        Assert-Test (-not $fixture.State.Events.Contains('acl-DataFile') -and -not $fixture.State.Events.Contains('acl-BackupDirectory')) ('Backup ACLs changed while a service process could still run: ' + $state)
    }
    $fixture.State.Service.State = 'Stopped'; $fixture.State.Service.ProcessId = 0
    Initialize-CoreServiceBackupStorage -DataDirectory $fixture.State.Data
    Assert-Test ($fixture.State.Events.Contains('acl-DataFile') -and $fixture.State.Events.Contains('acl-BackupDirectory')) 'A fully stopped service did not allow backup ACL repair.'
    $fixture.State.Service.State = 'Running'; $fixture.State.Service.ProcessId = 1717
    $fixture.State.BusyListener = $false
    Invoke-Action $fixture 'Stop' | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Stopped') 'Graceful stop did not stop the owned service.'
    Invoke-Action $fixture 'Start' | Out-Null
    $fixture.State.Events.Clear()
    Invoke-Action $fixture 'Restart' | Out-Null
    Assert-Test ($fixture.State.Events.IndexOf('stop') -lt $fixture.State.Events.IndexOf('start')) 'Restart did not gracefully stop before starting.'
    Assert-Test ($fixture.State.Events.Contains('health')) 'Restart did not require health.'
    Assert-Test ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ceq $archiveDigest) 'Restart changed retained encrypted archive bytes.'
    Invoke-Action $fixture 'Uninstall' | Out-Null
    Assert-Test ($null -eq $fixture.State.Service) 'Uninstall did not remove its owned service.'
    Assert-Test ($fixture.State.Events.Contains('restore-CoreData')) 'Uninstall did not restore console data ACLs.'
    Assert-Preserved $fixture $preserved
    Assert-Test ([IO.File]::ReadAllText((Join-Path $fixture.State.Data 'core-service-installation.json')) -ceq $serviceReceipt) 'Uninstall deleted/changed its ownership receipt.'
    Assert-Test ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ceq $archiveDigest) 'Service uninstall removed retained backup data.'
    Invoke-Action $fixture | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'Same-package reinstall failed.'
    Assert-Preserved $fixture $preserved

    # Installer validates only the documented bounded backup tree, including
    # interrupted-publication names, without adopting arbitrary data directories.
    $fixture = New-Fixture
    Invoke-Action $fixture | Out-Null
    $backupDirectory = Join-Path $fixture.State.Data 'backups'
    $work = Join-Path $backupDirectory ('work-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory((Join-Path $work 'extracted'))
    foreach ($name in @('snapshot.db','snapshot.db-journal','payload.tmp','archive.tmp','verify.tmp','manifest.json','configuration.json','core.db')) {
        [IO.File]::WriteAllText((Join-Path $work $name), 'bounded-work-fixture')
    }
    foreach ($name in @('core.db','configuration.json')) { [IO.File]::WriteAllText((Join-Path (Join-Path $work 'extracted') $name), 'extracted-fixture') }
    foreach ($name in @('backup-identity.json','restore-journal.json','restore-old.db','restore.lock',('restore-journal.json.' + ('b' * 32) + '.tmp'))) {
        [IO.File]::WriteAllText((Join-Path $backupDirectory $name), 'interrupted-work-fixture')
    }
    Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data
    Assert-Test (@(Get-CoreServiceBackupEntries -DataDirectory $fixture.State.Data).Count -eq 17) 'A supported interrupted backup tree was rejected or incompletely inspected.'
    foreach ($relative in @('foreign.txt','work-INVALID','work-00000000000000000000000000000000/foreign.txt')) {
        $foreign = Join-Path $backupDirectory $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($foreign))
        [IO.File]::WriteAllText($foreign, 'foreign-data')
        Assert-Rejected { Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data } ('Unsupported backup state accepted: ' + $relative)
        [IO.File]::Delete($foreign)
        if ($relative.Contains('/')) { [IO.Directory]::Delete([IO.Path]::GetDirectoryName($foreign)) }
    }
    $nested = Join-Path $work 'untrusted'
    [void][IO.Directory]::CreateDirectory($nested)
    Assert-Rejected { Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data } 'An arbitrary work directory was accepted.'
    [IO.Directory]::Delete($nested)
    $link = Join-Path $work 'payload.tmp.link'
    New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $fixture.State.Data 'pilot-config.json') | Out-Null
    Assert-Rejected { Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data } 'A link in writable backup storage was accepted.'
    Remove-Item -LiteralPath $link -Force
    for ($index = 0; $index -lt 31; $index++) { [IO.File]::WriteAllText((Join-Path $backupDirectory ($index.ToString('x32') + '.sab')), 'encrypted-fixture') }
    Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data
    [IO.File]::WriteAllText((Join-Path $backupDirectory ('f' * 32 + '.sab')), 'excess-fixture')
    Assert-Rejected { Assert-CoreServiceBackupStorage -DataDirectory $fixture.State.Data } 'The installer accepted unbounded archive retention.'

    foreach ($failure in @('FailPrepare','FailRegister','FailStart','FailHealth','BusyListener')) {
        $fixture = New-Fixture; $before = Get-PreservedState $fixture; $fixture.State[$failure] = $true
        Assert-Rejected { Invoke-Action $fixture } ('Installation accepted failure: ' + $failure)
        Assert-Preserved $fixture $before
        Assert-Test ($null -eq $fixture.State.Service) 'Failed fresh installation left its registered service behind.'
        if ($failure -in 'FailPrepare','BusyListener') { Assert-Test (-not $fixture.State.Events.Contains('register')) 'Rejected prerequisites changed SCM.' }
    }
    foreach ($mutation in @('unknown-service','missing-pilot-receipt','changed-code','changed-config','bad-database','unknown-data','missing-service-receipt','changed-account','changed-image','changed-receipt')) {
        $fixture = New-Fixture
        if ($mutation -in 'missing-service-receipt','changed-account','changed-image','changed-receipt') { Invoke-Action $fixture | Out-Null }
        switch ($mutation) {
            'unknown-service' { $fixture.State.Service = [pscustomobject]@{ Name = 'SentinelAICore'; StartName = 'LocalSystem'; PathName = 'unrelated.exe'; State = 'Running'; ProcessId = 1234 } }
            'missing-pilot-receipt' { Remove-Item -LiteralPath (Join-Path $fixture.State.Data 'pilot-installation.json') }
            'changed-code' { [IO.File]::WriteAllText((Join-Path $fixture.State.Code 'SentinelAI.Core.exe'), 'unverified-code') }
            'changed-config' { [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'pilot-config.json'), '{"urls":"http://remote.example","SentinelAI":{"DataDirectory":"invalid"}}') }
            'bad-database' { [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'sentinelai.db'), 'not-initialized') }
            'unknown-data' { [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'unexpected.key'), 'synthetic unsupported file') }
            'missing-service-receipt' { Remove-Item -LiteralPath (Join-Path $fixture.State.Data 'core-service-installation.json') }
            'changed-account' { $fixture.State.Service.StartName = 'LocalSystem' }
            'changed-image' { $fixture.State.Service.PathName += ' --password synthetic' }
            'changed-receipt' { [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'core-service-installation.json'), '{"format":"unknown"}') }
        }
        $fixture.State.Events.Clear()
        Assert-Rejected { Invoke-Action $fixture } ('Unsafe installation accepted: ' + $mutation)
        Assert-Test (-not $fixture.State.Events.Contains('register')) 'Rejected ownership/configuration changed SCM.'
        Assert-Test (-not $fixture.State.Events.Contains('start')) 'Rejected ownership/configuration started service.'
    }
    $fixture = New-Fixture
    Assert-Rejected { Invoke-Action $fixture 'Stop' } 'Stop accepted a service without ownership proof.'
    Assert-Rejected { Invoke-CoreServiceManagement -Action Install -CodeDirectory $fixture.State.Code -DataDirectory $fixture.State.Data } 'Install did not require explicit signed bundle trust.'
    $fixture.State.Key = Join-Path $fixture.State.Bundle 'untrusted-public.pem'
    [IO.File]::WriteAllText($fixture.State.Key, 'synthetic public key delivered in untrusted bundle')
    Assert-Rejected { Invoke-Action $fixture } 'Install accepted public trust from the same delivered bundle.'

    foreach ($mutation in @('missing-database','corrupt-database','unknown-runtime-file')) {
        foreach ($action in @('Stop','Uninstall')) {
            $fixture = New-Fixture
            Invoke-Action $fixture | Out-Null
            $database = Join-Path $fixture.State.Data 'sentinelai.db'
            switch ($mutation) {
                'missing-database' { Remove-Item -LiteralPath $database }
                'corrupt-database' { [IO.File]::WriteAllText($database, 'synthetic damaged state must be retained') }
                'unknown-runtime-file' { [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'runtime-extra.txt'), 'synthetic runtime output') }
            }
            $retained = @{}
            foreach ($file in @(Get-ChildItem -LiteralPath $fixture.State.Data -File)) { $retained[$file.Name] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName)) }
            Invoke-Action $fixture $action | Out-Null
            if ($action -eq 'Stop') { Assert-Test ($fixture.State.Service.State -eq 'Stopped') 'Damaged state prevented safe stop.' }
            else { Assert-Test ($null -eq $fixture.State.Service) 'Damaged state prevented safe uninstall.' }
            foreach ($name in $retained.Keys) {
                Assert-Test ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $fixture.State.Data $name))) -ceq $retained[$name]) ('Stop/uninstall changed retained state: ' + $name)
            }
            if ($mutation -eq 'missing-database') { Assert-Test (-not (Test-Path -LiteralPath $database)) 'Stop/uninstall silently created a database.' }
        }
    }
    $fixture = New-Fixture
    $service = [pscustomobject]@{ ProcessId = 1717; State = 'Running' }
    $ipv4 = [Uri]'http://127.0.0.1:5017'
    Assert-Test (-not (Test-CoreServiceListener -Origin $ipv4 -Service $service)) 'A missing listener passed health ownership.'
    $fixture.State.Listeners = @([pscustomobject]@{ LocalAddress = '127.0.0.1'; OwningProcess = 1717 })
    Assert-Test (Test-CoreServiceListener -Origin $ipv4 -Service $service) 'Exact service-owned loopback listener was rejected.'
    $service.ProcessId = 0
    Assert-Test (-not (Test-CoreServiceListener -Origin $ipv4 -Service $service)) 'A zero SCM process ID passed ownership.'
    $service.ProcessId = 1818
    Assert-Test (-not (Test-CoreServiceListener -Origin $ipv4 -Service $service)) 'Foreign healthy listener passed service ownership.'
    $service.ProcessId = 1717
    foreach ($address in @('0.0.0.0','::','10.0.0.17')) {
        $fixture.State.Listeners = @([pscustomobject]@{ LocalAddress = $address; OwningProcess = 1717 })
        Assert-Test (-not (Test-CoreServiceListener -Origin $ipv4 -Service $service)) 'Wildcard/remote listener passed local health ownership.'
    }
    $fixture.State.Listeners = @([pscustomobject]@{ LocalAddress = '::1'; OwningProcess = 1717 })
    Assert-Test (Test-CoreServiceListener -Origin ([Uri]'http://[::1]:5017') -Service $service) 'Exact IPv6 service-owned loopback listener was rejected.'
    $fixture.State.Listeners += [pscustomobject]@{ LocalAddress = '127.0.0.1'; OwningProcess = 1818 }
    Assert-Test (-not (Test-CoreServiceListener -Origin ([Uri]'http://localhost:5017') -Service $service)) 'Mixed owned/foreign localhost listeners passed ownership.'
    # The central role: the local-network port must be free before a new central service is registered, and health
    # requires that listener whenever Core's certificate exists. A local-only installation never probes or requires it.
    $fixture = New-Fixture
    Invoke-Action $fixture | Out-Null
    Assert-Test (-not ($fixture.State.Events | Where-Object { $_ -like 'probe-network-*' }) -and $fixture.State.HealthPort -eq 0) 'A local-only Core probed or required the local-network listener.'
    $fixture = New-Fixture -LocalNetwork
    Invoke-Action $fixture | Out-Null
    Assert-Test ($fixture.State.Events.Contains('probe-network-5443') -and $fixture.State.HealthPort -eq 5443 -and
        $fixture.State.Events.IndexOf('probe-network-5443') -lt $fixture.State.Events.IndexOf('register')) 'The central Core did not reserve and require its local-network listener.'
    $fixture.State.Events.Clear(); $fixture.State.CertificatePresent = $false
    Invoke-Action $fixture 'Restart' | Out-Null
    Assert-Test ($fixture.State.HealthPort -eq 0 -and -not $fixture.State.Events.Contains('probe-network-5443')) 'Health required a listener whose certificate is missing.'
    $fixture = New-Fixture -LocalNetwork; $fixture.State.BusyNetwork = $true
    Assert-Rejected { Invoke-Action $fixture } 'Core installation accepted an occupied local-network port.'
    Assert-Test (-not $fixture.State.Events.Contains('register') -and $null -eq $fixture.State.Service) 'An occupied local-network port changed SCM.'
    # An existing central service restarts even when another program took the port: Core then serves loopback only.
    $fixture = New-Fixture -LocalNetwork
    Invoke-Action $fixture | Out-Null
    $fixture.State.Events.Clear(); $fixture.State.BusyNetwork = $true
    Invoke-Action $fixture 'Restart' | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Running' -and $fixture.State.HealthPort -eq 5443 -and
        -not $fixture.State.Events.Contains('probe-network-5443')) 'A taken local-network port stopped an existing Core service.'
    foreach ($network in @(@{ LocalNetworkPort = '5444'; LocalNetworkCertificateSha256 = 'D' * 64 }, @{ LocalNetworkPort = '5443'; LocalNetworkCertificateSha256 = 'd' * 64 },
        @{ LocalNetworkPort = '5443' }, @{ LocalNetworkCertificateSha256 = 'D' * 64 }, @{ LocalNetworkPort = '5443'; LocalNetworkCertificateSha256 = 'D' * 64; LocalNetworkAddress = '0.0.0.0' })) {
        $fixture = New-Fixture
        $settings = @{ DataDirectory = $fixture.State.Data } + $network
        [IO.File]::WriteAllText((Join-Path $fixture.State.Data 'pilot-config.json'), (@{ urls = 'http://127.0.0.1:5017'; SentinelAI = $settings } | ConvertTo-Json -Depth 4))
        Assert-Rejected { Invoke-Action $fixture } 'Core service management accepted a changed local-network configuration.'
        Assert-Test (-not $fixture.State.Events.Contains('register')) 'A changed local-network configuration changed SCM.'
    }

    # The central listener answers on every interface and only from the Core service process.
    $service = [pscustomobject]@{ ProcessId = 1717; State = 'Running' }
    foreach ($case in @(@{ Listeners = @(); Expected = $false }, @{ Listeners = @(@{ LocalAddress = '::'; OwningProcess = 1717 }); Expected = $true },
        @{ Listeners = @(@{ LocalAddress = '0.0.0.0'; OwningProcess = 1717 }, @{ LocalAddress = '::'; OwningProcess = 1717 }); Expected = $true },
        @{ Listeners = @(@{ LocalAddress = '::'; OwningProcess = 1818 }); Expected = $false },
        @{ Listeners = @(@{ LocalAddress = '::'; OwningProcess = 1717 }, @{ LocalAddress = '10.0.0.17'; OwningProcess = 1818 }); Expected = $false },
        @{ Listeners = @(@{ LocalAddress = '127.0.0.1'; OwningProcess = 1717 }); Expected = $false })) {
        $fixture.State.Listeners = @($case.Listeners | ForEach-Object { [pscustomobject]$_ })
        Assert-Test ((Test-CoreServiceLocalNetworkListener -Port 5443 -Service $service) -eq $case.Expected) 'Local-network listener ownership was misjudged.'
    }
    # Health waives the listener only while another program holds the port or Windows reserved it.
    foreach ($case in @(@{ Listeners = @(); Ranges = @(); Expected = $false }, @{ Listeners = @(@{ LocalAddress = '0.0.0.0'; OwningProcess = 1717 }); Ranges = @(); Expected = $false },
        @{ Listeners = @(@{ LocalAddress = '0.0.0.0'; OwningProcess = 1818 }); Ranges = @(); Expected = $true },
        @{ Listeners = @(@{ LocalAddress = '0.0.0.0'; OwningProcess = 1717 }, @{ LocalAddress = '::'; OwningProcess = 1818 }); Ranges = @(); Expected = $true },
        @{ Listeners = @(); Ranges = @(@{ Start = 5400; End = 5499 }); Expected = $true }, @{ Listeners = @(); Ranges = @(@{ Start = 5443; End = 5443 }); Expected = $true },
        @{ Listeners = @(); Ranges = @(@{ Start = 5444; End = 5543 }, @{ Start = 5300; End = 5442 }); Expected = $false })) {
        $fixture.State.Listeners = @($case.Listeners | ForEach-Object { [pscustomobject]$_ })
        $fixture.State.ExcludedRanges = @($case.Ranges | ForEach-Object { [pscustomobject]$_ })
        Assert-Test ((& $fixture.Module { param($service) Test-CoreServiceLocalNetworkPortUnusable -Port 5443 -Service $service } $service) -eq $case.Expected) 'An unusable local-network port was misjudged.'
    }
    $fixture.State.ExcludedRanges = @()
    # netsh output in any display language: only the data lines carry two port numbers.
    $ranges = @(ConvertFrom-CoreServiceExcludedPortRanges -Lines @('', 'Protocol tcp Port Exclusion Ranges', '', 'Start Port    End Port', '----------    --------',
        '      5357        5357', '     50000       50059     *', '', '* - Administered port exclusions.', 'Zakresy wykluczeń portów protokołu tcp 1 2 3'))
    Assert-Test ($ranges.Count -eq 2 -and $ranges[0].Start -eq 5357 -and $ranges[0].End -eq 5357 -and $ranges[1].Start -eq 50000 -and $ranges[1].End -eq 50059) 'Windows excluded port ranges were misread.'
    Assert-Test (@(ConvertFrom-CoreServiceExcludedPortRanges -Lines @((New-Object Management.Automation.ErrorRecord((New-Object Exception('5443 5443')), 'native', 'NotSpecified', $null)))).Count -eq 0) 'A netsh error line was read as an excluded range.'

    # The owned firewall rule: inbound TCP 5443 for Core's program, LocalSubnet, Domain and Private only.
    $module = $fixture.Module
    $program = 'C:\Program Files\SentinelAI\Core\SentinelAI.Core.exe'
    & $module {
        param($program)
        $script:Firewall = @{ Rule = $null; Created = $null; Removed = 0; Program = $program }
        function script:New-FirewallTestRule {
            param($Overrides = @{})
            $rule = @{ Name = 'SentinelAI-Core-LocalNetwork'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 3; EdgeTraversalPolicy = 'Block';
                Protocol = 'TCP'; LocalPort = '5443'; RemotePort = 'Any'; RemoteAddress = 'LocalSubnet'; LocalAddress = 'Any'; Program = $script:Firewall.Program }
            foreach ($key in $Overrides.Keys) { $rule[$key] = $Overrides[$key] }
            return [pscustomobject]$rule
        }
        function script:Get-NetFirewallRule { [CmdletBinding()] param($Name); if ($Name -ceq 'SentinelAI-Core-LocalNetwork') { $script:Firewall.Rule } }
        function script:Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule); [pscustomobject]@{ Protocol = $AssociatedNetFirewallRule.Protocol; LocalPort = $AssociatedNetFirewallRule.LocalPort; RemotePort = $AssociatedNetFirewallRule.RemotePort } }
        function script:Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule); [pscustomobject]@{ RemoteAddress = $AssociatedNetFirewallRule.RemoteAddress; LocalAddress = $AssociatedNetFirewallRule.LocalAddress } }
        function script:Get-NetFirewallApplicationFilter { param($AssociatedNetFirewallRule); [pscustomobject]@{ Program = $AssociatedNetFirewallRule.Program } }
        function script:Remove-NetFirewallRule { param($Name); $script:Firewall.Removed++; $script:Firewall.Rule = $null }
        function script:New-NetFirewallRule {
            param($Name,$DisplayName,$Description,$Group,$Direction,$Action,$Protocol,$LocalPort,$RemoteAddress,$Profile,$Program,$EdgeTraversalPolicy,$Enabled)
            $script:Firewall.Created = $PSBoundParameters
            $script:Firewall.Rule = New-FirewallTestRule @{ Name = $Name; Enabled = [string]$Enabled; Direction = [string]$Direction; Action = [string]$Action;
                Profile = $(if ((@($Profile) -join ',') -ceq 'Domain,Private') { 3 } else { 7 }); EdgeTraversalPolicy = [string]$EdgeTraversalPolicy;
                Protocol = [string]$Protocol; LocalPort = [string]$LocalPort; RemoteAddress = [string]$RemoteAddress; Program = $Program }
        }
    } $program
    Assert-Test (-not (& $module { param($program) Test-CoreServiceFirewallRule -Rule $null -ExecutablePath $program -Port 5443 } $program)) 'A missing firewall rule passed verification.'
    Assert-Test (& $module { param($program) Test-CoreServiceFirewallRule -Rule (New-FirewallTestRule) -ExecutablePath $program -Port 5443 } $program) 'The exact owned firewall rule failed verification.'
    foreach ($override in @(@{ Enabled = 'False' }, @{ Direction = 'Outbound' }, @{ Action = 'Block' }, @{ Profile = 7 }, @{ Profile = 4 }, @{ Profile = 1 },
        @{ EdgeTraversalPolicy = 'Allow' }, @{ Protocol = 'UDP' }, @{ LocalPort = '5000' }, @{ LocalPort = @('5443','5000') }, @{ RemotePort = '80' },
        @{ RemoteAddress = 'Any' }, @{ RemoteAddress = @('LocalSubnet','203.0.113.0/24') }, @{ LocalAddress = '10.0.0.17' }, @{ Program = 'C:\Other\Core.exe' }, @{ Program = 'Any' })) {
        Assert-Test (-not (& $module { param($program, $override) Test-CoreServiceFirewallRule -Rule (New-FirewallTestRule $override) -ExecutablePath $program -Port 5443 } $program $override)) 'A widened or changed firewall rule passed verification.'
    }
    & $module { param($program) Set-CoreServiceFirewallRule -ExecutablePath $program -Port 5443 } $program
    $created = & $module { $script:Firewall.Created }
    Assert-Test ($created.Name -ceq 'SentinelAI-Core-LocalNetwork' -and (@($created.Profile) -join ',') -ceq 'Domain,Private' -and $created.RemoteAddress -ceq 'LocalSubnet' -and
        $created.Direction -ceq 'Inbound' -and $created.Action -ceq 'Allow' -and $created.Protocol -ceq 'TCP' -and [string]$created.LocalPort -ceq '5443' -and
        $created.Program -ceq $program -and $created.EdgeTraversalPolicy -ceq 'Block' -and $created.Group -ceq 'SentinelAI') 'Setup created a firewall rule other than the owned Domain/Private LocalSubnet rule.'
    & $module { param($program) $script:Firewall.Created = $null; Set-CoreServiceFirewallRule -ExecutablePath $program -Port 5443 } $program
    Assert-Test ($null -eq (& $module { $script:Firewall.Created }) -and (& $module { $script:Firewall.Removed }) -eq 0) 'An intact owned rule was recreated.'
    & $module { $script:Firewall.Rule = New-FirewallTestRule @{ RemoteAddress = 'Any'; Profile = 7 } }
    & $module { param($program) Set-CoreServiceFirewallRule -ExecutablePath $program -Port 5443 } $program
    Assert-Test ((& $module { $script:Firewall.Removed }) -eq 1 -and (& $module { param($program) Test-CoreServiceFirewallRule -Rule $script:Firewall.Rule -ExecutablePath $program -Port 5443 } $program)) 'Repair did not restore a widened rule exactly.'
    & $module { Remove-CoreServiceFirewallRule }
    Assert-Test ($null -eq (& $module { $script:Firewall.Rule })) 'Uninstall left the owned firewall rule.'
    & $module { Remove-CoreServiceFirewallRule }
    Write-Output ('Core service portable workflow tests passed: ' + $script:assertionCount + ' assertions.')
} finally {
    Remove-Module CoreServiceInstaller -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
