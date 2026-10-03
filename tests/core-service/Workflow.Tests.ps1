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
    Remove-Module CoreServiceInstaller -ErrorAction SilentlyContinue
    $module = Import-Module $modulePath -Force -DisableNameChecking -PassThru
    $script:fixtureNumber++
    $root = Join-Path $testRoot ('case-' + $script:fixtureNumber)
    $state = @{ Root = $root; Code = (Join-Path $root 'Core Code'); Data = (Join-Path $root 'Core Data');
        Bundle = (Join-Path $root 'Bundle'); Key = (Join-Path $root 'public.pem'); Service = $null;
        Events = [Collections.Generic.List[string]]::new(); ScArguments = [Collections.Generic.List[object]]::new(); Listeners = @();
        FailPrepare = $false; FailRegister = $false; FailStart = $false; FailHealth = $false; BusyListener = $false }
    foreach ($path in @($state.Code,$state.Data,$state.Bundle)) { [void][IO.Directory]::CreateDirectory($path) }
    [IO.File]::WriteAllText($state.Key, 'synthetic public trust fixture')
    [IO.File]::WriteAllText((Join-Path $state.Code 'SentinelAI.Core.exe'), 'verified-core-fixture')
    [IO.File]::WriteAllText((Join-Path $state.Data 'pilot-config.json'), (@{ urls = 'http://127.0.0.1:5017'; SentinelAI = @{ DataDirectory = $state.Data } } | ConvertTo-Json -Depth 4))
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
        function script:Get-PilotCurrentOperatorSid { 'S-1-5-21-100-200-300-1001' }
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
                PathName = (Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath); State = 'Stopped'; ProcessId = 1717 }
        }
        function script:Invoke-PilotSc { param([string[]]$Arguments); $script:TestState.ScArguments.Add($Arguments) }
        function script:Start-CoreService {
            $script:TestState.Events.Add('start')
            if ($script:TestState.FailStart) { throw 'Synthetic start failure.' }
            $script:TestState.Service.State = 'Running'
        }
        function script:Stop-CoreService { $script:TestState.Events.Add('stop'); $script:TestState.Service.State = 'Stopped' }
        function script:Remove-CoreService { $script:TestState.Events.Add('remove'); $script:TestState.Service = $null }
        function script:Assert-CoreServiceListenerAvailable {
            $script:TestState.Events.Add('probe-listener')
            if ($script:TestState.BusyListener) { throw 'The loopback listener is occupied.' }
        }
        function script:Wait-CoreServiceHealth {
            $script:TestState.Events.Add('health')
            if ($script:TestState.FailHealth) { throw 'Synthetic health failure.' }
        }
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
    foreach ($kind in @('Code','DataDirectory','DataFile','ProtectedFile')) {
        $rules = @(Get-CoreServiceAclRules -Kind $kind -Directory:($kind -in 'Code','DataDirectory'))
        $serviceRules = @($rules | Where-Object { $_.Sid -like 'S-1-5-80-*' })
        Assert-Test ($serviceRules.Count -gt 0) ('Missing explicit virtual identity ACL: ' + $kind)
        foreach ($rule in $serviceRules) {
            $rights = [Security.AccessControl.FileSystemRights]$rule.Rights
            Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::ChangePermissions) -eq 0) 'Service can change filesystem permissions.'
            Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::TakeOwnership) -eq 0) 'Service can take filesystem ownership.'
            Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -eq 0) 'Service can delete protected directory children.'
            if ($kind -eq 'ProtectedFile' -or $kind -eq 'Code') {
                Assert-Test (($rights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete)) -eq 0) 'Service can overwrite/delete trusted code or metadata.'
            }
            if ($kind -eq 'DataDirectory' -and $rule.Propagation -ne 'InheritOnly') {
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::Delete) -eq 0) 'Service can delete its data directory.'
                Assert-Test (($rights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0) 'Service cannot create SQLite sidecars.'
            }
        }
    }
    $preserved = Get-PreservedState $fixture
    $output = Invoke-Action $fixture
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
    $fixture.State.BusyListener = $false
    Invoke-Action $fixture 'Stop' | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Stopped') 'Graceful stop did not stop the owned service.'
    Invoke-Action $fixture 'Start' | Out-Null
    $fixture.State.Events.Clear()
    Invoke-Action $fixture 'Restart' | Out-Null
    Assert-Test ($fixture.State.Events.IndexOf('stop') -lt $fixture.State.Events.IndexOf('start')) 'Restart did not gracefully stop before starting.'
    Assert-Test ($fixture.State.Events.Contains('health')) 'Restart did not require health.'
    Invoke-Action $fixture 'Uninstall' | Out-Null
    Assert-Test ($null -eq $fixture.State.Service) 'Uninstall did not remove its owned service.'
    Assert-Test ($fixture.State.Events.Contains('restore-CoreData')) 'Uninstall did not restore console data ACLs.'
    Assert-Preserved $fixture $preserved
    Assert-Test ([IO.File]::ReadAllText((Join-Path $fixture.State.Data 'core-service-installation.json')) -ceq $serviceReceipt) 'Uninstall deleted/changed its ownership receipt.'
    Invoke-Action $fixture | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'Same-package reinstall failed.'
    Assert-Preserved $fixture $preserved

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
    Write-Output ('Core service portable workflow tests passed: ' + $script:assertionCount + ' assertions.')
} finally {
    Remove-Module CoreServiceInstaller -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
