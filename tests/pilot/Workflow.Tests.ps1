# Dependency-free portable tests. Native Windows facts/ACL/SCM and enrollment
# transport are replaced; path layout, configuration and install logic are real.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'installer/pilot/PilotInstaller.psm1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-pilot-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:assertionCount = 0
$script:fixtureNumber = 0
$credential = [PSCredential]::new('synthetic-pilot-admin', (ConvertTo-SecureString 'synthetic-only-password-123456' -AsPlainText -Force))

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
    Remove-Module PilotInstaller -ErrorAction SilentlyContinue
    $module = Import-Module $modulePath -Force -DisableNameChecking -PassThru
    $script:fixtureNumber++
    $root = Join-Path $testRoot ('case-' + $script:fixtureNumber)
    [void][IO.Directory]::CreateDirectory($root)
    $state = @{
        Root = $root; CodeDirectory = (Join-Path $root 'Agent Code'); DataDirectory = (Join-Path $root 'Agent Data')
        CoreData = (Join-Path $root 'Core Data'); BundleDirectory = (Join-Path $root 'Bundle')
        PublicKeyPath = (Join-Path $root 'public.pem'); Events = [Collections.Generic.List[string]]::new()
        Service = $null; FailPrepare = $false; FailRegister = $false; FailStart = $false; FailWait = $false
        Token = ('a' * 64); RegisterArguments = @(); EndpointId = [Guid]::NewGuid().ToString('D')
        InstallationId = [Guid]::NewGuid().ToString('D')
    }
    [void][IO.Directory]::CreateDirectory($state.BundleDirectory)
    [void][IO.Directory]::CreateDirectory($state.CoreData)
    [IO.File]::WriteAllText($state.PublicKeyPath, 'synthetic public verification fixture')
    [IO.File]::WriteAllText((Join-Path $state.CoreData 'sentinelai.db'), 'synthetic database fixture')
    & $module {
        param($state)
        $script:TestState = $state
        function script:Assert-PilotSupportedHost { }
        # Only root/drive Windows facts are replaced; the real layout validator
        # still rejects equality/nesting and actual links in the install workflow.
        function script:Assert-PilotPath {
            param([string]$Path)
            if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Invalid test path.' }
            return [IO.Path]::GetFullPath($Path)
        }
        function script:Assert-PilotTrustedPath { }
        function script:Get-PilotCurrentOperatorSid { return 'S-1-5-21-100-200-300-1001' }
        function script:Set-PilotDirectoryAcl { $script:TestState.Events.Add('directory-acl') }
        function script:Set-PilotFileAcl { $script:TestState.Events.Add('file-acl') }
        function script:New-PilotDirectoryWithAcl {
            param([string]$Path, [string]$Kind)
            [void][IO.Directory]::CreateDirectory($Path)
            $script:TestState.Events.Add('directory-acl')
        }
        function script:Invoke-PilotPrepare {
            param($BundleDirectory, $PublicKeyPath, $KeyId, $Environment, $Channel, $Component, $OutputDirectory)
            $script:TestState.Events.Add('prepare')
            if ($script:TestState.FailPrepare) { throw 'Rejected synthetic package.' }
            [void][IO.Directory]::CreateDirectory($OutputDirectory)
            [IO.File]::WriteAllText((Join-Path $OutputDirectory ('SentinelAI.' + $Component + '.exe')), 'verified synthetic code')
            return [PSCustomObject]@{ version = '1.0.0'; artifactId = ('sentinelai-' + $Component.ToLowerInvariant() + '-win-x64'); channel = $Channel; environment = $Environment }
        }
        function script:Get-PilotService { return $script:TestState.Service }
        function script:Register-PilotService {
            param($ExecutablePath, $ConfigurationPath)
            $script:TestState.Events.Add('register')
            $script:TestState.RegisterArguments = @($ExecutablePath, $ConfigurationPath)
            if ($script:TestState.FailRegister) { throw 'Synthetic registration failure.' }
            $script:TestState.Service = [PSCustomObject]@{
                Name = 'SentinelAIAgent'; PathName = (Get-PilotAgentImagePath -ExecutablePath $ExecutablePath -ConfigurationPath $ConfigurationPath)
                StartName = 'NT AUTHORITY\LocalService'; State = 'Stopped'
            }
        }
        function script:Start-PilotService {
            $script:TestState.Events.Add('start')
            if ($script:TestState.FailStart) { throw 'Synthetic start failure.' }
            $script:TestState.Service.State = 'Running'
        }
        function script:Stop-PilotService {
            $script:TestState.Events.Add('stop')
            if ($null -ne $script:TestState.Service) { $script:TestState.Service.State = 'Stopped' }
        }
        function script:Remove-PilotService {
            $script:TestState.Events.Add('remove')
            $script:TestState.Service = $null
        }
        function script:Request-PilotEnrollmentToken {
            $script:TestState.Events.Add('request-token')
            return $script:TestState.Token
        }
        function script:Wait-PilotAgentEnrollment {
            $script:TestState.Events.Add('wait-enrollment')
            if ($script:TestState.FailWait) { throw 'Synthetic enrollment timeout.' }
            $data = $script:TestState.DataDirectory
            $files = @{
                'installation-id' = $script:TestState.InstallationId
                'enrollment-state' = 'synthetic DPAPI ciphertext, never a real secret'
                'endpoint-id' = $script:TestState.EndpointId
            }
            foreach ($entry in $files.GetEnumerator()) {
                $path = Join-Path $data $entry.Key
                if (-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, $entry.Value) }
            }
            $handoff = Join-Path $data 'pilot-enrollment-token'
            if (Test-Path -LiteralPath $handoff) { Remove-Item -LiteralPath $handoff }
            return [PSCustomObject]@{ endpointId = $script:TestState.EndpointId; installationId = $script:TestState.InstallationId }
        }
    } $state
    return [PSCustomObject]@{ Module = $module; State = $state }
}
function Get-InstallOptions {
    param($Fixture, [string]$Component = 'Agent')
    return @{
        Component = $Component; BundleDirectory = $Fixture.State.BundleDirectory
        PublicKeyPath = $Fixture.State.PublicKeyPath; KeyId = 'dev-pilot-test'; Environment = 'development'; Channel = 'pilot'
        CodeDirectory = $Fixture.State.CodeDirectory; DataDirectory = $Fixture.State.DataDirectory
        CoreUrl = 'http://127.0.0.1:5000'; AdminCredential = $credential; TimeoutSeconds = 30
    }
}
function Assert-NoSecrets {
    param($Fixture, $Output)
    $text = ($Output | Out-String)
    Assert-Test (-not $text.Contains($Fixture.State.Token)) 'Workflow output exposed the synthetic enrollment token.'
    Assert-Test (-not $text.Contains('synthetic-only-password-123456')) 'Workflow output exposed the synthetic administrator password.'
    $configurationPath = Join-Path $Fixture.State.DataDirectory 'pilot-config.json'
    Assert-Test (Test-Path -LiteralPath $configurationPath -PathType Leaf) 'Installation did not produce the nonsecret host configuration.'
    $configuration = [IO.File]::ReadAllText($configurationPath)
    Assert-Test (-not $configuration.Contains($Fixture.State.Token)) 'Host configuration contains an enrollment token.'
    Assert-Test (-not $configuration.Contains('synthetic-only-password-123456')) 'Host configuration contains an administrator password.'
    return $configurationPath
}

try {
    $nativeModule = Import-Module $modulePath -Force -DisableNameChecking -PassThru
    foreach ($invalidPath in @('relative-path', '\\server\share\folder', 'Registry::HKEY_LOCAL_MACHINE\Software', 'C:\invalid:stream', 'C:\invalid"quote', "C:\invalid`nnewline", 'C:\invalid?name')) {
        Assert-Rejected { Assert-PilotPath -Path $invalidPath } 'An unsupported path format was accepted.'
    }
    $fixture = New-Fixture
    # Real origin validation retains the existing remote HTTPS + certificate-pin boundary.
    foreach ($origin in @('http://127.0.0.1:5000', 'http://localhost:5010', 'http://[::1]:5000')) {
        Assert-PilotCoreOrigin -CoreUrl $origin | Out-Null
        Assert-Test $true 'A valid loopback origin was rejected.'
    }
    foreach ($origin in @('http://remote.example', 'http://127.0.0.1:5000/path', 'http://user:pass@127.0.0.1:5000', 'http://127.0.0.1:5000?query=1', 'http://127.0.0.1:5000#fragment', 'file:///tmp/example')) {
        Assert-Rejected { Assert-PilotCoreOrigin -CoreUrl $origin } 'An unsafe Core origin was accepted.'
    }
    Assert-Rejected { Assert-PilotCoreOrigin -CoreUrl 'https://remote.example' } 'A remote origin without a pin was accepted.'
    Assert-Rejected { Assert-PilotCoreOrigin -CoreUrl 'https://remote.example' -CoreCertificateSha256 'invalid' } 'A malformed certificate pin was accepted.'
    Assert-Rejected { Assert-PilotCoreOrigin -CoreUrl 'http://localhost:5000' -CoreCertificateSha256 ('a' * 64) } 'An HTTP certificate pin was accepted.'
    Assert-PilotCoreOrigin -CoreUrl 'https://remote.example' -CoreCertificateSha256 ('a' * 64) | Out-Null
    Assert-Test $true 'A pinned HTTPS origin was rejected.'

    # The real ImagePath builder and service creation arguments keep spaces quoted,
    # fix the account to LocalService, and allow no account/service overrides.
    $executable = Join-Path $fixture.State.CodeDirectory 'SentinelAI.Agent.exe'
    $configurationPath = Join-Path $fixture.State.DataDirectory 'agent-config.json'
    $imagePath = Get-PilotAgentImagePath -ExecutablePath $executable -ConfigurationPath $configurationPath
    Assert-Test ($imagePath -ceq ('"' + $executable + '" --config "' + $configurationPath + '"')) 'The service ImagePath is not quoted exactly.'
    Assert-Rejected { Get-PilotAgentImagePath -ExecutablePath ($executable + '"') -ConfigurationPath $configurationPath } 'A quoted executable path was accepted.'
    Assert-Rejected { Get-PilotAgentImagePath -ExecutablePath $executable -ConfigurationPath ($configurationPath + "`n") } 'A newline in service arguments was accepted.'
    $nativeArguments = @(
        @{ Value = ''; Encoded = '""' },
        @{ Value = 'two words'; Encoded = '"two words"' },
        @{ Value = 'C:\Agent\'; Encoded = '"C:\Agent\\"' },
        @{ Value = 'a\"b'; Encoded = '"a\\\"b"' },
        @{ Value = '"C:\Program Files\Agent.exe" --config "C:\Agent Data\pilot-config.json"'; Encoded = '"\"C:\Program Files\Agent.exe\" --config \"C:\Agent Data\pilot-config.json\""' }
    )
    foreach ($argument in $nativeArguments) {
        Assert-Test ((ConvertTo-PilotWindowsArgument -Argument $argument.Value) -ceq $argument.Encoded) 'A native Windows argument did not preserve spaces, quotes or trailing backslashes.'
    }
    Assert-Rejected { ConvertTo-PilotWindowsArgument -Argument ('unsafe' + [char]0 + 'argument') } 'A native argument containing NUL was accepted.'
    $registrationModule = Import-Module $modulePath -Force -DisableNameChecking -PassThru
    & $registrationModule {
        param($state)
        $script:ScTestState = $state
        function script:Assert-PilotPath { param($Path) return [IO.Path]::GetFullPath($Path) }
        function script:Invoke-PilotSc { param([string[]]$Arguments) $script:ScTestState.RegisterArguments = @($Arguments) }
    } $fixture.State
    Register-PilotService -ExecutablePath $executable -ConfigurationPath $configurationPath
    $scArguments = @($fixture.State.RegisterArguments)
    Assert-Test ($scArguments -contains 'create') 'Registration did not create a Windows service.'
    Assert-Test ($scArguments -contains 'SentinelAIAgent') 'Registration used an unexpected service name.'
    Assert-Test ($scArguments -contains 'NT AUTHORITY\LocalService') 'Registration did not fix the LocalService account.'
    Assert-Test ($scArguments -contains $imagePath) 'Registration changed the correctly quoted ImagePath.'

    $fixture = New-Fixture
    Assert-Rejected { Assert-PilotPathLayout -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.CodeDirectory } 'Equal code and state paths were accepted.'
    Assert-Rejected { Assert-PilotPathLayout -CodeDirectory $fixture.State.CodeDirectory -DataDirectory (Join-Path $fixture.State.CodeDirectory 'state') } 'State nested inside code was accepted.'
    Assert-Rejected { Assert-PilotPathLayout -CodeDirectory (Join-Path $fixture.State.DataDirectory 'code') -DataDirectory $fixture.State.DataDirectory } 'Code nested inside state was accepted.'

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture 'Core'
    $output = @(Invoke-PilotInstall @options *>&1)
    Assert-Test ($null -eq $fixture.State.Service) 'Installing Core changed the Agent service.'
    Assert-Test (-not $fixture.State.Events.Contains('request-token')) 'Installing Core requested an Agent enrollment token.'
    Assert-Test (Test-Path -LiteralPath (Join-Path $fixture.State.CodeDirectory 'SentinelAI.Core.exe')) 'Core verified code was not installed.'
    Assert-NoSecrets $fixture $output | Out-Null

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    $output = @(Invoke-PilotInstall @options *>&1)
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'The Agent workflow did not start the service.'
    Assert-Test ($fixture.State.Events.IndexOf('prepare') -lt $fixture.State.Events.IndexOf('register')) 'Service registration preceded authenticated package preparation.'
    Assert-Test ($fixture.State.Service.StartName -eq 'NT AUTHORITY\LocalService') 'The Agent workflow changed the service account.'
    $configurationPath = Assert-NoSecrets $fixture $output
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'))) 'The consumed token handoff was retained.'
    $retainedPaths = @('installation-id', 'enrollment-state', 'endpoint-id') | ForEach-Object { Join-Path $fixture.State.DataDirectory $_ }
    $retainedPaths += $configurationPath
    $retainedPaths += Join-Path $fixture.State.CoreData 'sentinelai.db'
    $retainedBytes = @{}
    foreach ($path in $retainedPaths) { $retainedBytes[$path] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory -CoreUrl $options.CoreUrl -TimeoutSeconds 30 | Out-Null
    Assert-Test ($null -eq $fixture.State.Service) 'Uninstallation did not remove the matching service.'
    foreach ($path in $retainedPaths) {
        Assert-Test (Test-Path -LiteralPath $path -PathType Leaf) 'Uninstallation deleted persistent test state.'
        Assert-Test ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -eq $retainedBytes[$path]) 'Uninstallation changed retained state.'
    }
    $fixture.State.Events.Clear()
    Invoke-PilotInstall @options | Out-Null
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'Reinstallation did not start the matching Agent service.'
    Assert-Test (-not $fixture.State.Events.Contains('request-token')) 'Reinstallation requested a new token for protected existing enrollment.'
    foreach ($path in $retainedPaths) {
        Assert-Test ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -eq $retainedBytes[$path]) 'Reinstallation changed existing identity, credentials or configuration.'
    }

    # Setup supplies a borrowed one-use token through its private worker pipe.
    # The actual Pilot workflow must accept it without logging in again, and
    # releasing it must not trigger parameter validation during null cleanup.
    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    [void]$options.Remove('AdminCredential')
    $options.EnrollmentToken = $fixture.State.Token
    $output = @(Invoke-PilotInstall @options *>&1)
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'Explicit-token enrollment did not start the Agent service.'
    Assert-Test (-not $fixture.State.Events.Contains('request-token')) 'Explicit-token enrollment requested administrator credentials.'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'))) 'Explicit-token enrollment retained its consumed handoff.'
    Assert-NoSecrets $fixture $output | Out-Null

    foreach ($invalidToken in @('', $null, 'invalid', ('g' * 64), ('a' * 63), ('a' * 65))) {
        $fixture = New-Fixture
        $options = Get-InstallOptions $fixture
        [void]$options.Remove('AdminCredential')
        $options.EnrollmentToken = $invalidToken
        Assert-Rejected { Invoke-PilotInstall @options } 'An invalid explicit enrollment token was accepted.'
        Assert-Test ($fixture.State.Events.Count -eq 0) 'Invalid-token validation occurred after installation mutation.'
    }
    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture 'Core'
    [void]$options.Remove('AdminCredential')
    $options.EnrollmentToken = $fixture.State.Token
    Assert-Rejected { Invoke-PilotInstall @options } 'An explicit Agent token was accepted for Core installation.'
    Assert-Test ($fixture.State.Events.Count -eq 0) 'Core token rejection occurred after installation mutation.'
    $options.Component = 'Agent'; $options.AdminCredential = $credential
    Assert-Rejected { Invoke-PilotInstall @options } 'An explicit token was accepted together with administrator credentials.'
    Assert-Test ($fixture.State.Events.Count -eq 0) 'Conflicting credential rejection occurred after installation mutation.'
    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    [void]$options.Remove('AdminCredential')
    $options.EnrollmentToken = $fixture.State.Token
    $fixture.State.FailWait = $true
    Assert-Rejected { Invoke-PilotInstall @options } 'An explicit-token enrollment failure was ignored.'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'))) 'Failed explicit-token enrollment retained its one-use handoff.'
    Assert-Test (-not $fixture.State.Events.Contains('request-token')) 'Failed explicit-token enrollment retried administrator login.'

    $fixture = New-Fixture
    $fixture.State.FailPrepare = $true
    $options = Get-InstallOptions $fixture
    Assert-Rejected { Invoke-PilotInstall @options } 'Tampered package preparation was ignored.'
    Assert-Test (-not $fixture.State.Events.Contains('register')) 'A rejected package changed the Service Control Manager.'
    Assert-Test (-not $fixture.State.Events.Contains('start')) 'A rejected package started a service.'
    Assert-Test (-not (Test-Path -LiteralPath $fixture.State.CodeDirectory)) 'A rejected package left executable installation code.'

    $fixture = New-Fixture
    $fixture.State.Service = [PSCustomObject]@{ Name = 'SentinelAIAgent'; PathName = '"C:\Unrelated\Other.exe"'; StartName = 'LocalSystem'; State = 'Running' }
    $options = Get-InstallOptions $fixture
    Assert-Rejected { Invoke-PilotInstall @options } 'The installer adopted an unknown existing service.'
    Assert-Test (-not $fixture.State.Events.Contains('prepare')) 'An unknown service was not rejected before package preparation.'
    Assert-Test (-not $fixture.State.Events.Contains('stop')) 'An unknown existing service was stopped.'
    Assert-Test (-not $fixture.State.Events.Contains('remove')) 'An unknown existing service was removed.'
    Assert-Rejected { Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory } 'Uninstallation adopted an unknown service.'
    Assert-Test (-not $fixture.State.Events.Contains('remove')) 'Uninstallation removed an unknown service.'

    foreach ($failure in @('FailStart', 'FailWait')) {
        $fixture = New-Fixture
        $fixture.State[$failure] = $true
        $options = Get-InstallOptions $fixture
        Assert-Rejected { Invoke-PilotInstall @options } 'A native start/enrollment failure was ignored.'
        Assert-Test ($fixture.State.Events.Contains('remove')) 'Failure cleanup did not remove its newly created service.'
        Assert-Test ($null -eq $fixture.State.Service) 'Failure cleanup retained its newly created service.'
        Assert-Test (Test-Path -LiteralPath $fixture.State.DataDirectory -PathType Container) 'Failure cleanup deleted persistent data.'
        Assert-Test (-not (Test-Path -LiteralPath (Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'))) 'Failure cleanup retained the transient token.'
        Assert-Test ([IO.File]::ReadAllText((Join-Path $fixture.State.CoreData 'sentinelai.db')) -eq 'synthetic database fixture') 'Agent failure cleanup affected Core data.'
    }

    $fixture = New-Fixture
    $fixture.State.FailRegister = $true
    $options = Get-InstallOptions $fixture
    Assert-Rejected { Invoke-PilotInstall @options } 'A registration failure was ignored.'
    Assert-Test (-not $fixture.State.Events.Contains('remove')) 'Registration failure cleanup removed a service it did not create.'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'))) 'Registration failure retained its transient token.'

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    Invoke-PilotInstall @options | Out-Null
    $fixture.State.Events.Clear()
    $fixture.State.FailWait = $true
    Assert-Rejected { Invoke-PilotInstall @options } 'Existing-service verification failure was ignored.'
    Assert-Test (-not $fixture.State.Events.Contains('remove')) 'Failure cleanup removed an existing owned service.'
    Assert-Test (-not $fixture.State.Events.Contains('stop')) 'Failure cleanup stopped an existing running service.'
    Assert-Test ($fixture.State.Service.State -eq 'Running') 'An existing running service was changed on failed verification.'

    foreach ($invalidContent in @('{', '{"Agent":{"CoreUrl":"http://remote.example","DataDirectory":"invalid"}}', '{"Agent":{"CoreUrl":"http://127.0.0.1:5000","DataDirectory":"invalid","EnrollmentToken":"embedded-secret"}}')) {
        $fixture = New-Fixture
        $options = Get-InstallOptions $fixture
        Invoke-PilotInstall @options | Out-Null
        Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory | Out-Null
        $path = Join-Path $fixture.State.DataDirectory 'pilot-config.json'
        [IO.File]::WriteAllText($path, $invalidContent)
        $fixture.State.Events.Clear()
        Assert-Rejected { Invoke-PilotInstall @options } 'Malformed or changed existing configuration was accepted.'
        Assert-Test (-not $fixture.State.Events.Contains('register')) 'Invalid existing configuration changed the service.'
        Assert-Test (-not $fixture.State.Events.Contains('start')) 'Invalid existing configuration started the service.'
        Assert-Test ([IO.File]::ReadAllText($path) -eq $invalidContent) 'Invalid existing configuration was overwritten silently.'
    }

    foreach ($encoding in @('duplicate', 'escaped-duplicate', 'comment', 'trailing-comma')) {
        $fixture = New-Fixture
        $options = Get-InstallOptions $fixture
        Invoke-PilotInstall @options | Out-Null
        Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory | Out-Null
        $path = Join-Path $fixture.State.DataDirectory 'pilot-config.json'
        $validJson = ([IO.File]::ReadAllText($path) | ConvertFrom-Json) | ConvertTo-Json -Depth 4 -Compress
        $invalidJson = switch ($encoding) {
            'duplicate' { $validJson.Replace('"CoreUrl":', '"CoreUrl":"http://127.0.0.1:5000","CoreUrl":') }
            'escaped-duplicate' { $validJson.Replace('"CoreUrl":', '"Core\u0055rl":"http://127.0.0.1:5000","CoreUrl":') }
            'comment' { $validJson.Replace('"Agent":', "// unsupported JSON comment`n" + '"Agent":') }
            'trailing-comma' { $validJson.Substring(0, $validJson.Length - 1) + ',}' }
        }
        [IO.File]::WriteAllText($path, $invalidJson)
        $fixture.State.Events.Clear()
        Assert-Rejected { Invoke-PilotInstall @options } ('Ambiguous JSON configuration was accepted: ' + $encoding)
        Assert-Test (-not $fixture.State.Events.Contains('register')) 'Ambiguous configuration changed the service.'
    }

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    Invoke-PilotInstall @options | Out-Null
    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory | Out-Null
    [IO.File]::WriteAllText((Join-Path $fixture.State.CodeDirectory 'SentinelAI.Agent.exe'), 'changed unverified local code')
    $fixture.State.Events.Clear()
    Assert-Rejected { Invoke-PilotInstall @options } 'Reinstallation ignored local executable changes.'
    Assert-Test (-not $fixture.State.Events.Contains('register')) 'Changed executable code was not rejected before service creation.'
    Assert-Test ([IO.File]::ReadAllText((Join-Path $fixture.State.CodeDirectory 'SentinelAI.Agent.exe')) -eq 'changed unverified local code') 'Reinstallation silently overwrote modified executable code.'

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    Invoke-PilotInstall @options | Out-Null
    $fixture.State.Service.StartName = 'LocalSystem'
    $fixture.State.Events.Clear()
    Assert-Rejected { Invoke-PilotInstall @options } 'A changed service account was accepted.'
    Assert-Test (-not $fixture.State.Events.Contains('start')) 'A changed service account was restarted.'
    Assert-Test (-not $fixture.State.Events.Contains('remove')) 'A changed existing service account was removed.'

    $fixture = New-Fixture
    $options = Get-InstallOptions $fixture
    Invoke-PilotInstall @options | Out-Null
    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $fixture.State.CodeDirectory -DataDirectory $fixture.State.DataDirectory | Out-Null
    Remove-Item -LiteralPath (Join-Path $fixture.State.DataDirectory 'enrollment-state')
    Remove-Item -LiteralPath (Join-Path $fixture.State.DataDirectory 'endpoint-id')
    $pendingToken = Join-Path $fixture.State.DataDirectory 'pilot-enrollment-token'
    [IO.File]::WriteAllText($pendingToken, ('b' * 64))
    $fixture.State.Events.Clear()
    Assert-Rejected { Invoke-PilotInstall @options } 'A preexisting pending enrollment handoff was overwritten.'
    Assert-Test ([IO.File]::ReadAllText($pendingToken) -eq ('b' * 64)) 'Failure cleanup removed a token it did not create.'
    Assert-Test (-not $fixture.State.Events.Contains('register')) 'A pending one-use token was not checked before service creation.'

    foreach ($existingKind in @('code', 'data')) {
        $fixture = New-Fixture
        $path = if ($existingKind -eq 'code') { $fixture.State.CodeDirectory } else { $fixture.State.DataDirectory }
        [void][IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'unowned-fixture'), 'retain this unrelated fixture')
        $options = Get-InstallOptions $fixture
        Assert-Rejected { Invoke-PilotInstall @options } 'A fresh install adopted a nonempty unowned directory.'
        Assert-Test (-not $fixture.State.Events.Contains('prepare')) 'An unowned directory was not rejected before preparation.'
        Assert-Test ([IO.File]::ReadAllText((Join-Path $path 'unowned-fixture')) -eq 'retain this unrelated fixture') 'A fresh install deleted unowned data.'
    }

    Write-Output ('Pilot workflow assertions passed: ' + $script:assertionCount)
} finally {
    Remove-Module PilotInstaller -ErrorAction SilentlyContinue
    $credential.Password.Dispose()
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
