#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$DevelopmentPrivateKey,
    [Parameter(Mandatory = $true)][ValidatePattern('^dev-[A-Za-z0-9_-]{1,48}$')][string]$KeyId,
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [string]$OutputDirectory,
    # MVP-3: a prepared pilot-license directory (trust/<key ID>.pem public keys, optional contact.json) deployed next to Core.
    [string]$PilotLicenseDirectory,
    # MVP-7: the owner's HTTPS update server, built into Core as update-server.json; without it Core offers no central update.
    [string]$UpdateServerUrl = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repo ('artifacts/pilot/win-x64/' + $Version) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$complete = $false

function Invoke-PilotDotnet {
    param([string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'A pilot build/signing command failed.' }
}

try {
    foreach ($part in $Version.Split('.')) { if ([int]$part -gt 65535) { throw 'Invalid version.' } }
    if (-not [IO.Path]::IsPathRooted($DevelopmentPrivateKey) -or -not (Test-Path -LiteralPath $DevelopmentPrivateKey -PathType Leaf)) { throw 'A development key outside source is required.' }
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'The output directory must be new.' }
    if ($UpdateServerUrl.Length -gt 0 -and ($UpdateServerUrl.Length -gt 256 -or $UpdateServerUrl -cnotmatch '\Ahttps://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~-]+)*\z')) {
        throw 'The update server must be a lowercase https:// URL without credentials, query, fragment or trailing slash.'
    }
    # Validate key placement before creating artifacts. The separate signer repeats this check.
    for ($directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DevelopmentPrivateKey)); $null -ne $directory; $directory = [IO.Path]::GetDirectoryName($directory)) {
        if ((Test-Path -LiteralPath (Join-Path $directory '.git')) -or
            ((Test-Path -LiteralPath (Join-Path $directory 'AGENTS.md')) -and (Test-Path -LiteralPath (Join-Path $directory 'SentinelAI.sln')))) { throw 'A development key outside source is required.' }
    }
    if (-not [string]::IsNullOrWhiteSpace($PilotLicenseDirectory)) {
        if (-not [IO.Path]::IsPathRooted($PilotLicenseDirectory) -or -not (Test-Path -LiteralPath (Join-Path $PilotLicenseDirectory 'trust') -PathType Container)) { throw 'A prepared pilot license directory is required.' }
        foreach ($entry in @(Get-ChildItem -LiteralPath $PilotLicenseDirectory -Recurse -Force)) {
            $relative = $entry.FullName.Substring($PilotLicenseDirectory.TrimEnd('\', '/').Length + 1).Replace('\', '/')
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not ($relative -ceq 'trust' -or $relative -ceq 'contact.json' -or $relative -cmatch '\Atrust/[A-Za-z0-9_-]{1,64}\.pem\z')) { throw 'The pilot license directory holds only public keys and contact details.' }
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # The Agent is signed first: Core's code carries this release's signed Agent package for automatic Agent updates (MVP-7).
    foreach ($component in @('agent', 'core', 'updater')) {
        $project = switch ($component) { 'core' { 'core/SentinelAI.Core.csproj' }; 'agent' { 'agent/SentinelAI.Agent.csproj' }; 'updater' { 'updater/SentinelAI.Updater.csproj' } }
        $publish = Join-Path $OutputDirectory ($component + '-publish')
        # Ordinary self-contained directories: Setup keeps all runtime code inside the signed, protected installation.
        Invoke-PilotDotnet -Arguments @('publish', (Join-Path $repo $project), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'true',
            '-p:PublishSingleFile=false', '-p:DebugType=none', '-p:DebugSymbols=false',
            ('-p:Version=' + $Version), ('-p:AssemblyVersion=' + $Version + '.0'), '--output', $publish)
        $executable = 'SentinelAI.' + $(if ($component -eq 'core') { 'Core' } elseif ($component -eq 'agent') { 'Agent' } else { 'Updater' }) + '.exe'
        if (-not (Test-Path -LiteralPath (Join-Path $publish $executable) -PathType Leaf)) { throw 'The Windows executable was not published.' }
        if ($component -eq 'core' -and -not [string]::IsNullOrWhiteSpace($PilotLicenseDirectory)) {
            Copy-Item -LiteralPath $PilotLicenseDirectory -Destination (Join-Path $publish 'pilot-license') -Recurse
        }
        if ($component -eq 'core' -and $UpdateServerUrl.Length -gt 0) {
            $server = [ordered]@{ url = $UpdateServerUrl; channel = $Channel } | ConvertTo-Json -Compress
            [IO.File]::WriteAllText((Join-Path $publish 'update-server.json'), $server, (New-Object Text.UTF8Encoding($false)))
        }
        if ($component -eq 'core') {
            $agentUpdate = Join-Path $publish 'agent-update'
            New-Item -ItemType Directory -Path $agentUpdate | Out-Null
            Copy-Item -LiteralPath (Join-Path $OutputDirectory 'agent.zip') -Destination (Join-Path $agentUpdate 'agent.zip')
            Copy-Item -LiteralPath (Join-Path $OutputDirectory 'agent.manifest.json') -Destination (Join-Path $agentUpdate 'agent.manifest.json')
        }
        if ($component -eq 'updater') { Move-Item -LiteralPath $publish -Destination (Join-Path $OutputDirectory 'updater'); continue }
        $zip = Join-Path $OutputDirectory ($component + '.zip')
        [IO.Compression.ZipFile]::CreateFromDirectory($publish, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
        Invoke-PilotDotnet -Arguments @('run', '--project', (Join-Path $repo 'tools/update-dev/SentinelAI.UpdateDev.csproj'), '--configuration', 'Release', '--', 'sign',
            '--private-key', [IO.Path]::GetFullPath($DevelopmentPrivateKey), '--key-id', $KeyId, '--package', $zip, '--version', $Version,
            '--artifact-id', ('sentinelai-' + $component + '-win-x64'), '--artifact-url', ('https://updates.example.invalid/pilot/' + $Version + '/' + $component + '.zip'),
            '--channel', $Channel, '--output', (Join-Path $OutputDirectory ($component + '.manifest.json')))
        Remove-Item -LiteralPath $publish -Recurse -Force
    }
    # Setup loads only these two installer modules.
    New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'installer') | Out-Null
    foreach ($module in @('PilotInstaller.psm1', 'CoreServiceInstaller.psm1')) {
        Copy-Item -LiteralPath (Join-Path $repo ('installer/pilot/' + $module)) -Destination (Join-Path $OutputDirectory 'installer')
    }
    $complete = $true
    Write-Output ('Signed development packages created: ' + $OutputDirectory)
} catch {
    throw 'Pilot packaging failed. Check the version, development key outside source, SDK/package access and new output path. Partial artifacts are not a release.'
} finally {
    if (-not $complete) { Write-Warning 'Packaging did not finish; review and remove only the failed output directory before retrying.' }
}
