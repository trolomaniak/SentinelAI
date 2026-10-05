#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$DevelopmentPrivateKey,
    [Parameter(Mandatory = $true)][ValidatePattern('^dev-[A-Za-z0-9_-]{1,48}$')][string]$KeyId,
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [string]$OutputDirectory
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
    # Validate key placement before creating artifacts. The separate signer repeats this check.
    for ($directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DevelopmentPrivateKey)); $null -ne $directory; $directory = [IO.Path]::GetDirectoryName($directory)) {
        if ((Test-Path -LiteralPath (Join-Path $directory '.git')) -or
            ((Test-Path -LiteralPath (Join-Path $directory 'AGENTS.md')) -and (Test-Path -LiteralPath (Join-Path $directory 'SentinelAI.sln')))) { throw 'A development key outside source is required.' }
    }
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($component in @('core', 'agent', 'updater')) {
        $project = switch ($component) { 'core' { 'core/SentinelAI.Core.csproj' }; 'agent' { 'agent/SentinelAI.Agent.csproj' }; 'updater' { 'updater/SentinelAI.Updater.csproj' } }
        $publish = Join-Path $OutputDirectory ($component + '-publish')
        Invoke-PilotDotnet -Arguments @('publish', (Join-Path $repo $project), '--configuration', 'Release', '--runtime', 'win-x64', '--self-contained', 'true',
            '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:DebugType=none', '-p:DebugSymbols=false',
            ('-p:Version=' + $Version), ('-p:AssemblyVersion=' + $Version + '.0'), '--output', $publish)
        $executable = 'SentinelAI.' + $(if ($component -eq 'core') { 'Core' } elseif ($component -eq 'agent') { 'Agent' } else { 'Updater' }) + '.exe'
        if (-not (Test-Path -LiteralPath (Join-Path $publish $executable) -PathType Leaf)) { throw 'The Windows executable was not published.' }
        if ($component -eq 'core' -and (-not (Test-Path -LiteralPath (Join-Path $publish 'dashboard/index.html') -PathType Leaf) -or
            -not (Test-Path -LiteralPath (Join-Path $publish 'dashboard/assets/app.js') -PathType Leaf))) { throw 'Published Core dashboard assets are missing.' }
        if ($component -eq 'updater') { Move-Item -LiteralPath $publish -Destination (Join-Path $OutputDirectory 'updater'); continue }
        $zip = Join-Path $OutputDirectory ($component + '.zip')
        [IO.Compression.ZipFile]::CreateFromDirectory($publish, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
        Invoke-PilotDotnet -Arguments @('run', '--project', (Join-Path $repo 'tools/update-dev/SentinelAI.UpdateDev.csproj'), '--configuration', 'Release', '--', 'sign',
            '--private-key', [IO.Path]::GetFullPath($DevelopmentPrivateKey), '--key-id', $KeyId, '--package', $zip, '--version', $Version,
            '--artifact-id', ('sentinelai-' + $component + '-win-x64'), '--artifact-url', ('https://updates.example.invalid/pilot/' + $Version + '/' + $component + '.zip'),
            '--channel', $Channel, '--output', (Join-Path $OutputDirectory ($component + '.manifest.json')))
        Remove-Item -LiteralPath $publish -Recurse -Force
    }
    Copy-Item -LiteralPath (Join-Path $repo 'installer/pilot') -Destination (Join-Path $OutputDirectory 'installer') -Recurse
    Copy-Item -LiteralPath (Join-Path $repo 'docs/PILOT.md') -Destination (Join-Path $OutputDirectory 'PILOT.md')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/CORE-SERVICE.md') -Destination (Join-Path $OutputDirectory 'CORE-SERVICE.md')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/DESKTOP-AUTH.md') -Destination (Join-Path $OutputDirectory 'DESKTOP-AUTH.md')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/DESKTOP-DEVICES.md') -Destination (Join-Path $OutputDirectory 'DESKTOP-DEVICES.md')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/DESKTOP-ALERTS.md') -Destination (Join-Path $OutputDirectory 'DESKTOP-ALERTS.md')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/DESKTOP-RISK-REPORTS.md') -Destination (Join-Path $OutputDirectory 'DESKTOP-RISK-REPORTS.md')
    $complete = $true
    Write-Output ('Development pilot bundle created: ' + $OutputDirectory)
} catch {
    throw 'Pilot packaging failed. Check the version, development key outside source, SDK/package access and new output path. Partial artifacts are not a release.'
} finally {
    if (-not $complete) { Write-Warning 'Packaging did not finish; review and remove only the failed output directory before retrying.' }
}
