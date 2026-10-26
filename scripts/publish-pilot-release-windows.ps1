#requires -Version 5.1
# MVP-4 pilot release: builds SentinelAI-Setup.exe and SentinelAI-Agent-Setup.exe with the owner's keys and contact
# details, and gathers them with the four pilot documents and SHA256SUMS.txt in one new folder, ready to upload.
# Inputs are the update public key and the pilot public keys; the only private key it reads is the update signing key,
# which signs the packages and is never copied. The pilot license private key is never an input.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$UpdateSigningPrivateKey,
    [Parameter(Mandatory = $true)][string]$UpdatePublicKeyPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^dev-[A-Za-z0-9_-]{1,48}$')][string]$KeyId,
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [Parameter(Mandatory = $true)][string[]]$PilotLicensePublicKey,
    [Parameter(Mandatory = $true)][string]$PilotContactCompany,
    [string]$PilotContactEmail = '',
    [string]$PilotContactPhone = '',
    [string]$PilotContactWebsite = '',
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$documents = @('SentinelAI-dla-firm.pl.md', 'SentinelAI-for-business.en.md', 'SentinelAI-przewodnik-IT.pl.md', 'SentinelAI-IT-guide.en.md')
$installers = @('SentinelAI-Setup.exe', 'SentinelAI-Agent-Setup.exe')
$work = $null
$created = $false
$complete = $false

try {
    if (-not [IO.Path]::IsPathRooted($OutputDirectory)) { throw 'An absolute output directory is required.' }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'The release directory must be new.' }
    if ($PilotLicensePublicKey.Count -eq 0) { throw 'A pilot release needs at least one pilot public key.' }
    foreach ($document in $documents) {
        if (-not (Test-Path -LiteralPath (Join-Path $repo ('docs/pilot/' + $document)) -PathType Leaf)) { throw 'A pilot document is missing.' }
    }

    # Both installers come from the existing publisher, which checks key placement, public trust, signatures and payloads.
    $work = $OutputDirectory + '.work-' + [Guid]::NewGuid().ToString('N')
    $common = @{
        Version = $Version; KeyId = $KeyId; Channel = $Channel
        DevelopmentPrivateKey = $UpdateSigningPrivateKey; PublicKeyPath = $UpdatePublicKeyPath
    }
    & (Join-Path $PSScriptRoot 'publish-setup-windows.ps1') @common -OutputDirectory (Join-Path $work 'central') `
        -PilotLicensePublicKey $PilotLicensePublicKey -PilotContactCompany $PilotContactCompany -PilotContactEmail $PilotContactEmail `
        -PilotContactPhone $PilotContactPhone -PilotContactWebsite $PilotContactWebsite
    & (Join-Path $PSScriptRoot 'publish-setup-windows.ps1') @common -OutputDirectory (Join-Path $work 'agent') -Product Agent

    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $created = $true
    Copy-Item -LiteralPath (Join-Path $work 'central/SentinelAI-Setup.exe') -Destination $OutputDirectory
    Copy-Item -LiteralPath (Join-Path $work 'agent/SentinelAI-Agent-Setup.exe') -Destination $OutputDirectory
    foreach ($document in $documents) { Copy-Item -LiteralPath (Join-Path $repo ('docs/pilot/' + $document)) -Destination $OutputDirectory }

    # sha256sum format: lowercase hash, two spaces, file name; Get-FileHash output can be compared with it directly.
    $lines = foreach ($name in $installers + $documents) {
        $stream = [IO.File]::OpenRead((Join-Path $OutputDirectory $name))
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() + '  ' + $name }
        finally { $sha256.Dispose(); $stream.Dispose() }
    }
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))

    # The release holds exactly the two installers, the four documents and the checksums: no key, script or intermediate file.
    $expected = @($installers + $documents + @('SHA256SUMS.txt') | Sort-Object)
    $actual = @(Get-ChildItem -LiteralPath $OutputDirectory -Force | ForEach-Object { $_.Name } | Sort-Object)
    if (($expected -join '|') -cne ($actual -join '|')) { throw 'The release folder does not hold exactly the expected files.' }
    foreach ($name in $installers) { if ((Get-Item -LiteralPath (Join-Path $OutputDirectory $name)).Length -le 0) { throw 'An installer is empty.' } }
    $complete = $true
    Write-Output ('Pilot release created: ' + $OutputDirectory)
} catch {
    throw ('Pilot release failed: ' + $_.Exception.Message)
} finally {
    if ($null -ne $work -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force }
    # Only a folder this run created is removed; an existing folder given by mistake is never touched.
    if (-not $complete -and $created) { Remove-Item -LiteralPath $OutputDirectory -Recurse -Force }
}
