[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Core','Agent','UninstallAgent')][string]$Component,
    [string]$BundleDirectory,
    [string]$PublicKeyPath,
    [string]$KeyId,
    [ValidateSet('development','production')][string]$Environment,
    [ValidateSet('stable','pilot','beta')][string]$Channel,
    [string]$CodeDirectory,
    [string]$DataDirectory,
    [string]$CoreUrl = 'http://127.0.0.1:5000',
    [string]$CoreCertificateSha256,
    [ValidateRange(10,600)][int]$TimeoutSeconds = 180,
    [PSCredential]$AdminCredential
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PilotInstaller.psm1') -Force -DisableNameChecking
try {
    Invoke-PilotInstall @PSBoundParameters | ConvertTo-Json -Compress
} catch {
    # Never render HTTP error bodies, credential objects, tokens or the original exception.
    Write-Error 'Pilot installation failed. Use elevated Windows x64 PowerShell, protected local NTFS paths, the intended signed bundle and explicit public trust configuration. Existing state is retained.' -ErrorAction Continue
    exit 1
}
