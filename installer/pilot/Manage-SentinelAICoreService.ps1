#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Start','Stop','Restart','Uninstall')][string]$Action,
    [string]$CodeDirectory, [string]$DataDirectory,
    [string]$BundleDirectory, [string]$PublicKeyPath, [string]$KeyId,
    [ValidateSet('development','production')][string]$Environment,
    [ValidateSet('stable','pilot','beta')][string]$Channel,
    [ValidateRange(10,600)][int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'CoreServiceInstaller.psm1') -Force -DisableNameChecking
try { Invoke-CoreServiceManagement @PSBoundParameters }
catch {
    throw 'Core service management failed. Use elevated Windows x64 PowerShell and the matching protected signed pilot installation. Bootstrap the administrator in console mode first; stop that console before installing the service. Existing state is retained.'
}
