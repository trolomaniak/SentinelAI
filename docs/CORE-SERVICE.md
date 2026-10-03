# Core Windows Service

Core can run as the managed `SentinelAICore` Windows Service on Windows 11 x64. It runs independently of the desktop and Agent. Console development hosting remains supported. Service registration uses the existing signed pilot code, protected configuration and SQLite directory; it does not migrate state or initialize a new administrator.

## Install

Follow [pilot package preparation and Core installation](PILOT.md) using a fresh development/test environment, a trusted bootstrap installer and a separately provisioned public key. Initialize the administrator through [native Desktop setup](DESKTOP-AUTH.md) before registering the service. The existing `Start-SentinelAICore.ps1` console alternative remains available; stop that exact console process before service registration. Desktop setup uses a private Core stdin pipe; legacy console bootstrap stays in the child console environment. Service mode rejects bootstrap environment credentials and refuses a database without an initialized administrator.

Open PowerShell **as Administrator** from a trusted checkout or the packaged installer directory:

```powershell
$manage = '.\installer\pilot\Manage-SentinelAICoreService.ps1'
$options = @{
    CodeDirectory = "$env:ProgramFiles\SentinelAI\Core"
    DataDirectory = "$env:ProgramData\SentinelAI\Core"
}
& $manage -Action Install @options -BundleDirectory 'C:\SentinelAI-Pilot' `
    -PublicKeyPath 'C:\SentinelAI-Trust\dev-pilot.public.pem' -KeyId dev-pilot `
    -Environment development -Channel pilot
Get-Service SentinelAICore
```

Installation re-verifies the signed package and exact installed code, existing pilot ownership, strict configuration, file links and ACLs before changing service registration. It writes a separate protected `core-service-installation.json` receipt. Existing unknown services, conflicting paths/configuration and untrusted writable locations are refused. The SCM command is the quoted executable followed only by `--config` and the quoted absolute `pilot-config.json` path. No account password, administrator password, activation credential or enrollment token is stored in that command or receipt.

## Identity and storage

The fixed account is the virtual account `NT SERVICE\SentinelAICore`, not an administrator. Windows manages its password and service logon. The installer needs elevation for SCM and NTFS ACL changes; Core itself needs no administrator, interactive logon, debug or shutdown privilege. Virtual accounts may authenticate to domain resources as the machine account; this workflow configures only loopback and does not enable ambient outbound authentication or provision domain access. Privileged local administrators remain trusted.

| Location | Service access | Purpose |
| --- | --- | --- |
| Core code directory | Read and execute | Immutable installed code and dashboard assets |
| Existing Core data directory | Traverse/read and create files | Existing SQLite and runtime files, without directory delete-child access |
| SQLite/runtime files | Modify | Persistence and SQLite sidecars |
| `pilot-config.json` and ownership receipts | Read only, protected ACLs | Nonsecret configuration and installer ownership |
| Agent code/data | No new grant | Existing LocalService/DPAPI enrollment boundary |

Configuration and receipts keep administrator/System ownership and protected ACLs. The service cannot rewrite or replace them. Service write trust applies only within the explicit Core data directory; code and unrelated ancestors retain installer-only write access. Code and data paths remain separate. Back up the existing data before operational changes; uninstall preserves it.

## Startup, stop and recovery

The installer explicitly selects delayed automatic startup. SCM restarts failed/crashed service processes after 5, 15 and 60 seconds, resetting the failure count after one day. Recovery does not reboot the computer or run commands. Non-crash failure actions are enabled; clean operator stop is successful and does not trigger recovery. A hosted worker that requests a clean stop is not equivalent to a process failure. Expected license-renewal failures continue to leave local monitoring running.

```powershell
& $manage -Action Stop @options
& $manage -Action Start @options
& $manage -Action Restart @options
```

The host allows 15 seconds for graceful shutdown; installer service operations have a bounded deadline (60 seconds by default). Start verifies the registered process and the existing `GET /api/health` response at the exact protected loopback origin. The endpoint keeps its existing `{"status":"healthy"}` contract and becomes available after persistence initialization. Closing `SentinelAI.Desktop.exe` leaves Core running. SQLite identity, administrator hash and retained security state persist; existing ephemeral bearer sessions still expire on Core restart, so sign in again.

Core retains its JSON console logging policy. SCM service hosting does not provide an interactive console or persist those messages to a new log file. Inspect the management command's generic failure, service state and Windows SCM events when diagnosing startup. Commands do not print credentials or request bodies; avoid credential transcripts and tracing.

## Remove or re-register

```powershell
& $manage -Action Uninstall @options
```

Removal stops and deletes only the matching installer-owned service, then restores protected operator/admin ACLs for console use. Code, configuration, receipts and SQLite bytes are retained. Re-register with `Install` and the same signed package to preserve administrator and Core identities. This workflow does not replace an older package, migrate accounts/state, delete data, change Agent enrollment or wire transactional automatic upgrades.

## Validation

`./scripts/build.sh` builds Core with the official WindowsServices integration. `./scripts/test.sh` runs actual console-host persistence/restart tests and portable PowerShell installer-policy tests, plus existing backend/desktop/dashboard regressions.

On a fresh elevated Windows 11 x64 test computer without `SentinelAICore` installed, prepare a signed development bundle and publish the desktop, then run the native acceptance script:

```powershell
& .\tests\core-service\Windows.Acceptance.ps1 -BundleDirectory 'C:\SentinelAI-Pilot' `
    -PublicKeyPath 'C:\SentinelAI-Trust\dev-pilot.public.pem' -KeyId dev-pilot `
    -Environment development -Channel pilot `
    -DesktopExecutablePath .\artifacts\desktop\win-x64\SentinelAI.Desktop.exe
```

The script stages the exact generated signed package/public verifier and separately supplied public key into fresh protected sibling directories, without copying source ACLs or relaxing installer checks. It uses synthetic credentials and verifies real SCM identity/policy/ACLs, graceful stop/start/restart, persisted administrator/Core identity, crash recovery and continued health after the real desktop closes. It removes only its owned service and retains test state for inspection. Cross-compilation and portable tests do not establish Windows runtime acceptance. The `core-service-windows` CI job runs this acceptance separately; successful native results for TASK-017 are recorded in [development status](../.agent/STATUS.md).
