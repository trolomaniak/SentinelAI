# Windows pilot installation

For complete fresh installation from one executable, use [SentinelAI Setup](SETUP.md). This guide retains the separate signed-bundle workflow for development and diagnostics.

This pilot runs Core and one Endpoint Agent on a Windows 11 x64 computer. Native Desktop is the supported production interface and normal operation needs no browser. Initialize Core through Desktop, then register Core under its limited virtual service account with delayed automatic startup and recovery using the [Core service workflow](CORE-SERVICE.md). Agent runs automatically as `SentinelAIAgent` under Windows `LocalService`; both services continue when Desktop is closed. Console Core remains a development/diagnostic alternative. Published executables are self-contained and include .NET 10; deployment needs Windows PowerShell 5.1 or PowerShell 7, not an SDK. Use a fresh test environment first.

## Prepare a development bundle

On the build computer, install .NET 10 SDK. From a trusted repository checkout, create disposable development signing keys in a private directory outside every repository, then publish. Keep the private key on the build computer. Supply the public key to the deployment operator through a separate trusted channel.

```powershell
$keys = Join-Path $env:LOCALAPPDATA 'SentinelAI\PilotDevelopmentKeys'
dotnet run --project tools/update-dev -- keygen --directory $keys --key-id dev-pilot
& .\scripts\publish-pilot-windows.ps1 -Version 1.0.0 -DevelopmentPrivateKey (Join-Path $keys 'dev-pilot.private.pem') -KeyId dev-pilot -Channel pilot
```

The new bundle is `artifacts/pilot/win-x64/1.0.0`: signed `core.zip` / `agent.zip` and manifests, the public-only `updater` executable, installer scripts and this guide. It contains no private key, administrator credential or enrollment token. Existing output is refused; a partially failed build is not a release. The example URL in manifests is metadata; no download is performed. The manifests always identify `development`; use `-Environment development` explicitly. Production signing/provisioning remains outside these development tools. Publish Desktop separately using `./scripts/publish-desktop-windows.sh` from the same trusted checkout, then copy its complete `artifacts/desktop/win-x64` directory to the Windows machine; the pilot Core/Agent bundle does not install Desktop.

Package signatures authenticate the Core/Agent payloads. The installer scripts and bundled verifier are trusted bootstrap tools: obtain them from a trusted checkout/build, review them and verify your delivery channel. A public key included by an unknown sender does not establish trust. These pilot binaries/scripts do not have Authenticode signatures; follow the computer's script-execution policy and organizational signing requirements. Do not globally disable execution policy or certificate validation.

## Install and start Core

Copy the bundle to a local NTFS directory, for example `C:\SentinelAI-Pilot`, and the separately obtained public key to a protected file. Open **PowerShell as Administrator** for installation. The installer checks elevation and does not silently elevate. The default code directories are under Program Files; private configuration and persistent data are under ProgramData. Absolute custom local NTFS paths are supported, with code and data separated; roots, UNC paths, links and untrusted writable locations are rejected.

```powershell
$bundle = 'C:\SentinelAI-Pilot'
$trust = 'C:\SentinelAI-Trust\dev-pilot.public.pem'
$install = Join-Path $bundle 'installer\Install-SentinelAIPilot.ps1'
& $install -Component Core -BundleDirectory $bundle -PublicKeyPath $trust -KeyId dev-pilot -Environment development -Channel pilot
```

At the default paths and loopback port, open the published `SentinelAI.Desktop.exe` and follow [Desktop administrator setup](DESKTOP-AUTH.md) to create the first administrator. The native setup uses the trusted installed Core's one-shot command; it does not start or control a service. After initialization, register/start Core with the packaged service manager:

```powershell
$manage = Join-Path $bundle 'installer\Manage-SentinelAICoreService.ps1'
$serviceOptions = @{
    CodeDirectory = "$env:ProgramFiles\SentinelAI\Core"
    DataDirectory = "$env:ProgramData\SentinelAI\Core"
}
& $manage -Action Install @serviceOptions -BundleDirectory $bundle -PublicKeyPath $trust `
    -KeyId dev-pilot -Environment development -Channel pilot
& $manage -Action Start @serviceOptions
```

Sign in from the normal Desktop window. Native Devices, Alerts, Risk, Reports and Settings provide the supported workflow. See [browserless operation](DESKTOP-OPERATION.md) for reopening, duplicate activation and optional per-user tray/auto-start settings, which leave Core and Agent startup policies unchanged.

## Install and enroll Agent

In an elevated PowerShell terminal, while Core is running:

```powershell
& $install -Component Agent -BundleDirectory $bundle -PublicKeyPath $trust -KeyId dev-pilot -Environment development -Channel pilot
```

Enter the Core administrator credential in the secure prompt. The installer logs in locally and requests the existing ten-minute, one-use enrollment token. It writes that token to an ACL-restricted `pilot-enrollment-token` handoff file, creates the quoted Windows Service command with only `--config <nonsecret path>` and starts the service. Agent stores its credential using DPAPI under LocalService and removes the handoff after durable enrollment. The installer never prints passwords, tokens, bearer credentials or DPAPI payloads. Do not enable transcripts or debug tracing for credential handling.

The installer returns the enrolled endpoint ID. The nonsecret `endpoint-id` receipt is derived from validated enrollment state, so verification targets this exact endpoint rather than a possibly duplicated hostname. The service account stays LocalService across reinstall; changing it would make its current-user DPAPI state unusable. LocalService is shared with other Windows services; this pilot does not claim per-service isolation of that account.

## Verify the pilot

```powershell
$verify = Join-Path $bundle 'installer\Verify-SentinelAIPilot.ps1'
& $verify -CoreUrl http://127.0.0.1:5000 -AgentDataDirectory "$env:ProgramData\SentinelAI\Agent" -SinceUtc ([DateTimeOffset]::UtcNow.AddMinutes(-5))
Get-Service SentinelAIAgent
```

Supply the same administrator credential at the secure prompt. Verification requires Core health, a fresh authenticated heartbeat, fresh inventory and the exact endpoint in Devices. The existing pilot verifier also checks diagnostic dashboard assets for backward compatibility; using that dashboard is unnecessary for normal operation. Heartbeats normally arrive every 30 seconds; initial inventory is sent after enrollment. Open Desktop, sign in and confirm the endpoint in native **Devices**, including its observation time. Missing Windows telemetry is shown as unknown; an empty alert list/zero score does not establish endpoint safety.

To test a restart, capture the time, restart the service, then verify again:

```powershell
$since = [DateTimeOffset]::UtcNow
Restart-Service SentinelAIAgent
& $verify -CoreUrl http://127.0.0.1:5000 -AgentDataDirectory "$env:ProgramData\SentinelAI\Agent" -SinceUtc $since
```

## Uninstall or reinstall Agent

```powershell
& $install -Component UninstallAgent
```

Uninstall stops/deletes only a matching installer-owned `SentinelAIAgent` service. It preserves code, configuration, Core SQLite, installation ID, endpoint receipt and DPAPI enrollment state. No data purge or automatic endpoint deletion occurs. Reinstall with the same paths, account and exact signed package uses the existing enrollment; it does not consume another token. Existing services without a matching ownership receipt or changed code/configuration are refused. This console-pilot installer does not overwrite an older release. Transactional maintenance of owned Setup deployments is available through the [Setup lifecycle](SETUP.md#repair-upgrade-and-uninstall); it does not adopt or convert this separate console-pilot installation.

The separate [Core service workflow](CORE-SERVICE.md) provides managed startup/stop/restart and service-only removal. Closing Desktop leaves Core and Agent running. Remove retained files only as a separate operator decision after backups; this task provides no data-deletion command.

## Development and diagnostic console alternative

For explicit console diagnostics, use the existing launcher instead of the managed Core service:

```powershell
$start = Join-Path $bundle 'installer\Start-SentinelAICore.ps1'
$core = & $start
```

The launcher prompts securely for the first administrator and places bootstrap credentials only in the child Core environment. Core stores the password hash; credentials do not become arguments or persistent configuration. Leave the console open while testing. Stop only the console process you started, using its terminal or `Stop-Process -Id $core.ProcessId`, before registering a managed service.

Custom-path/port diagnostics may supply the same explicit loopback `-CoreUrl`, such as `http://127.0.0.1:5500`, during Core/Agent installation and verification. An occupied port is refused. Normal Desktop retains the fixed trusted default installation/origin. If console first-run setup was interrupted, `& $start -InitializeAdministrator` initializes an empty administrator state only; existing administrators are never replaced. Preserve the database during diagnosis.

The existing browser dashboard is a development/diagnostic compatibility surface only. An explicit diagnostic session may open the configured Core origin; remote access still requires separately provisioned HTTPS. Native Desktop needs neither that dashboard nor Node.js on the target machine.

## Acceptance and limitations

From the trusted checkout on a fresh elevated Windows 11 x64 test computer, use a bundle and separately provisioned public key:

```powershell
& .\tests\pilot\Windows.Acceptance.ps1 -BundleDirectory $bundle -PublicKeyPath $trust -KeyId dev-pilot -Environment development -Channel pilot
```

The automated acceptance script uses generated test credentials and isolated directories, exercises actual service registration/ACLs/enrollment/heartbeat/inventory and diagnostic dashboard compatibility, then restart and uninstall/reinstall with identity/state preservation. It retains test data for inspection and stops only its own test process/service. Do not run it on an existing `SentinelAIAgent` installation. Portable tests and console-host integration on Linux validate logic; they do not substitute for this Windows SCM/NTFS/DPAPI test. Windows execution must be recorded separately before declaring the deployment Definition of Done verified.

Known limitations: the cloud development environment is Linux; live Windows service/ACL/DPAPI acceptance is not claimed there. The full pilot Agent acceptance remains separate from the native Core service and Desktop authentication checks that pass in Windows CI. The pilot acceptance script uses console Core; native Core service validation is described in [the service guide](CORE-SERVICE.md). Both installer workflows support co-located loopback. LAN deployment requires separately provisioned trusted HTTPS, TLS 1.3, certificate pinning and network access from the existing Agent documentation; the installer does not generate certificates, open firewall ports or expose Core. Signing keys, production release hosting, Authenticode, automatic upgrades, state/account migration and data purge are outside this pilot task.

Installation failure preserves code and state. After an ownership receipt has been written, a service registration, start or enrollment failure can be retried with the same paths and signed package. An earlier filesystem or ACL failure can leave an incomplete directory without that receipt; the installer deliberately refuses to adopt it. Inspect retained files and permissions before recovery; do not delete data or weaken ownership checks.
