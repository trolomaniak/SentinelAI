# Native Desktop operation

SentinelAI Desktop is the supported Windows production interface. Normal administrator setup, sign-in, endpoint review, incident review and status changes, deterministic Risk, report generation/saving, licensing and optional assistive AI use native controls. No browser, embedded web view or dashboard process is needed. Overview remains a placeholder; use the dedicated workspaces for current information.

## Open and reopen

Publish using `./scripts/publish-desktop-windows.sh`, copy the complete `artifacts/desktop/win-x64` directory to the Windows x64 machine, and open `SentinelAI.Desktop.exe`. The application includes its runtime; keep its accompanying files together. This remains a development/pilot artifact without a new installer, shortcut installer or Authenticode release.

For an initialized installation, start the existing [Core service](CORE-SERVICE.md) and installed Agent through their existing service configuration. Open Desktop and sign in with the Core administrator. Desktop's fixed supported origin is `http://127.0.0.1:5000` and its trusted installation uses the existing default paths. See [first-run setup and authentication](DESKTOP-AUTH.md) for the separate initial-administrator setup window and UAC boundary.

Normal Desktop activation is limited to one application for the current Windows user and interactive session. Opening the executable again requests **Open SentinelAI** on that existing application, restores its minimized or hidden window, and exits the duplicate process successfully. Activation carries only a bounded literal activation message; it cannot carry credentials, URLs, commands or navigation content. A separate initial-administrator setup process retains its existing setup-only boundary.

Closing the window fully exits Desktop, cancels pending UI operations and erases its in-memory credentials/session/data. Core and Agent continue independently. Reopening Desktop reads the same local installation and asks for explicit sign-in; it never restores a bearer or replays a stored password. Closing Desktop is not a protection or service-stop action.

## Optional local operation settings

Desktop's tray integration and Windows sign-in auto-start are optional and off by default. In native **Settings**, expand **Desktop startup and notifications**. Use **Show SentinelAI in the notification area**, **Notify when a local protection service stops**, and **Open SentinelAI when I sign in to Windows**; all three default off. Notifications require tray integration, and disabling tray also disables notifications. These are local UI preferences, independent of licensing and the session-only cloud AI consent setting.

With tray integration enabled, the tray menu provides **Open SentinelAI** and **Exit Desktop**. Opening restores the native window. Exiting closes Desktop; neither action starts, stops, restarts or reconfigures Core or Agent. The ordinary window close still fully exits the application.

Desktop auto-start uses the `SentinelAI.Desktop` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with the exact quoted current Desktop executable. That Run command, including quotes, must fit Windows' 260-character limit. Nonsecret tray/notification preferences use the `Integration` DWORD under `HKCU\Software\SentinelAI\Desktop`. These are current-user settings only; they store no password, bearer or account identity. Desktop auto-start registers only the current user's normal Desktop executable for Windows sign-in. It does not enable automatic authentication, run setup as administrator or modify either service's startup policy. Turning it off removes only Desktop's own matching entry; foreign or changed registrations are preserved and produce a fixed settings error. **Refresh Desktop settings** rereads the current local registration without overwriting it. Service startup remains owned by the existing installation/service workflow. A moved or removed executable requires the operator to resolve its old registration before enabling the new location.

Settings also exposes read-only local Core/Agent service status. Both the connection strip and Settings show Core/Agent service observations: Unknown, Not installed, Starting, Running, Stopping or Stopped. A service's SCM state and Core's API health are separate observations; missing, inaccessible or failed reads are shown explicitly. These observations do not establish endpoint health or effective security. Desktop offers no service-control buttons.

When explicitly enabled, tray notifications report an observed local Core/Agent transition from Running to Stopped after the initial snapshot. At most one notification is requested per 30 seconds, across both services, and an initial stopped/missing/unknown service does not trigger a notification. They contain no endpoint names, incident evidence, administrator identity, credentials, license bodies or cloud output. They open the existing native window only; they do not execute commands or open external destinations. No notification collector, external integration or additional monitoring service is introduced. Core and Agent remain responsible for protection while Desktop is closed.

## Native workspaces

- [Devices](DESKTOP-DEVICES.md) shows enrolled endpoint health and available inventory with explicit missing observations.
- [Alerts](DESKTOP-ALERTS.md) shows retained incidents and Core-authoritative, versioned operator status changes.
- [Risk and Reports](DESKTOP-RISK-REPORTS.md) show deterministic priorities and generate/save the local HTML attachment, including in Safe Mode.
- [AI and licensing](DESKTOP-AI-LICENSING.md) show Core's current permission snapshot and provide explicit manual actions. Cloud AI requires both session consent and Core permission; failures leave local workspaces available.

Saving a report completes inside Desktop using the native destination picker. Opening, printing or converting that exported HTML with an operator-selected offline viewer is optional document handling outside normal SentinelAI operation. Desktop never automatically opens it; browser printing/PDF is an optional compatibility capability rather than a required product step.

## Development and diagnostic compatibility

Core continues to serve the existing browser dashboard and unchanged HTTP contracts for development and diagnostics. The dashboard is not the supported production user interface. Its Node.js build/tests and assets remain in the repository to preserve compatibility; Node.js and a browser are not required to run the published Desktop. Console Core startup and custom-path/port workflows remain development/pilot diagnostic options. Remote dashboard access still requires separately configured HTTPS and the existing authentication rules.

## Verification

Run `./scripts/build.sh` and `./scripts/test.sh` for the full build and portable regression suites. The native Windows test runner verifies operation settings, UI bindings, shutdown and activation adapters. Actual published application behavior requires Windows:

```powershell
.\tests\desktop\Authentication.Acceptance.ps1 -BundleDirectory 'C:\SentinelAI-Pilot' `
  -PublicKeyPath 'C:\SentinelAI-Trust\dev-pilot.public.pem' -KeyId dev-pilot `
  -Environment development -Channel pilot `
  -ExecutablePath .\artifacts\desktop\win-x64\SentinelAI.Desktop.exe `
  -VerifyDevices -VerifyAlerts -VerifyRiskReports -VerifyAiLicenseSettings -VerifyBrowserless
```

Use a fresh elevated interactive Windows x64 machine with absent default Core installation/service, as required by the existing authentication fixture. After the native workspace checks, the browserless fixture launches a duplicate executable, requires a successful bounded duplicate exit and exactly one original UI process, and checks restoration of its minimized window. It then closes and reopens Desktop without another login, verifies signed-out reconnection to the initialized Core, and checks unchanged Core PID/health plus unchanged Agent service state/PID if one exists. No browser is launched and no registry entry is modified by this fixture. Record actual Windows CI results in [development status](../.agent/STATUS.md); Linux cross-compilation does not establish these checks.

The full fresh Windows Agent enrollment/DPAPI/uninstall-reinstall pilot acceptance, an interactive UAC prompt and physical multi-monitor scaling retain their separately documented validation limits. This task adds neither a single-file setup installer nor an installation/upgrade migration.
