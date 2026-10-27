# SentinelAI

SentinelAI is a Windows-first, local-first security platform in development. It collects endpoint inventory and selected Windows configuration observations, evaluates deterministic security rules, and provides native incident review, risk prioritization and local reports.

The operator interface is **SentinelAI.Desktop**, a native .NET 10 WPF application for Windows x64. Core and Agent run independently of the window. Normal operation requires no browser, and Core serves no browser interface.

## Current project state

The current implementation includes native Desktop workflows and a single **`SentinelAI-Setup.exe`**. TASK-025 adds detection of owned installations, version-aware repair/upgrade, signed whole-deployment replacement with rollback, explicit recovery and uninstall with data retained by default. Actual Windows acceptance passed fresh installation, upgrade, health-failed rollback, damaged-file repair, retained-data uninstall/restore and explicitly confirmed data removal. See [development status](.agent/STATUS.md) for exact results.

Distribution is at the **development/pilot stage**: the two installers, `SentinelAI-Setup.exe` and `SentinelAI-Agent-Setup.exe`, are the only packages and can be built from source with development-signed payloads. There is no published release download; the earlier pilot release remains a draft with no uploaded assets. See [validation and limitations](#validation-and-limitations).

## Implemented functionality

| Area | Current behavior |
| --- | --- |
| Devices and telemetry | Enrolled endpoint list/detail, heartbeat connectivity, inventory timestamps, OS/build, CPU, RAM, disks and selected Windows configuration, plus hourly endpoint security telemetry: BitLocker, antivirus and Defender health, local Administrators members (SIDs only), Windows Update policy and results, pending restarts, security service states and installed application counts ([endpoint telemetry](docs/ENDPOINT-TELEMETRY.md)). Unavailable observations remain Unknown with their reason. |
| Security rules | 13 deterministic configuration rules covering firewall profiles, UAC, RDP, SMB, automatic logon, LSA protection and update policy, whose findings describe the observed configuration, 4 endpoint telemetry rules (antivirus reported at risk, system volume without BitLocker protection, firewall or event log service not running), and 12 deterministic runtime event rules (`SA-EVT-*`) over collected Windows security events, such as failed-logon bursts, Defender detections, disabled protection, cleared logs and new services, drivers or scheduled tasks ([runtime event detections](docs/EVENT-RULES.md)). |
| Alerts and incidents | Stored detections, typed evidence, observation/history details and versioned Open / Investigating / Resolved / Accepted decisions. Conflicting edits require review of the current version. |
| Risk | Local deterministic organization/endpoint scores with decimal contributions, correlation, policy, coverage and freshness explanations. |
| Reports | Local HTML generation for an inclusive UTC date range and explicit saving through a native Windows picker. Reports work offline and in Safe Mode; historical score trends are unavailable. |
| Licensing | Signed seven-day leases, FULL / GRACE / SAFE_MODE / RECOVERING states, public capabilities and explicit manual renewal. Safe Mode preserves local monitoring, incident access and reporting. |
| Assistive AI | Explicit explanations for supported selected alerts. Requests require session consent, Core permission and a signed `cloud_ai` entitlement. Suggestions perform no endpoint actions. |
| Desktop operation | One normal instance per Windows user/session, restoration on repeated launch, read-only service status, optional tray notifications and independent per-user Desktop auto-start. |
| Windows setup | One elevated EXE installs the local deployment and offers owned-installation repair, upgrade, recovery and uninstall. Uninstall keeps protected data unless its removal is explicitly confirmed with DELETE. |
| Updates | Explicit Setup maintenance uses signed whole-deployment verification and the existing transactional replacement/rollback API. Agents installed by Agent Setup update automatically from Core: the Agent downloads the signed Agent package Core carries and a SYSTEM task verifies and installs it with rollback ([automatic Agent updates](docs/UPDATES.md#automatic-agent-updates-from-core-mvp-7)). Optionally (off by default) Core downloads a newer signed Setup from the owner's built-in HTTPS server and a nightly SYSTEM task installs it ([central update](docs/UPDATES.md#optional-central-update-from-the-providers-server-mvp-7-part-2)). |

**Overview remains a placeholder.** Current information is available in Devices, Alerts, Risk, Reports and Settings. Tray, notifications and Desktop auto-start default off. Cloud AI consent also defaults off and is cleared on sign-out or close.

## Architecture

- **Core** (`core/`) owns the local ASP.NET Core API, administrator authentication, SQLite state, rule evaluation, risk scoring, incidents and reporting. It supports console development hosting and the `SentinelAICore` Windows Service.
- **Agent** (`agent/`) collects bounded Windows inventory/configuration and sends authenticated heartbeats and inventory. It watches the monitored security settings and re-sends inventory within seconds of a change; the six-hour inventory remains reconciliation. It also continuously collects a fixed allowlist of minimized Windows security events and reports overwritten, cleared or dropped records as explicit gaps; Core stores both and evaluates newly stored events with deterministic runtime rules. The pilot installs `SentinelAIAgent` under LocalService and protects its enrollment credential with Windows DPAPI.
- **Desktop** (`desktop/`) is the native operator workspace. Closing it clears its in-memory authentication session and exits the GUI; Core and Agent continue. Reopening requires a fresh sign-in. Desktop does not start, stop or configure either service.
- **Optional services** (`cloud/`) contain a separate development License API and AI Gateway. Core keeps their configured destinations and credentials; provider keys stay in the gateway. AI receives minimized evidence and does not determine detections or risk scores.

The pilot installs one central computer per company (Windows 10 22H2 or Windows 11 x64) with Core, Desktop, Updater and its own Agent; Agents on the other computers of the local network report to it over HTTPS on port 5443 and trust Core only by its certificate's SHA-256 fingerprint ([central computer](docs/SETUP.md#central-computer-and-the-local-network)). Desktop connects to the trusted local installation at `http://127.0.0.1:5000`. See [architecture](docs/ARCHITECTURE.md), [Setup](docs/SETUP.md) and [AI privacy/configuration](docs/AI.md).

## Run the Windows pilot

Use a fresh Windows 11 x64 development/test machine and follow the [single-EXE setup guide](docs/SETUP.md):

1. Build `SentinelAI-Setup.exe` using separate development signing/trust files, or obtain the artifact from a successful `setup-windows` CI job for the desired commit. Transfer it through a trusted channel.
2. Run Setup, approve elevation and create the initial local administrator in its native window.
3. Wait for installation progress to complete. Setup starts Core and enrolls/starts Agent without manual ZIP extraction.
4. Open Desktop from Setup or **Start → SentinelAI**, sign in with the account you created, and verify the exact endpoint and fresh observation times in Devices.

Published applications include their .NET runtime. The target machine needs no SDK or browser; Setup uses the stock Windows PowerShell.

For an existing owned Setup installation, close Desktop and follow the [maintenance guide](docs/SETUP.md#repair-upgrade-and-uninstall). Repair/upgrade require the matching installed trust root/channel and preserve security history, configuration, identity, enrollment and licensing state. Setup never treats retained data as a fresh deployment.

AI and license renewal require operator-provided service configuration and credentials. Without a configured provider or entitlement, AI displays a safe unavailable/disabled state while local workflows remain available. Enable **Allow cloud AI requests for this session** in Settings before explicitly requesting an explanation. See [native AI/licensing](docs/DESKTOP-AI-LICENSING.md) and [licensing configuration](docs/LICENSING.md).

## Build and test from source

Build prerequisites are the **.NET 10 SDK** and **Bash**. Install **PowerShell 7 (`pwsh`)** to run the portable installer and service tests; `scripts/test.sh` skips those suites when it is absent.

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the solution. The test script runs Core/Agent, rules, scoring, licensing, AI, update, Desktop and Setup regressions, plus the PowerShell suites when available. Building on Linux cross-compiles Windows projects; native WPF and Windows service acceptance execute on Windows. Publishing the final Setup EXE requires Windows and Visual Studio C++ build tools with the Windows SDK; see [Setup build instructions](docs/SETUP.md#build-the-development-artifact).

A pilot release (both installers, the four pilot documents and checksums) is built on Windows with `scripts/publish-pilot-release-windows.ps1`; see the [pilot test checklist](docs/pilot/PILOT-TEST-CHECKLIST.md). Native WPF/GUI test commands and manual DPI checks are in [desktop/README.md](desktop/README.md). The installed Desktop uses its fixed trusted local Core destination; it has no destination or credential editor.

## Validation and limitations

TASK-024 passed the full build/regression scripts with **zero .NET warnings/errors**, **322 Setup assertions**, **2,814 Desktop assertions** and **63 dashboard tests**. Windows CI built and executed the actual Setup EXE on a fresh runner, verified services/ACLs/Agent state and telemetry, authenticated the installed native Desktop and refused a repeated installation. Existing native WPF, service and Desktop regressions remain in CI. See [STATUS](.agent/STATUS.md) for exact commits and results, or [GitHub Actions](https://github.com/trolomaniak/SentinelAI/actions/workflows/ci.yml) for later runs.

TASK-025 passed all twelve push/PR checks: full builds/regressions, **436 Setup assertions**, **903 update assertions**, portable PowerShell worker/lifecycle checks and complete native Windows lifecycle acceptance. Both lifecycle runs verified upgrade, a signed unhealthy candidate's working rollback, damaged-file repair, retained-data uninstall/restoration and confirmed removal while preserving identity, configuration, DPAPI enrollment, license state and security history.

Current limits:

- Detection covers the documented configuration, endpoint telemetry and runtime event rules. Malware scanning, patch compliance, vulnerability matching and automatic remediation are not implemented. An empty alert list or zero risk score does not prove security.
- On the Windows Server CI runner the installed LocalService Agent collects every endpoint telemetry source except Security Center antivirus health, which servers do not provide. Client editions are not yet measured; a source an endpoint refuses is reported as access denied and is never treated as safe.
- Monitored security settings are delivered within seconds of a reachable change, but other inventory can be stale, and posture is current state rather than an event history. Core does not retain complete inventory/heartbeat history or historical risk scores; reports distinguish current risk from retained incident activity.
- Selected Windows security events are evaluated by twelve deterministic runtime rules whose alerts appear with the other alerts and in Risk; raw events are not shown in Desktop, reports or AI. Setup gives the installed Agent's own service SID read access to the Security channel and enables the auditing that scheduled task creation needs; detections work on Windows in any display language.
- Setup's fresh Agent enrollment/DPAPI/heartbeat/inventory/restart and complete maintenance lifecycle acceptance passed.
- Interactive UAC approval and physical multi-monitor DPI checks remain manual. Tray delivery and auto-start also depend on Windows shell/startup policy.
- Pilot packages use development manifest signatures. Authenticode signing, production trust provisioning, automatic upgrades and state/account migrations remain outstanding. Unverified ownership is refused; failed transaction recovery requires explicit action.
- Billing and enforcement of the signed endpoint limit are not implemented.
- Gateway/provider integration tests use synthetic responses and development credentials. Live model-provider operation requires separate operator configuration.

## Documentation

- **Pilot documents for companies** (Polish and English): [SentinelAI dla firm](docs/pilot/SentinelAI-dla-firm.pl.md) · [SentinelAI for business](docs/pilot/SentinelAI-for-business.en.md) · [Przewodnik IT](docs/pilot/SentinelAI-przewodnik-IT.pl.md) · [IT guide](docs/pilot/SentinelAI-IT-guide.en.md) · [Pilot scope](docs/MVP.md) · [Pilot test checklist](docs/pilot/PILOT-TEST-CHECKLIST.md)

- [Development status and verification](.agent/STATUS.md) · [Architectural decisions](.agent/DECISIONS.md)
- [Single-EXE Windows setup](docs/SETUP.md) · [Desktop setup/sign-in](docs/DESKTOP-AUTH.md)
- [Desktop operation, tray and auto-start](docs/DESKTOP-OPERATION.md) · [Devices](docs/DESKTOP-DEVICES.md) · [Alerts](docs/DESKTOP-ALERTS.md)
- [Native Risk/Reports](docs/DESKTOP-RISK-REPORTS.md) · [Scoring policy](scoring/README.md) · [Rule catalog](rules/README.md) · [Posture monitoring](docs/POSTURE-MONITOR.md) · [Security event collection](docs/SECURITY-EVENTS.md) · [Endpoint telemetry](docs/ENDPOINT-TELEMETRY.md) · [Report semantics](docs/REPORTING.md)
- [Native AI/licensing](docs/DESKTOP-AI-LICENSING.md) · [AI Gateway/configuration](docs/AI.md) · [Licensing](docs/LICENSING.md) · [Development issuer](cloud/license-api/README.md)
- [Signed update verification and rollback](docs/UPDATES.md) · [Desktop structure and Windows validation](desktop/README.md)
