# SentinelAI

SentinelAI is a Windows-first, local-first security platform in development. It collects endpoint inventory and selected Windows configuration observations, evaluates deterministic security rules, and provides native incident review, risk prioritization and local reports.

The operator interface is **SentinelAI.Desktop**, a native .NET 10 WPF application for Windows x64. Core and Agent run independently of the window. Normal operation requires no browser; the existing dashboard remains available for development and diagnostics.

## Current project state

The current implementation includes native Desktop workflows and a single **`SentinelAI-Setup.exe`**. TASK-025 adds detection of owned installations, version-aware repair/upgrade, signed whole-deployment replacement with rollback, explicit recovery and uninstall with data retained by default. Its native Windows lifecycle acceptance is pending; TASK-024's fresh-install services/ACLs, Agent enrollment/DPAPI/restart and Desktop sign-in acceptance already passed. See [development status](.agent/STATUS.md) for exact results.

Distribution is at the **development/pilot stage**: Setup, a self-contained Desktop directory and development-signed packages can be built from source. There is no published release download; the earlier pilot release remains a draft with no uploaded assets. See [validation and limitations](#validation-and-limitations).

## Implemented functionality

| Area | Current behavior |
| --- | --- |
| Devices and telemetry | Enrolled endpoint list/detail, heartbeat connectivity, inventory timestamps, OS/build, CPU, RAM, disks and selected Windows configuration. Unavailable observations remain Unknown. |
| Security rules | 13 deterministic configuration rules covering firewall profiles, UAC, RDP, SMB, automatic logon, LSA protection and update policy. Findings describe the observed configuration. |
| Alerts and incidents | Stored detections, typed evidence, observation/history details and versioned Open / Investigating / Resolved / Accepted decisions. Conflicting edits require review of the current version. |
| Risk | Local deterministic organization/endpoint scores with decimal contributions, correlation, policy, coverage and freshness explanations. |
| Reports | Local HTML generation for an inclusive UTC date range and explicit saving through a native Windows picker. Reports work offline and in Safe Mode; historical score trends are unavailable. |
| Licensing | Signed seven-day leases, FULL / GRACE / SAFE_MODE / RECOVERING states, public capabilities and explicit manual renewal. Safe Mode preserves local monitoring, incident access and reporting. |
| Assistive AI | Explicit explanations for supported selected alerts. Requests require session consent, Core permission and a signed `cloud_ai` entitlement. Suggestions perform no endpoint actions. |
| Desktop operation | One normal instance per Windows user/session, restoration on repeated launch, read-only service status, optional tray notifications and independent per-user Desktop auto-start. |
| Windows setup | One elevated EXE installs the local deployment and offers owned-installation repair, upgrade, recovery and uninstall. Uninstall keeps protected data unless its removal is explicitly confirmed with DELETE. |
| Updates | Explicit Setup maintenance uses signed whole-deployment verification and the existing transactional replacement/rollback API. Automatic download and scheduling remain unimplemented. |

**Overview remains a placeholder.** Current information is available in Devices, Alerts, Risk, Reports and Settings. Tray, notifications and Desktop auto-start default off. Cloud AI consent also defaults off and is cleared on sign-out or close.

## Architecture

- **Core** (`core/`) owns the local ASP.NET Core API, administrator authentication, SQLite state, rule evaluation, risk scoring, incidents and reporting. It supports console development hosting and the `SentinelAICore` Windows Service.
- **Agent** (`agent/`) collects bounded Windows inventory/configuration and sends authenticated heartbeats and inventory. The pilot installs `SentinelAIAgent` under LocalService and protects its enrollment credential with Windows DPAPI.
- **Desktop** (`desktop/`) is the native operator workspace. Closing it clears its in-memory authentication session and exits the GUI; Core and Agent continue. Reopening requires a fresh sign-in. Desktop does not start, stop or configure either service.
- **Optional services** (`cloud/`) contain a separate development License API and AI Gateway. Core keeps their configured destinations and credentials; provider keys stay in the gateway. AI receives minimized evidence and does not determine detections or risk scores.

The supported pilot co-locates Core, Agent and Desktop on Windows 11 x64. Desktop connects to the trusted local installation at `http://127.0.0.1:5000`. Remote Agent connections require separately provisioned trusted HTTPS, TLS 1.3 and certificate pinning. See [architecture](docs/ARCHITECTURE.md), [Core service operation](docs/CORE-SERVICE.md) and [AI privacy/configuration](docs/AI.md).

## Run the Windows pilot

Use a fresh Windows 11 x64 development/test machine and follow the [single-EXE setup guide](docs/SETUP.md):

1. Build `SentinelAI-Setup.exe` using separate development signing/trust files, or obtain the artifact from a successful `setup-windows` CI job for the desired commit. Transfer it through a trusted channel.
2. Run Setup, approve elevation and create the initial local administrator in its native window.
3. Wait for installation progress to complete. Setup starts Core and enrolls/starts Agent without manual ZIP extraction.
4. Open Desktop from Setup or **Start → SentinelAI**, sign in with the account you created, and verify the exact endpoint and fresh observation times in Devices.

Published applications include their .NET runtime. The target machine needs no SDK, Node.js or browser; Setup uses the stock Windows PowerShell. The [manual pilot installation guide](docs/PILOT.md) remains available for development and diagnostics, including separate Desktop publishing and [Core service operation](docs/CORE-SERVICE.md).

For an existing owned Setup installation, close Desktop and follow the [maintenance guide](docs/SETUP.md#repair-upgrade-and-uninstall). Repair/upgrade require the matching installed trust root/channel and preserve security history, configuration, identity, enrollment and licensing state. Setup never treats retained data as a fresh deployment.

AI and license renewal require operator-provided service configuration and credentials. Without a configured provider or entitlement, AI displays a safe unavailable/disabled state while local workflows remain available. Enable **Allow cloud AI requests for this session** in Settings before explicitly requesting an explanation. See [native AI/licensing](docs/DESKTOP-AI-LICENSING.md) and [licensing configuration](docs/LICENSING.md).

## Build and test from source

Build prerequisites are the **.NET 10 SDK**, **Bash** and **Node.js 20 or newer**. Install **PowerShell 7 (`pwsh`)** to run the portable pilot/service tests; `scripts/test.sh` skips those suites when it is absent.

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores/builds the solution and diagnostic dashboard. The test script runs Core/Agent, rules, scoring, licensing, AI, update, Desktop, Setup and dashboard regressions, plus the PowerShell suites when available. Building on Linux cross-compiles Windows projects; native WPF and Windows service acceptance execute on Windows. Publishing the final Setup EXE requires Windows and Visual Studio C++ build tools with the Windows SDK; see [Setup build instructions](docs/SETUP.md#build-the-development-artifact).

```sh
./scripts/publish-desktop-windows.sh
./scripts/publish-agent-windows.sh
```

These commands produce the self-contained Desktop directory and Agent executable under `artifacts/`. Core/Agent bundle preparation is documented in the [pilot guide](docs/PILOT.md). Native WPF/GUI test commands and manual DPI checks are in [desktop/README.md](desktop/README.md).

Console Core and the same-origin browser dashboard remain development/diagnostic options. The [console workflow](docs/PILOT.md#development-and-diagnostic-console-alternative) explains administrator bootstrap. The installed Desktop uses its fixed trusted local Core destination; it has no destination or credential editor.

## Validation and limitations

TASK-024 passed the full build/regression scripts with **zero .NET warnings/errors**, **322 Setup assertions**, **2,814 Desktop assertions** and **63 dashboard tests**. Windows CI built and executed the actual Setup EXE on a fresh runner, verified services/ACLs/Agent state and telemetry, authenticated the installed native Desktop and refused a repeated installation. Existing native WPF, service and Desktop regressions remain in CI. See [STATUS](.agent/STATUS.md) for exact commits and results, or [GitHub Actions](https://github.com/trolomaniak/SentinelAI/actions/workflows/ci.yml) for later runs.

Those are the recorded first-install results. TASK-025 changes repeated launch to an explicit maintenance workflow; its complete Windows lifecycle acceptance is pending.

Current limits:

- Detection covers the documented configuration rules. Malware scanning, live antivirus health, patch compliance and automatic remediation are not implemented. An empty alert list or zero risk score does not prove security.
- Inventory can be stale. Core does not retain complete inventory/heartbeat history or historical risk scores; reports distinguish current risk from retained incident activity.
- Setup's fresh Agent enrollment/DPAPI/heartbeat/inventory/restart acceptance passed. The original TASK-015 console pilot's full uninstall/reinstall scenario remains unexecuted. Setup lifecycle acceptance is tracked separately.
- Interactive UAC approval and physical multi-monitor DPI checks remain manual. Tray delivery and auto-start also depend on Windows shell/startup policy.
- Pilot packages use development manifest signatures. Authenticode signing, production trust provisioning, automatic upgrades and state/account migrations remain outstanding. Unverified ownership is refused; failed transaction recovery requires explicit action.
- Billing and enforcement of the signed endpoint limit are not implemented.
- Gateway/provider integration tests use synthetic responses and development credentials. Live model-provider operation requires separate operator configuration.

## Documentation

- [Development status and verification](.agent/STATUS.md) · [Architectural decisions](.agent/DECISIONS.md)
- [Single-EXE Windows setup](docs/SETUP.md) · [Manual pilot installation](docs/PILOT.md) · [Core Windows Service](docs/CORE-SERVICE.md) · [Desktop setup/sign-in](docs/DESKTOP-AUTH.md)
- [Desktop operation, tray and auto-start](docs/DESKTOP-OPERATION.md) · [Devices](docs/DESKTOP-DEVICES.md) · [Alerts](docs/DESKTOP-ALERTS.md)
- [Native Risk/Reports](docs/DESKTOP-RISK-REPORTS.md) · [Scoring policy](scoring/README.md) · [Rule catalog](rules/README.md) · [Report semantics](docs/REPORTING.md)
- [Native AI/licensing](docs/DESKTOP-AI-LICENSING.md) · [AI Gateway/configuration](docs/AI.md) · [Licensing](docs/LICENSING.md) · [Development issuer](cloud/license-api/README.md)
- [Signed update verification and rollback](docs/UPDATES.md) · [Desktop structure and Windows validation](desktop/README.md)
