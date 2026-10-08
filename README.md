# SentinelAI

SentinelAI is a Windows-first, local-first security platform in development. It collects endpoint inventory and selected Windows configuration observations, evaluates deterministic security rules, and provides native incident review, risk prioritization and local reports.

The operator interface is **SentinelAI.Desktop**, a native .NET 10 WPF application for Windows x64. Core and Agent run independently of the window. Normal operation requires no browser; the existing dashboard remains available for development and diagnostics.

## Current project state

The current main branch includes the native Desktop workflows completed through **TASK-023**. Builds and native Windows CI have passed, including authentication, incident review, reports, duplicate-window activation and closing/reopening Desktop against the installed Core service.

Distribution is at the **development/pilot stage**: a self-contained Desktop directory and development-signed Core/Agent packages can be built from source. There is no published release download or Desktop installer. The pilot release is still a draft with no uploaded assets. Full fresh-machine Agent deployment acceptance remains pending; see [validation and limitations](#validation-and-limitations) and the [development status](.agent/STATUS.md).

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
| Update foundation | Signed manifest/package verification, local staging and a transactional installation/rollback API. Automatic download, scheduling and integration into pilot upgrades remain unimplemented. |

**Overview remains a placeholder.** Current information is available in Devices, Alerts, Risk, Reports and Settings. Tray, notifications and Desktop auto-start default off. Cloud AI consent also defaults off and is cleared on sign-out or close.

## Architecture

- **Core** (`core/`) owns the local ASP.NET Core API, administrator authentication, SQLite state, rule evaluation, risk scoring, incidents and reporting. It supports console development hosting and the `SentinelAICore` Windows Service.
- **Agent** (`agent/`) collects bounded Windows inventory/configuration and sends authenticated heartbeats and inventory. The pilot installs `SentinelAIAgent` under LocalService and protects its enrollment credential with Windows DPAPI.
- **Desktop** (`desktop/`) is the native operator workspace. Closing it clears its in-memory authentication session and exits the GUI; Core and Agent continue. Reopening requires a fresh sign-in. Desktop does not start, stop or configure either service.
- **Optional services** (`cloud/`) contain a separate development License API and AI Gateway. Core keeps their configured destinations and credentials; provider keys stay in the gateway. AI receives minimized evidence and does not determine detections or risk scores.

The supported pilot co-locates Core, Agent and Desktop on Windows 11 x64. Desktop connects to the trusted local installation at `http://127.0.0.1:5000`. Remote Agent connections require separately provisioned trusted HTTPS, TLS 1.3 and certificate pinning. See [architecture](docs/ARCHITECTURE.md), [Core service operation](docs/CORE-SERVICE.md) and [AI privacy/configuration](docs/AI.md).

## Run the Windows pilot

Use a fresh development/test machine and follow the [pilot installation guide](docs/PILOT.md) for the exact commands and trust inputs:

1. Build the Core/Agent development bundle and separately provide its trusted public verification key.
2. Install Core into the protected default directories using the elevated pilot installer.
3. Publish Desktop from the same checkout:

   ```sh
   ./scripts/publish-desktop-windows.sh
   ```

4. Copy the complete `artifacts/desktop/win-x64` directory to Windows and open `SentinelAI.Desktop.exe`. Create the first administrator through [native setup](docs/DESKTOP-AUTH.md), then register/start Core using the [service workflow](docs/CORE-SERVICE.md).
5. Install and enroll Agent through the pilot installer, sign in to Desktop and verify the exact endpoint and observation times in Devices.

Published applications include their .NET runtime. The target machine needs no SDK, Node.js or browser; installation scripts require Windows PowerShell 5.1 or PowerShell 7. Desktop is published separately and is not installed by the Core/Agent pilot bundle.

AI and license renewal require operator-provided service configuration and credentials. Without a configured provider or entitlement, AI displays a safe unavailable/disabled state while local workflows remain available. Enable **Allow cloud AI requests for this session** in Settings before explicitly requesting an explanation. See [native AI/licensing](docs/DESKTOP-AI-LICENSING.md) and [licensing configuration](docs/LICENSING.md).

## Build and test from source

Build prerequisites are the **.NET 10 SDK**, **Bash** and **Node.js 20 or newer**. Install **PowerShell 7 (`pwsh`)** to run the portable pilot/service tests; `scripts/test.sh` skips those suites when it is absent.

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores/builds the solution and diagnostic dashboard. The test script runs Core/Agent, rules, scoring, licensing, AI, update, Desktop and dashboard regressions, plus the PowerShell suites when available. Building on Linux cross-compiles Windows projects; native WPF and Windows service acceptance execute on Windows.

```sh
./scripts/publish-desktop-windows.sh
./scripts/publish-agent-windows.sh
```

These commands produce the self-contained Desktop directory and Agent executable under `artifacts/`. Core/Agent bundle preparation is documented in the [pilot guide](docs/PILOT.md). Native WPF/GUI test commands and manual DPI checks are in [desktop/README.md](desktop/README.md).

Console Core and the same-origin browser dashboard remain development/diagnostic options. The [console workflow](docs/PILOT.md#development-and-diagnostic-console-alternative) explains administrator bootstrap. The installed Desktop uses its fixed trusted local Core destination; it has no destination or credential editor.

## Validation and limitations

The last completed implementation, TASK-023, passed the full build/regression scripts with **zero .NET warnings/errors**, **2,814 Desktop assertions**, **63 dashboard tests** and all eight push/PR CI checks. Windows CI exercised actual WPF controls, published Desktop and signed installed Core, including restart/reconnect, report saving and independent service lifetime. These are recorded implementation results; see [STATUS](.agent/STATUS.md) for exact commits, CI links and acceptance details, or [GitHub Actions](https://github.com/trolomaniak/SentinelAI/actions/workflows/ci.yml) for later runs.

Current limits:

- Detection covers the documented configuration rules. Malware scanning, live antivirus health, patch compliance and automatic remediation are not implemented. An empty alert list or zero risk score does not prove security.
- Inventory can be stale. Core does not retain complete inventory/heartbeat history or historical risk scores; reports distinguish current risk from retained incident activity.
- The full fresh Windows Agent enrollment/DPAPI/heartbeat/inventory/uninstall-reinstall acceptance remains unexecuted. Existing Windows Agent tests and service smoke checks have passed; they do not establish that full deployment scenario.
- Interactive UAC approval and physical multi-monitor DPI checks remain manual. Tray delivery and auto-start also depend on Windows shell/startup policy.
- Pilot packages use development manifest signatures. Authenticode signing, production trust provisioning, a Desktop installer, automatic upgrades and state/account migrations remain outstanding.
- Billing and enforcement of the signed endpoint limit are not implemented.
- Gateway/provider integration tests use synthetic responses and development credentials. Live model-provider operation requires separate operator configuration.

## Documentation

- [Development status and verification](.agent/STATUS.md) · [Architectural decisions](.agent/DECISIONS.md)
- [Pilot installation](docs/PILOT.md) · [Core Windows Service](docs/CORE-SERVICE.md) · [Desktop setup/sign-in](docs/DESKTOP-AUTH.md)
- [Desktop operation, tray and auto-start](docs/DESKTOP-OPERATION.md) · [Devices](docs/DESKTOP-DEVICES.md) · [Alerts](docs/DESKTOP-ALERTS.md)
- [Native Risk/Reports](docs/DESKTOP-RISK-REPORTS.md) · [Scoring policy](scoring/README.md) · [Rule catalog](rules/README.md) · [Report semantics](docs/REPORTING.md)
- [Native AI/licensing](docs/DESKTOP-AI-LICENSING.md) · [AI Gateway/configuration](docs/AI.md) · [Licensing](docs/LICENSING.md) · [Development issuer](cloud/license-api/README.md)
- [Signed update verification and rollback](docs/UPDATES.md) · [Desktop structure and Windows validation](desktop/README.md)
