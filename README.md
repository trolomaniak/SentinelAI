# SentinelAI

**Windows-first, local-first cybersecurity monitoring and risk management.**

SentinelAI is a security platform that monitors Windows endpoints, detects configuration vulnerabilities, and helps security teams prioritize risk — all running locally on your infrastructure with optional cloud-assisted analysis.

## What it does

- **Monitor endpoints** — Automated collection of Windows configuration, security settings, and system inventory
- **Detect vulnerabilities** — 13 deterministic security rules covering firewall, UAC, RDP, SMB, LSA protection and more
- **Assess risk** — Local scoring engine that prioritizes endpoints by security posture with detailed explanations
- **Track incidents** — Alert management with evidence, history, and status tracking (Open/Investigating/Resolved/Accepted)
- **Generate reports** — HTML security reports for date ranges, working offline without external dependencies
- **Assistive AI** — Optional cloud-based explanations for alerts (requires explicit consent and configuration)

## Architecture

SentinelAI consists of three main components:

- **Core** — Central API server, rule engine, risk scoring, and data storage (ASP.NET Core + SQLite)
- **Agent** — Lightweight Windows service that collects inventory and security configuration from endpoints
- **Desktop** — Native Windows application (WPF) for viewing devices, alerts, risk scores and reports

All components run on your infrastructure. The Core server evaluates security rules locally. Agent data never leaves your network unless you explicitly configure optional cloud AI features.

## Current status

**Development/Pilot stage** — The platform is functional and can be deployed for testing and evaluation. Native Windows acceptance tests pass for installation, service management, and all core workflows.

### What's implemented

✅ Native Windows installer (`SentinelAI-Setup.exe`)  
✅ Endpoint monitoring and inventory collection  
✅ 13 security configuration rules  
✅ Alert tracking and incident management  
✅ Risk scoring with detailed explanations  
✅ Local HTML report generation  
✅ Signed license management (7-day development leases)  
✅ Optional cloud AI for alert explanations  

### What's not ready

⚠️ Production Authenticode signing  
⚠️ Automatic updates (foundation exists, not integrated)  
⚠️ Uninstall workflow  
⚠️ Published release downloads (draft exists, not published)  
⚠️ Multi-tenant/SaaS deployment  

See [development status](.agent/STATUS.md) for detailed verification results and [known issues](#limitations).

## Quick start

### Prerequisites

- Windows 11 x64 (for pilot deployment)
- .NET 10 SDK (for building from source)
- Bash and Node.js 20+ (for build scripts)
- PowerShell 7 (optional, for running service tests)

### Install on Windows

1. Build or obtain `SentinelAI-Setup.exe` from the [`setup-windows` CI job](https://github.com/trolomaniak/SentinelAI/actions/workflows/ci.yml)
2. Run Setup with administrator elevation
3. Create an initial administrator account when prompted
4. Wait for installation to complete (installs Core, Agent, Desktop, and services)
5. Launch **SentinelAI** from the Start Menu and sign in

Detailed instructions: [Setup guide](docs/SETUP.md)

### Build from source

```bash
./scripts/build.sh
./scripts/test.sh
```

The build script compiles all components and the diagnostic dashboard. The test script runs 3,000+ assertions covering Core, Agent, Desktop, Setup, rules, scoring, licensing, AI, and updates.

Publish Windows binaries:
```bash
./scripts/publish-desktop-windows.sh
./scripts/publish-agent-windows.sh
```

See [pilot installation guide](docs/PILOT.md) for manual deployment and [Setup build instructions](docs/SETUP.md) for compiling the installer.

## Configuration

### Local deployment (default)

The pilot deployment co-locates Core, Agent, and Desktop on a single Windows 11 x64 machine:

- **Core** runs as a Windows service (`SentinelAICore`) under `NT SERVICE\SentinelAICore`
- **Agent** runs as a Windows service (`SentinelAIAgent`) under `NT AUTHORITY\LocalService`
- **Desktop** connects to Core at `http://127.0.0.1:5000`

### Remote agents

Agents can report to a remote Core server over HTTPS with certificate pinning. Requires separate TLS provisioning. See [architecture documentation](docs/ARCHITECTURE.md).

### Optional cloud features

**Licensing:** Configure a license server URL and activation credential for signed 7-day leases. See [licensing docs](docs/LICENSING.md).

**AI explanations:** Deploy the AI Gateway with a configured model provider key. Core sends minimized alert evidence (no raw logs or credentials) for assistive analysis. See [AI configuration](docs/AI.md).

Both features degrade gracefully — local monitoring, incident tracking, and reporting continue without them.

## Validation

TASK-024 verification (latest):
- ✅ Zero .NET build warnings/errors
- ✅ 322 Setup assertions
- ✅ 2,814 Desktop assertions  
- ✅ 63 dashboard tests
- ✅ Native Windows CI: fresh install, services, ACLs, enrollment, DPAPI, telemetry, authentication

See [STATUS.md](.agent/STATUS.md) for commit hashes and CI run links, or check [GitHub Actions](https://github.com/trolomaniak/SentinelAI/actions/workflows/ci.yml) for recent runs.

## Limitations

- **Detection scope:** Covers 13 configuration rules. Does not scan for malware, check live antivirus status, or verify patch compliance.
- **Inventory:** Can be stale during outages. Historical inventory/heartbeat data is not retained.
- **Scoring:** Prioritizes configuration findings, not effective protection or actual threat probability. A zero score doesn't prove security.
- **Signing:** Development signatures only. Production Authenticode and trust provisioning remain outstanding.
- **Upgrades:** Signed update foundation exists but automatic upgrades are not integrated.
- **Uninstall:** Setup refuses existing installations and retains state on failure. No uninstall workflow provided.

See [Validation and limitations](#validation) section in the original README for complete details.

## Documentation

**Getting started**
- [Single-EXE setup](docs/SETUP.md) · [Manual pilot installation](docs/PILOT.md) · [Desktop authentication](docs/DESKTOP-AUTH.md)

**Operation**
- [Core Windows Service](docs/CORE-SERVICE.md) · [Desktop operation](docs/DESKTOP-OPERATION.md)
- [Devices](docs/DESKTOP-DEVICES.md) · [Alerts](docs/DESKTOP-ALERTS.md) · [Risk & Reports](docs/DESKTOP-RISK-REPORTS.md)

**Architecture & decisions**
- [Architecture overview](docs/ARCHITECTURE.md) · [Architectural decisions](.agent/DECISIONS.md) · [Development status](.agent/STATUS.md)

**Features**
- [Security rules catalog](rules/README.md) · [Risk scoring policy](scoring/README.md) · [Report semantics](docs/REPORTING.md)
- [AI configuration](docs/AI.md) · [Licensing](docs/LICENSING.md) · [Signed updates](docs/UPDATES.md)

## License

See project documentation for licensing terms.
