# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform. Core provides a local API with SQLite-backed administrator login, endpoint heartbeats, and endpoint inventory. The Agent sends heartbeats and inventory to Core; Core serves a local device dashboard.

The backend uses .NET 10 and contains the Agent, Core web host, shared contracts, reusable deterministic rules, risk scoring, a separate cloud License API and AI Gateway. The dashboard uses dependency-free browser JavaScript and builds with Node.js 20 or newer.

From the repository root, run:

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the .NET solution, then builds the dashboard. The test script runs Agent/Core and licensing integration checks, individual rule/scoring/lease verification tests, and dashboard JavaScript tests.

To start Core for the first time, set a bootstrap administrator name and a password of at least 12 characters. The password is used only to create the initial administrator and is stored as a password hash in SQLite. Remove the password from the environment after the first successful start; later starts use the existing database.

```sh
export SENTINELAI_BOOTSTRAP_USERNAME=admin
read -r -s -p 'Initial administrator password: ' SENTINELAI_BOOTSTRAP_PASSWORD
export SENTINELAI_BOOTSTRAP_PASSWORD
dotnet run --project core/SentinelAI.Core.csproj --no-launch-profile
```

Core listens at `http://127.0.0.1:5000` by default. Set `ASPNETCORE_URLS` to change the address or enable HTTPS with a configured Kestrel certificate. Set `SentinelAI__DataDirectory` to change the SQLite directory; otherwise Core uses the operating system's local application data directory under `SentinelAI/Core`. Keep that directory private and backed up. An existing administrator is never replaced by bootstrap environment variables.

`GET /api/health` is public. `POST /api/auth/login` accepts JSON with `username` and `password` and returns a short-lived bearer access token when credentials are valid. Send it as `Authorization: Bearer <accessToken>` to `GET /api/admin/me`. Invalid credentials receive the same `401` response. Login attempts are rate-limited. Tokens expire after 15 minutes and are invalidated when Core restarts.

## Native Windows desktop

The separate .NET 10 WPF `SentinelAI.Desktop` provides native Windows x64 administrator setup, sign-in, sign-out and session handling, with native Devices, Alerts/incidents, Risk and Reports workspaces available after sign-in. Run `./scripts/publish-desktop-windows.sh` to produce the self-contained application directory at `artifacts/desktop/win-x64`, then open `SentinelAI.Desktop.exe` on Windows. See [native Devices](docs/DESKTOP-DEVICES.md), [native Alerts](docs/DESKTOP-ALERTS.md), [native Risk and Reports](docs/DESKTOP-RISK-REPORTS.md), [desktop authentication](docs/DESKTOP-AUTH.md) and [desktop structure and Windows validation](desktop/README.md). Existing dashboard workflows remain available through Core; Overview and Settings remain native placeholders.

## Core Windows Service

Core supports Windows Service hosting as `SentinelAICore` while retaining the console commands above. The [Core service guide](docs/CORE-SERVICE.md) covers signed pilot installation, local administrator initialization, the limited virtual service account, protected persistent storage, delayed automatic startup, recovery and service-only removal. Core runs independently of the desktop window. Registration requires an explicitly elevated PowerShell terminal and an initialized pilot installation; service arguments contain only the nonsecret configuration path.

## Signed subscription leases

The separate [License API](cloud/license-api/README.md) issues a seven-day signed lease containing organization and Core installation IDs, plan, endpoint limit, enabled features, issue time, and full-mode expiration. Its activation credential selects an operator-configured entitlement; client requests cannot choose their own plan or limits. The development issuer uses ECDSA P-256/SHA-256 (ES256), an asymmetric equivalent allowed by TASK-010, without an external crypto dependency.

Core verifies signatures locally using only provisioned public P-256 SPKI PEM keys. Set `SentinelAI__Licensing__TrustedPublicKeys__<keyId>` to an absolute public-key file path. Key IDs support overlapping trust during rotation. Core rejects private keys and other curves; it never references the cloud signer. Lease identity must match the organization and Core installation IDs already stored by enrollment (also returned when issuing an enrollment token).

An authenticated Core administrator can call `POST /api/admin/license/verify` with `{"lease":"<signed-lease>"}`. The response reports `valid`, `expired`, `invalid`, `notYetValid`, or `identityMismatch`; claims are exposed only for a verified, identity-matching valid or expired lease. Invalid signatures, unknown keys, malformed tokens, modified claims, and unsupported algorithms fail verification. Expiration begins exactly at `full_mode_until`; there is no hidden extension. Like other administrator reads, verification requires HTTPS outside loopback and sends `Cache-Control: no-store`.

With no public trust keys configured, the verification endpoint returns `503`; existing monitoring continues. TASK-011 adds opt-in renewal, persisted signed lease/time state, and the explicit FULL/GRACE/SAFE_MODE/RECOVERING lifecycle. A failed renewal retains GRACE only until the signed seven-day deadline; Safe Mode preserves telemetry, rules, alerts, incident access, and emergency export. See [licensing operation and configuration](docs/LICENSING.md). TASK-012 uses these capabilities for the optional signed `cloud_ai` feature; future premium features and endpoint-limit enforcement remain separate work. Use the automated development key-generation workflow documented with the License API; tests generate their own temporary keys and use synthetic entitlements. Never provision a private signing key to Core or commit signing keys or activation credentials.

## Assistive alert explanations

Select **Explain with AI** on an alert to request a structured explanation, investigation suggestions and remediation suggestions. Core sends only minimized configuration evidence through the separate AI Gateway; the provider key stays on that gateway. Analysis is labeled assistive, cannot override the deterministic alert, and performs no endpoint actions. Cloud failures leave local alerts and review controls available. The optional feature requires a signed `cloud_ai` entitlement. See [AI configuration and privacy](docs/AI.md).

## Device dashboard

Open the Core origin in a browser, for example `http://127.0.0.1:5000/`, and sign in with the Core administrator account. Core serves the dashboard on the same origin as its API, so no cross-origin permission is required. For access from another computer, configure Core with HTTPS; the dashboard sign-in form will not submit credentials over remote HTTP. The bearer token stays in browser memory and is cleared on sign-out, page refresh, or the next request after session expiry.

The device list shows enrolled endpoints, their last heartbeat, Agent version, OS, and the last reported configured firewall settings. Select an endpoint to see its inventory and firewall profile details. Health is computed from Core's last-seen time: healthy through two minutes, warning through five minutes, offline after five minutes, and unknown before the first heartbeat. Missing inventory is displayed as unknown. Anonymous legacy loopback heartbeats do not appear as enrolled devices. The authenticated `GET /api/admin/devices` and `GET /api/admin/devices/{endpointId}` endpoints supply the list and details.

## Security rules v1

The authenticated `GET /api/admin/devices/{endpointId}/alerts` API evaluates the newest accepted inventory snapshot using 13 deterministic configuration rules. Each finding includes the rule ID, title, severity, reason, typed evidence, endpoint ID, observation timestamp, and recommended action. The response includes `observedUtc`; a snapshot may be old when an endpoint is offline. Missing inventory has a null observation time and no findings. Unknown settings do not trigger rules, so an empty result does not establish that every protection is enabled.

Rules cover configured firewall profiles, UAC, RDP authentication/encryption, SMBv1 and guest access, automatic logon, LSA protection, and automatic update policy. The Agent reads bounded Windows registry settings without scanning files, running external programs, or reading stored credentials. Findings describe configuration risks rather than proving runtime protection, Internet exposure, or missing patches. BitLocker, live Defender/third-party AV health, administrator baselines, and update compliance require additional telemetry; they are not inferred from these settings. See [the rule catalog](rules/README.md) for conditions and severity.

Core derives current findings locally from persisted inventory on request. Repeated reads of the same snapshot are deterministic; a newer normal snapshot removes the current finding, and an older upload cannot replace it. Durable alert tracking is separate from this current-state API and is described below. Detection does not use an LLM or perform remediation. This API requires administrator authentication and HTTPS outside loopback, and responses are not cached.

## Alerts and status tracking

Open **Alerts** in the dashboard to view stored detections. Filter by severity or status, page through the list, and select an alert for its endpoint, reason, typed evidence, observation times, recommended action, and status history. Administrators can set **Open**, **Investigating**, **Resolved**, or **Accepted**. A status edit records the administrator and Core's time; it does not change endpoint configuration. Concurrent edits are rejected with a conflict so the administrator can review the latest state.

Core stores one tracked alert per endpoint and rule, atomically with each accepted newer inventory. Repeated positive observations update the evidence and last-observed time without creating duplicate rows. Investigating and Accepted remain administrator decisions; a strictly newer positive observation reopens a Resolved alert. Normal or unknown observations do not automatically resolve stored alerts. Historical findings can therefore remain visible after they disappear from the current-state API. The first-observed time and status-change history are retained; evidence reflects the latest positive observation. Existing inventories are backfilled on startup without resetting statuses or duplicating history.

Administrator APIs, all uncached and requiring HTTPS outside loopback:

- `GET /api/admin/alerts?severity=high&status=open&offset=0&limit=50` returns `{ alerts, total, offset, limit }`. Filters are optional; valid limits are 1–200.
- `GET /api/admin/alerts/{alertId}` returns the alert details, the latest 100 status changes, and `statusHistoryCount`. Full status history remains stored locally.
- `PUT /api/admin/alerts/{alertId}/status` accepts `{ "status": "investigating", "expectedVersion": 1 }`, using the version from the latest detail response. A stale version returns `409`; an unknown alert returns `404`.

Snapshot-based detections may be stale while an endpoint is offline. Read the observation timestamps before acting. Risk scoring, cross-rule correlation, AI analysis, and automated remediation are outside TASK-008.

## Risk scoring

Open **Risk** in Desktop or the dashboard for the organization summary and ranked enrolled endpoints, then select an endpoint for its score and contributing factors. Desktop preserves Core's ranked server pages and exposes every factor with literal text and full decimal precision; dashboard device and alert details also link to endpoint risk. Scores are local prioritization indicators. A zero rounded score can reflect small positive contributions, an explicit confidence discount, resolved findings, or missing observations; it does not prove that an endpoint or organization is secure. Missing inventory and unknown observations are explicitly shown.

The deterministic policy combines each tracked alert's severity, configured detection-confidence weight, asset criticality, declared exposure, observation age, and remediation status, plus a bounded bonus for distinct rule groups confirmed in the same fresh latest inventory. Core computes scores from one consistent SQLite snapshot on each request, so newer inventory and administrator status changes are reflected on the next read. No AI determines the score.

Investigating and Accepted do not reduce the status multiplier because acknowledgment does not remediate a finding. Resolved sets that multiplier to zero until a newer positive observation reopens the alert. Older observations retain a reduced raw contribution; they do not silently become safe. Individual factors, defaults, raw contributions, correlation, and any score cap are exposed through the API and dashboard. Organization risk is the highest endpoint score, with counts showing the size and observation coverage of the enrolled estate. See [the scoring policy](scoring/README.md) for the formula, centralized weights, boundary rules, and configuration.

Administrator APIs require the existing bearer token and HTTPS outside loopback, and return uncached responses:

- `GET /api/admin/risk?offset=0&limit=50` returns the organization summary and a ranked endpoint page.
- `GET /api/admin/devices/{endpointId}/risk` returns the endpoint score and its factor breakdown.

Asset criticality defaults to standard priority; exposure defaults to unknown with a neutral multiplier. They are policy assumptions, not observations inferred from RDP or firewall settings. Operators may declare per-endpoint context through Core configuration. Risk configuration is validated at startup and changes require a Core restart; endpoint and alert data remain persisted.

Configuration lives under `SentinelAI:RiskScoring`. For example, start Core with `--SentinelAI:RiskScoring:EndpointContexts:<endpointId>:AssetCriticality high --SentinelAI:RiskScoring:EndpointContexts:<endpointId>:Exposure internet`, replacing `<endpointId>` with an enrolled endpoint GUID. Policy overrides go under `SentinelAI:RiskScoring:Policy`; use `MaximumCorrelationBaseBonus` for the limit applied before asset/exposure multipliers. The API returns the effective policy. Coverage uses the 13 supported rule inputs, not every possible Windows protection. Inventory freshness defaults to 12 hours (two collection cycles), while age/correlation uses its separately exposed policy window.

## Local security reports

Open **Reports** in Desktop or the dashboard, choose an inclusive UTC date range, and generate a standalone HTML report. In Desktop, **Generate report** retains Core's exact attachment in memory; **Save HTML** opens an explicit native destination picker, without embedding or automatically opening the document. The default range is the previous complete calendar month. The report includes a management summary, current organization risk and endpoint health, retained incident activity by severity, high/critical incidents, resolutions, tracked posture findings, prioritized actions and technical evidence. It works locally without AI, issuer connectivity or a premium license. Open the saved HTML offline; use the browser's print dialog to print it or save it as PDF.

`GET /api/admin/reports/security?from=2026-09-01&to=2026-09-30` returns an authenticated, uncached HTML attachment. Dates must be exactly `yyyy-MM-dd`, ordered and at most 366 inclusive days. The current risk/health snapshot is explicitly separate from period activity: Core does not store historical scores or complete inventory/heartbeat history, so historical trend is unavailable. See [report semantics and limits](docs/REPORTING.md).

## Signed update foundation

TASK-014 adds bounded signed update manifests, public P-256 signature verification, SHA-256/size verification of a private staged ZIP and explicit Stable/Pilot/Beta channels. The local `updater` tool verifies or stages a package under an operator-selected environment/artifact/channel/version policy. A separate development-only tool generates keys outside the checkout and creates signed test manifests; production signing material is never provisioned to Core, Agent or the verification client.

The transactional library verifies/extracts before stopping a service, retains the previous code, requires an explicit service lifecycle/health adapter and restores the previous installation on failure. Pending transactions can be recovered after interruption; a failed rollback preserves its journal and backup. This foundation does not add automatic updates or service installation. See [manifest trust, development commands and rollback operation](docs/UPDATES.md).

## Windows Agent and enrollment

For the first local Windows 11 x64 pilot, follow the [pilot installation guide](docs/PILOT.md). It provides signed development packaging, a private local Core configuration and initial administrator setup, Agent installation under LocalService, one-use enrollment, exact endpoint/heartbeat/inventory/dashboard verification and service uninstall with state preservation. Installation requires an explicitly elevated PowerShell terminal. Core's console pilot can be registered as a service using the [Core service guide](docs/CORE-SERVICE.md). See the guides for separate Windows acceptance and known limitations.

Run `./scripts/publish-agent-windows.sh` to produce `artifacts/agent/win-x64/SentinelAI.Agent.exe`. This is a self-contained, single-file Windows x64 build: the target does not need a separate .NET installation. The bundled native runtime is extracted when the EXE starts. CI verifies the EXE on Windows and uploads it as the `SentinelAI.Agent-win-x64` build artifact.

The Agent runs in user mode as a Windows Service or a console process for development. It creates a stable `installation-id` under `<LocalApplicationData>/SentinelAI/Agent`, then sends heartbeats every 30 seconds with bounded retries during Core outages. Configure `Agent__CoreUrl`, `Agent__DataDirectory`, `Agent__HeartbeatInterval`, `Agent__RetryDelay`, and `Agent__MaxRetryDelay` as needed. The default Core URL is `http://127.0.0.1:5000`.

To enroll an Agent, log in as the Core administrator and call `POST /api/admin/enrollment-tokens` with the administrator bearer token. The response contains a one-use enrollment token valid for ten minutes, plus the Core installation and organization IDs. Supply that token as `Agent__EnrollmentToken` before starting or restarting the Agent. The Agent calls `POST /api/agent/enroll`, receives a Core-assigned endpoint ID and credential, and stores them in `enrollment-state`. Remove the enrollment token from the Agent's environment after enrollment. Invalid, expired, or consumed tokens receive `401`; an installation that is already enrolled receives `409` and retains its endpoint ID.

Core binds to loopback by default. For an Agent on another machine, configure a Core HTTPS listener and a certificate trusted by the Agent operating system, set `Agent__CoreUrl` to its HTTPS origin, and set `Agent__CoreCertificateSha256` to the SHA-256 fingerprint of the Core leaf certificate in DER form. The Agent requires TLS 1.3, normal certificate validation, and the configured fingerprint for LAN connections. Core rejects remote HTTP enrollment and Agent heartbeat traffic. Local loopback HTTP remains available for development and same-machine installations.

The Agent protects its enrollment credential with Windows DPAPI under its service account; Unix test installations restrict the state file to mode `0600`. The state is bound to the configured Core origin and certificate fingerprint. An enrolled Agent authenticates every heartbeat with that credential. Legacy anonymous loopback heartbeats remain `unverified` and cannot update an enrolled endpoint. Core stores only hashes of enrollment tokens and Agent credentials in SQLite; `reporting` is the last observed health state, so consumers should use `last_seen` to assess freshness.

After an enrolled heartbeat succeeds, the Agent reports hostname, OS name and version, architecture, CPU model and logical processor count, installed RAM, local fixed-disk capacities, and available Windows firewall profile settings. Unavailable fields are reported as unknown. Collection uses bounded system metadata calls and does not scan files or launch external commands. The Agent refreshes inventory every six hours and retries a failed inventory upload after five minutes. Core accepts inventory only from an enrolled Agent over the same trusted transport as heartbeats, validates and limits the report, and stores the most recently collected report in SQLite. Inventory upload failures do not interrupt heartbeats.

Windows inventory includes the observed release label (`DisplayVersion`, with a legacy Windows 10 `ReleaseId` fallback), installation type and full native version/build with a valid registry `UBR` revision. Client branding distinguishes Windows 10/11 even when the registry's product name is stale; server products remain distinct. The device list displays, for example, `Windows 11 26H2 10.0.26200.0`, while detail separates `OS: Windows 11` and `OS Version: 26H2 10.0.26200.0`. The redundant `Client` installation type is omitted from the list; server installation types remain visible. Missing metadata is not invented, and older Agent reports remain accepted. After updating Core and Agent, restart the Agent to send fresh inventory and refresh the dashboard.

Use `installer/pilot/Install-SentinelAIPilot.ps1` for the pilot service rather than manually registering an unconfigured EXE. It quotes the executable/configuration paths, validates explicit package trust and paths, sets restricted ACLs and preserves the LocalService account across reinstall so it can decrypt its DPAPI state. Existing manual/development installations are not migrated or overwritten.
