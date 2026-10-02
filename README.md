# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform. Core provides a local API with SQLite-backed administrator login, endpoint heartbeats, and endpoint inventory. The Agent sends heartbeats and inventory to Core; Core serves a local device dashboard.

The backend uses .NET 10 and contains the Agent, Core web host, shared contracts, and reusable deterministic rules projects. The dashboard uses dependency-free browser JavaScript and builds with Node.js 20 or newer.

From the repository root, run:

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the .NET solution, then builds the dashboard. The test script runs Agent and Core integration checks, individual rule tests, and dashboard JavaScript tests.

To start Core for the first time, set a bootstrap administrator name and a password of at least 12 characters. The password is used only to create the initial administrator and is stored as a password hash in SQLite. Remove the password from the environment after the first successful start; later starts use the existing database.

```sh
export SENTINELAI_BOOTSTRAP_USERNAME=admin
read -r -s -p 'Initial administrator password: ' SENTINELAI_BOOTSTRAP_PASSWORD
export SENTINELAI_BOOTSTRAP_PASSWORD
dotnet run --project core/SentinelAI.Core.csproj --no-launch-profile
```

Core listens at `http://127.0.0.1:5000` by default. Set `ASPNETCORE_URLS` to change the address or enable HTTPS with a configured Kestrel certificate. Set `SentinelAI__DataDirectory` to change the SQLite directory; otherwise Core uses the operating system's local application data directory under `SentinelAI/Core`. Keep that directory private and backed up. An existing administrator is never replaced by bootstrap environment variables.

`GET /api/health` is public. `POST /api/auth/login` accepts JSON with `username` and `password` and returns a short-lived bearer access token when credentials are valid. Send it as `Authorization: Bearer <accessToken>` to `GET /api/admin/me`. Invalid credentials receive the same `401` response. Login attempts are rate-limited. Tokens expire after 15 minutes and are invalidated when Core restarts.

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

## Windows Agent and enrollment

Run `./scripts/publish-agent-windows.sh` to produce `artifacts/agent/win-x64/SentinelAI.Agent.exe`. This is a self-contained, single-file Windows x64 build: the target does not need a separate .NET installation. The bundled native runtime is extracted when the EXE starts. CI verifies the EXE on Windows and uploads it as the `SentinelAI.Agent-win-x64` build artifact.

The Agent runs in user mode as a Windows Service or a console process for development. It creates a stable `installation-id` under `<LocalApplicationData>/SentinelAI/Agent`, then sends heartbeats every 30 seconds with bounded retries during Core outages. Configure `Agent__CoreUrl`, `Agent__DataDirectory`, `Agent__HeartbeatInterval`, `Agent__RetryDelay`, and `Agent__MaxRetryDelay` as needed. The default Core URL is `http://127.0.0.1:5000`.

To enroll an Agent, log in as the Core administrator and call `POST /api/admin/enrollment-tokens` with the administrator bearer token. The response contains a one-use enrollment token valid for ten minutes, plus the Core installation and organization IDs. Supply that token as `Agent__EnrollmentToken` before starting or restarting the Agent. The Agent calls `POST /api/agent/enroll`, receives a Core-assigned endpoint ID and credential, and stores them in `enrollment-state`. Remove the enrollment token from the Agent's environment after enrollment. Invalid, expired, or consumed tokens receive `401`; an installation that is already enrolled receives `409` and retains its endpoint ID.

Core binds to loopback by default. For an Agent on another machine, configure a Core HTTPS listener and a certificate trusted by the Agent operating system, set `Agent__CoreUrl` to its HTTPS origin, and set `Agent__CoreCertificateSha256` to the SHA-256 fingerprint of the Core leaf certificate in DER form. The Agent requires TLS 1.3, normal certificate validation, and the configured fingerprint for LAN connections. Core rejects remote HTTP enrollment and Agent heartbeat traffic. Local loopback HTTP remains available for development and same-machine installations.

The Agent protects its enrollment credential with Windows DPAPI under its service account; Unix test installations restrict the state file to mode `0600`. The state is bound to the configured Core origin and certificate fingerprint. An enrolled Agent authenticates every heartbeat with that credential. Legacy anonymous loopback heartbeats remain `unverified` and cannot update an enrolled endpoint. Core stores only hashes of enrollment tokens and Agent credentials in SQLite; `reporting` is the last observed health state, so consumers should use `last_seen` to assess freshness.

After an enrolled heartbeat succeeds, the Agent reports hostname, OS name and version, architecture, CPU model and logical processor count, installed RAM, local fixed-disk capacities, and available Windows firewall profile settings. Unavailable fields are reported as unknown. Collection uses bounded system metadata calls and does not scan files or launch external commands. The Agent refreshes inventory every six hours and retries a failed inventory upload after five minutes. Core accepts inventory only from an enrolled Agent over the same trusted transport as heartbeats, validates and limits the report, and stores the most recently collected report in SQLite. Inventory upload failures do not interrupt heartbeats.

To install a manually published Windows EXE as a service, run `New-Service -Name SentinelAIAgent -BinaryPathName 'C:\SentinelAI\Agent\SentinelAI.Agent.exe' -StartupType Automatic` and then `Start-Service SentinelAIAgent` from an elevated PowerShell session. Keep the service account stable so it can decrypt its DPAPI state. A signed pilot installer belongs to TASK-015.
