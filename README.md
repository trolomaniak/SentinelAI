# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform. Core provides a local API with SQLite-backed administrator login and endpoint heartbeat persistence. The Agent sends local heartbeats; the dashboard remains a scaffold.

The backend uses .NET 10 and contains the Agent, Core web host, and shared contracts projects. The dashboard is a dependency-free static shell built with Node.js 20 or newer.

From the repository root, run:

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the .NET solution, then builds the dashboard. The test script runs Agent and Core integration checks.

To start Core for the first time, set a bootstrap administrator name and a password of at least 12 characters. The password is used only to create the initial administrator and is stored as a password hash in SQLite. Remove the password from the environment after the first successful start; later starts use the existing database.

```sh
export SENTINELAI_BOOTSTRAP_USERNAME=admin
read -r -s -p 'Initial administrator password: ' SENTINELAI_BOOTSTRAP_PASSWORD
export SENTINELAI_BOOTSTRAP_PASSWORD
dotnet run --project core/SentinelAI.Core.csproj --no-launch-profile
```

Core listens at `http://127.0.0.1:5000` by default. Set `ASPNETCORE_URLS` to change the address or enable HTTPS with a configured Kestrel certificate. Set `SentinelAI__DataDirectory` to change the SQLite directory; otherwise Core uses the operating system's local application data directory under `SentinelAI/Core`. Keep that directory private and backed up. An existing administrator is never replaced by bootstrap environment variables.

`GET /api/health` is public. `POST /api/auth/login` accepts JSON with `username` and `password` and returns a short-lived bearer access token when credentials are valid. Send it as `Authorization: Bearer <accessToken>` to `GET /api/admin/me`. Invalid credentials receive the same `401` response. Login attempts are rate-limited. Tokens expire after 15 minutes and are invalidated when Core restarts.

## Windows Agent and enrollment

Run `./scripts/publish-agent-windows.sh` to produce `artifacts/agent/win-x64/SentinelAI.Agent.exe`. This is a self-contained, single-file Windows x64 build: the target does not need a separate .NET installation. The bundled native runtime is extracted when the EXE starts. CI verifies the EXE on Windows and uploads it as the `SentinelAI.Agent-win-x64` build artifact.

The Agent runs in user mode as a Windows Service or a console process for development. It creates a stable `installation-id` under `<LocalApplicationData>/SentinelAI/Agent`, then sends heartbeats every 30 seconds with bounded retries during Core outages. Configure `Agent__CoreUrl`, `Agent__DataDirectory`, `Agent__HeartbeatInterval`, `Agent__RetryDelay`, and `Agent__MaxRetryDelay` as needed. The default Core URL is `http://127.0.0.1:5000`.

To enroll an Agent, log in as the Core administrator and call `POST /api/admin/enrollment-tokens` with the administrator bearer token. The response contains a one-use enrollment token valid for ten minutes, plus the Core installation and organization IDs. Supply that token as `Agent__EnrollmentToken` before starting or restarting the Agent. The Agent calls `POST /api/agent/enroll`, receives a Core-assigned endpoint ID and credential, and stores them in `enrollment-state`. Remove the enrollment token from the Agent's environment after enrollment. Invalid, expired, or consumed tokens receive `401`; an installation that is already enrolled receives `409` and retains its endpoint ID.

Core binds to loopback by default. For an Agent on another machine, configure a Core HTTPS listener and a certificate trusted by the Agent operating system, set `Agent__CoreUrl` to its HTTPS origin, and set `Agent__CoreCertificateSha256` to the SHA-256 fingerprint of the Core leaf certificate in DER form. The Agent requires TLS 1.3, normal certificate validation, and the configured fingerprint for LAN connections. Core rejects remote HTTP enrollment and Agent heartbeat traffic. Local loopback HTTP remains available for development and same-machine installations.

The Agent protects its enrollment credential with Windows DPAPI under its service account; Unix test installations restrict the state file to mode `0600`. The state is bound to the configured Core origin and certificate fingerprint. An enrolled Agent authenticates every heartbeat with that credential. Legacy anonymous loopback heartbeats remain `unverified` and cannot update an enrolled endpoint. Core stores only hashes of enrollment tokens and Agent credentials in SQLite; `reporting` is the last observed health state, so consumers should use `last_seen` to assess freshness.

To install a manually published Windows EXE as a service, run `New-Service -Name SentinelAIAgent -BinaryPathName 'C:\SentinelAI\Agent\SentinelAI.Agent.exe' -StartupType Automatic` and then `Start-Service SentinelAIAgent` from an elevated PowerShell session. Keep the service account stable so it can decrypt its DPAPI state. A signed pilot installer belongs to TASK-015.
