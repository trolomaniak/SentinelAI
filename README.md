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

## Endpoint Agent heartbeat

The Agent runs through a .NET host that can operate as a Windows Service or as a console process during development. It generates a stable installation ID in `<LocalApplicationData>/SentinelAI/Agent/installation-id`, sends heartbeats to Core every 30 seconds, and retries with a bounded delay when Core is unavailable. Configure it with `Agent__CoreUrl`, `Agent__DataDirectory`, `Agent__HeartbeatInterval`, `Agent__RetryDelay`, and `Agent__MaxRetryDelay` environment variables. The default Core URL is `http://127.0.0.1:5000`.

For a manual Windows service smoke test, publish on a Windows machine and run these commands from an elevated PowerShell session with a writable target directory:

```powershell
dotnet publish agent/SentinelAI.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:DebugSymbols=false -o C:\SentinelAI\Agent
New-Service -Name SentinelAIAgent -BinaryPathName 'C:\SentinelAI\Agent\SentinelAI.Agent.exe' -StartupType Automatic
Start-Service SentinelAIAgent
```

For TASK-003, Core accepts heartbeats only from the same machine and limits the endpoint to 30 requests per minute. `POST /api/agent/heartbeat` stores the server-observed `last_seen` timestamp and last reported `reporting` state in SQLite, with the device marked `unverified`. The stored state does not indicate whether the Agent is currently online; consumers must consider `last_seen`. Remote Agent enrollment and authenticated LAN communication belong to TASK-004. An installation ID is an identifier, not an authentication credential.
