# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform. The Core service provides a local API with SQLite-backed administrator login. The Agent and dashboard are still scaffolds.

The backend uses .NET 10 and contains the Agent, Core web host, and shared contracts projects. The dashboard is a dependency-free static shell built with Node.js 20 or newer.

From the repository root, run:

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the .NET solution, then builds the dashboard. The test script runs the Agent scaffold check and Core API integration checks.

To start Core for the first time, set a bootstrap administrator name and a password of at least 12 characters. The password is used only to create the initial administrator and is stored as a password hash in SQLite. Remove the password from the environment after the first successful start; later starts use the existing database.

```sh
export SENTINELAI_BOOTSTRAP_USERNAME=admin
read -r -s -p 'Initial administrator password: ' SENTINELAI_BOOTSTRAP_PASSWORD
export SENTINELAI_BOOTSTRAP_PASSWORD
dotnet run --project core/SentinelAI.Core.csproj --no-launch-profile
```

Core listens at `http://127.0.0.1:5000` by default. Set `ASPNETCORE_URLS` to change the address or enable HTTPS with a configured Kestrel certificate. Set `SentinelAI__DataDirectory` to change the SQLite directory; otherwise Core uses the operating system's local application data directory under `SentinelAI/Core`. Keep that directory private and backed up. An existing administrator is never replaced by bootstrap environment variables.

`GET /api/health` is public. `POST /api/auth/login` accepts JSON with `username` and `password` and returns a short-lived bearer access token when credentials are valid. Send it as `Authorization: Bearer <accessToken>` to `GET /api/admin/me`. Invalid credentials receive the same `401` response. Login attempts are rate-limited. Tokens expire after 15 minutes and are invalidated when Core restarts.

## Standalone Windows Agent EXE

Run `./scripts/publish-agent-windows.sh` to produce `artifacts/agent/win-x64/SentinelAI.Agent.exe`. This is a self-contained, single-file Windows x64 build: the target does not need a separate .NET installation. The bundled native runtime is extracted when the EXE starts. CI verifies the EXE on Windows and uploads it as the `SentinelAI.Agent-win-x64` build artifact.

The Agent currently exits without monitoring behavior. Windows Service hosting and heartbeat belong to TASK-003; a signed pilot installer belongs to TASK-015. This EXE runs in user mode and is not a kernel driver.
