# Development status

## Completed

- TASK-001 merged through PR #1; its GitHub Actions CI passed.
- TASK-002 Core API and local authentication are merged on `main`.
- TASK-003 is implemented on `codex/task-003-agent-heartbeat`: the Agent runs through a Windows Service capable host, persists an installation ID, sends periodic heartbeats, and retries temporary failures without exiting. Core receives loopback heartbeats and updates SQLite device records with server-observed `last_seen`, last reported health, and `unverified` enrollment status. Shared request and response contracts are in `shared/contracts/`.
- Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-01 with zero build warnings or errors. Tests cover transport failure, HTTP failure, retry, stable identity, Agent-to-Core communication, timestamp updates, and persistence across Core restart. A self-contained single-file `win-x64` Agent publish produced `SentinelAI.Agent.exe`.
- GitHub Actions run `36852418767` passed on 2026-10-01: Linux build and tests, plus a Windows Service smoke check that kept the Agent running with Core unavailable.

## Current architecture

- Agent is a .NET 10 background host with Windows Service integration and no interactive UI. Its default Core URL is loopback HTTP. It stores the installation ID under the operating system's local application data directory and uses configurable heartbeat and bounded retry intervals.
- Core is a .NET 10 ASP.NET Core service with local SQLite administrator authentication from TASK-002. It now initializes a Devices table and accepts rate-limited loopback `POST /api/agent/heartbeat` requests. Device records store an installation ID, UTC `last_seen`, last reported health, and enrollment status.
- Shared contracts define the heartbeat request and response. The dashboard remains a static shell. CI builds and tests on Linux and runs a Windows Service smoke check for the Agent.

## Important decisions

See `.agent/DECISIONS.md` for the TASK-003 Windows Service, provisional loopback trust boundary, and device state decisions.

## Known issues

- Secure enrollment and authenticated LAN Agent communication remain for TASK-004; a TASK-003 heartbeat records an unverified device.
- `reporting` records the last successful heartbeat and does not automatically change to an offline state when the Agent stops. Consumers must interpret `last_seen` until a freshness policy is defined.
- Open PR #3 packages the Agent as a standalone EXE and currently expects that EXE to exit during its smoke test. If it merges after TASK-003, its smoke test must be adapted to the long-running Agent host.
- The existing Core Data Protection key manager can log a generic unencrypted persistence warning. Its keys remain process-local and are not written to disk.

## Next task

TASK-004 — Secure enrollment. Do not start it as part of TASK-003.

## Last verified commit

`c74e06fe46f300fa84f1488a3da3b04e57662e8c` — TASK-003 implementation passed local build, integration tests, `win-x64` single-file publication, and hosted Linux and Windows CI.
