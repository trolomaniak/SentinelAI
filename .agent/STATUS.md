# Development status

## Completed

- TASK-001 merged through PR #1; its GitHub Actions CI passed.
- TASK-002 Core API and local authentication merged through PR #2: health, SQLite initialization, one bootstrap administrator, password hashing, login, a protected endpoint, configuration, and JSON structured logs.
- A standalone, self-contained Windows x64 Agent EXE can be built with `scripts/publish-agent-windows.sh`. Windows CI publishes, starts, and uploads the single-file EXE. This packaging change is separate from TASK-003 service behavior.
- Local `./scripts/build.sh`, `./scripts/test.sh`, and the Agent publish script passed on 2026-10-01. The branch CI build/test and Windows packaging jobs passed for `faa5b5a1b9de251cb1a1a310ae038746efe1f634`.

## Current architecture

- Agent remains a .NET 10 console scaffold with no endpoint behavior. Its portable `win-x64` EXE includes the .NET runtime and is uploaded as a CI artifact.
- Core is a .NET 10 ASP.NET Core service. It binds to loopback HTTP by default, supports standard Kestrel HTTPS configuration, and exposes `GET /api/health`, `POST /api/auth/login`, and authenticated `GET /api/admin/me`.
- Core creates a local SQLite database on startup and creates one administrator from first-run environment variables. It stores an Identity PBKDF2 password hash. Bearer tokens last 15 minutes and are invalidated on restart.
- Shared contracts are still empty. Dashboard remains a static shell. CI uses the root build and test scripts.

## Important decisions

See `.agent/DECISIONS.md` for the local Core authentication decisions and the standalone Agent packaging choice.

## Known issues

- Core has not yet been exercised on Windows. The Agent EXE is launched by Windows CI, but service hosting and heartbeat are still unimplemented until TASK-003.
- The Agent CI artifact is an unsigned development build; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. TASK-002 configures its repository in memory, and no Data Protection key file is written by Core.

## Next task

TASK-003 — Agent Heartbeat and Windows Service hosting.

## Last verified commit

`faa5b5a1b9de251cb1a1a310ae038746efe1f634` — Agent packaging passed local build/tests/publish and hosted Windows and Linux CI jobs.
