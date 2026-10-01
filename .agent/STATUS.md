# Development status

## Completed

- TASK-001 merged through PR #1; its GitHub Actions CI passed.
- TASK-002 Core API and local authentication are implemented on `codex/task-002-core-api-auth`: health, SQLite initialization, one bootstrap administrator, password hashing, login, a protected endpoint, configuration, and JSON structured logs.
- Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-01 with zero build warnings or errors. Core integration checks use a live loopback server and temporary SQLite database.

## Current architecture

- Agent remains a .NET 10 console scaffold with no endpoint behavior.
- Core is a .NET 10 ASP.NET Core service. It binds to loopback HTTP by default, supports standard Kestrel HTTPS configuration, and exposes `GET /api/health`, `POST /api/auth/login`, and authenticated `GET /api/admin/me`.
- Core creates a local SQLite database on startup and creates one administrator from first-run environment variables. It stores an Identity PBKDF2 password hash. Bearer tokens last 15 minutes and are invalidated on restart.
- Shared contracts are still empty. Dashboard remains a static shell. CI uses the root build and test scripts.

## Important decisions

See `.agent/DECISIONS.md` for the local storage, bootstrap, token, binding, and test decisions.

## Known issues

- The service has not yet been exercised on Windows; local and hosted CI validation run on Linux.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. TASK-002 configures its repository in memory, and no Data Protection key file is written by Core.

## Next task

TASK-003 — Agent Heartbeat. Do not start it as part of TASK-002.

## Last verified commit

`dfbfadc3caad29fc848f1c0ac9d7d80c9584bf3d` — TASK-002 implementation passed local build and integration tests.
