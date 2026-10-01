# Development status

## Completed

- TASK-001 merged through PR #1; its GitHub Actions CI passed.
- TASK-002 Core API and local administrator authentication merged through PR #2.
- The standalone Windows x64 Agent EXE packaging merged through PR #3. TASK-003 Windows Service hosting, heartbeat retries, and SQLite device persistence merged through PR #4.
- TASK-004 secure endpoint enrollment is implemented on `codex/task-004-secure-enrollment`: an administrator issues a ten-minute one-use token; Core assigns an endpoint ID and records its organization/Core association; the Agent stores its enrollment identity and authenticates subsequent heartbeats. Invalid, expired, consumed, or duplicate enrollment attempts fail as specified.
- Local `./scripts/build.sh`, `./scripts/test.sh`, and `./scripts/publish-agent-windows.sh` passed on 2026-10-01 with zero build warnings or errors. Tests cover enrollment success and failure, token expiry and one-use behavior, concurrent claims, duplicate rejection, Agent state persistence across restart, authenticated heartbeat, and remote HTTP rejection.
- GitHub Actions run `36914756583` passed on 2026-10-01: Linux build and tests; Windows Agent enrollment tests, single-file EXE publication, console startup, Windows Service startup, and artifact upload.

## Current architecture

- Agent is a .NET 10 user-mode background host that runs as a Windows Service or console process and can be published as a self-contained single-file EXE. It retains a stable installation ID, enrolls with a one-use token, persists its assigned endpoint ID and credential, and sends authenticated heartbeats with bounded retries. Windows enrollment state is protected with DPAPI under the service account. Remote Core connections require HTTPS, TLS 1.3, normal certificate validation, and an explicit certificate fingerprint.
- Core is a .NET 10 ASP.NET Core service with administrator authentication and SQLite persistence. It stores one Core installation/organization identity, hashes of short-lived enrollment tokens and Agent credentials, endpoint enrollments, and device heartbeat state. Administrator token issuance requires authentication; remote enrollment and enrolled heartbeats require HTTPS. Legacy anonymous loopback heartbeats can update only unverified devices.
- Shared contracts define heartbeat and enrollment requests/responses. The dashboard remains a static shell. CI builds/tests on Linux and tests Agent enrollment, EXE packaging, console startup, and Windows Service startup on Windows.

## Important decisions

See `.agent/DECISIONS.md` for the enrollment token, endpoint credential, Core trust, and Agent state decisions.

## Known issues

- A lost Agent enrollment state or lost first enrollment response requires an explicit administrator recovery workflow. TASK-004 rejects re-enrollment for an existing installation with `409` and does not silently create a duplicate.
- Full certificate/mTLS lifecycle management remains future work; operators must provision the Core HTTPS certificate and Agent fingerprint for LAN enrollment.
- `reporting` is the last observed health state and does not automatically become offline when heartbeats stop. Consumers should assess `last_seen`.
- The Agent CI artifact is an unsigned development build; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. Its repository is process-local and no Data Protection key file is written by Core.

## Next task

TASK-005 — Endpoint inventory. Do not start it as part of TASK-004.

## Last verified commit

`669ffdced348d7e8388c56323ec5667e8b827449` — TASK-004 implementation passed local build, Agent/Core integration tests, single-file Windows Agent publication, and hosted Linux and Windows CI.
