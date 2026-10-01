# Development status

## Completed

- TASK-001 through TASK-004 are merged through PRs #1, #2, #4, and #5 respectively. The standalone Windows Agent EXE packaging merged through PR #3.
- TASK-005 endpoint inventory is implemented on `codex/task-005-endpoint-inventory`. An enrolled Agent collects bounded endpoint metadata and submits it to Core. Core authenticates and validates reports and persists only the latest collection per endpoint.
- Local `./scripts/build.sh`, `./scripts/test.sh`, and `./scripts/publish-agent-windows.sh` passed on 2026-10-01. The build had zero warnings or errors. Agent tests cover inventory collection, Agent-to-Core delivery, and heartbeat continuity after an inventory upload failure. Core tests cover authentication, malformed and oversized input, newest-only storage, restart persistence, and remote HTTP rejection.

## Current architecture

- Agent is a .NET 10 user-mode background host that runs as a Windows Service or console process and publishes as a self-contained single-file Windows x64 EXE. It retains a stable installation ID, enrolls with a one-use token, protects its enrollment credential, and sends authenticated heartbeats with bounded retries. Remote Core connections require HTTPS, TLS 1.3, normal certificate validation, and a configured certificate fingerprint.
- After an enrolled heartbeat succeeds, the Agent reports hostname, OS name and version, architecture, CPU model and logical processor count, installed RAM, fixed local disks, configured Windows firewall profile settings, collection time, Agent version, and endpoint ID. Unavailable optional values remain unknown. It refreshes inventory every six hours, retries inventory failures after five minutes, and continues heartbeats if collection or upload fails.
- Core is a .NET 10 ASP.NET Core service with administrator authentication and SQLite persistence for Core/organization identity, enrollment, heartbeats, and the newest inventory report per endpoint. Inventory submission requires the enrolled Agent credential and a trusted transport; report size and fields are bounded. Anonymous loopback heartbeats remain unverified and cannot submit inventory. The dashboard remains a static shell. CI builds/tests on Linux and exercises Agent tests, EXE packaging, console startup, and Windows Service startup on Windows.

## Important decisions

See `.agent/DECISIONS.md` for inventory cadence, latest-only storage, collection bounds, and earlier enrollment/trust decisions.

## Known issues

- A lost Agent enrollment state or lost first enrollment response requires an explicit administrator recovery workflow. Re-enrollment of an existing installation remains rejected with `409`.
- Full certificate/mTLS lifecycle management remains future work; operators must provision the Core HTTPS certificate and Agent fingerprint for LAN enrollment.
- Windows firewall values describe configured profile settings where available, not the live Windows Filtering Platform state. Unknown values are stored as null. No antivirus or update-status probe is included in TASK-005.
- `reporting` is the last observed health state and does not automatically become offline when heartbeats stop. Consumers should assess `last_seen`.
- The Agent CI artifact is an unsigned development build; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. Its repository is process-local and no Data Protection key file is written by Core.

## Next task

TASK-006 — Dashboard devices. Do not start it as part of TASK-005.

## Last verified commit

`2ecfd2141aab73935c69091441eaad7beea2aec0` — TASK-005 implementation passed local build, Agent/Core integration tests, and standalone Windows Agent EXE publication.
