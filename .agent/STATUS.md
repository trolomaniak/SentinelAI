# Development status

## Completed

- TASK-001 through TASK-005 are merged through PRs #1, #2, #4, #5, and #6 respectively. The standalone Windows Agent EXE packaging merged through PR #3.
- TASK-006 device dashboard is implemented on `codex/task-006-dashboard-devices`. Core exposes authenticated enrolled-device list and detail APIs, and serves the dashboard on its own origin. The page shows health, last seen, OS, Agent version, and last reported firewall settings, with detail navigation and loading, error, and empty states.
- Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-02 with zero .NET build warnings or errors. Tests cover administrator-only device reads, empty and unverified-only lists, unknown/fresh/stale health, inventory details, restart persistence, remote HTTP rejection, dashboard static serving, and JavaScript route/status/origin helpers. `dotnet publish` of Core passed and included the dashboard assets.

## Current architecture

- Agent is a .NET 10 user-mode background host that runs as a Windows Service or console process and publishes as a self-contained single-file Windows x64 EXE. It retains a stable installation ID, enrolls with a one-use token, protects its enrollment credential, and sends authenticated heartbeats and bounded inventory reports. Remote Core connections require HTTPS, TLS 1.3, normal certificate validation, and a configured certificate fingerprint.
- Core is a .NET 10 ASP.NET Core service with administrator authentication and SQLite persistence for Core/organization identity, enrollment, heartbeats, and the newest inventory per endpoint. Administrator-only device list and detail APIs join enrolled endpoints to their latest heartbeat and inventory without exposing Agent credentials. They require HTTPS for non-loopback requests and return uncached display models.
- Core serves dependency-free dashboard assets from its own build/publish output. Browser sign-in uses the existing short-lived administrator bearer token in memory. The device list shows enrolled endpoints only; it computes healthy (up to two minutes), warning (up to five minutes), offline (older), and unknown (no heartbeat) from Core's last-seen clock. Firewall posture remains a separate last-reported value. CI builds/tests on Linux and exercises Agent tests, EXE packaging, console startup, and Windows Service startup on Windows.

## Important decisions

See `.agent/DECISIONS.md` for same-origin dashboard hosting, browser token handling, enrolled-only reads, and health thresholds, along with earlier enrollment and inventory decisions.

## Known issues

- A lost Agent enrollment state or lost first enrollment response requires an explicit administrator recovery workflow. Re-enrollment of an existing installation remains rejected with `409`.
- Operators must provision HTTPS and the Agent certificate fingerprint for LAN enrollment. The dashboard refuses remote HTTP sign-in and new device reads reject remote HTTP; the pre-existing direct `/api/auth/login` API still accepts remote HTTP if Core is explicitly exposed that way.
- Windows firewall values describe configured profile settings, not live Windows Filtering Platform state. Unknown values are null; antivirus and update-status probes are not yet available.
- The dashboard refreshes device data on navigation or when the administrator selects Refresh. Browser page reloads and expired tokens require another sign-in. Incident, AI, reporting, and multi-tenant views remain outside TASK-006.
- The Agent CI artifact is an unsigned development build; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. Its repository is process-local and no Data Protection key file is written by Core.

## Next task

TASK-007 — Rules v1. Do not start it as part of TASK-006.

## Last verified commit

`91613f692224355bb128a518d3332bcb6bd0ce44` — TASK-006 implementation passed local build, Agent/Core/dashboard tests, and a Core publish containing dashboard assets.
