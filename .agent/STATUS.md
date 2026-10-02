# Development status

## Completed

- TASK-001 through TASK-007 are merged through PRs #1, #2, #4, #5, #6, #7, and #8 respectively. Standalone Windows Agent EXE packaging merged through PR #3. TASK-008 started from current `main` at `0e4906a148de418155a28f11e6dcd4d9b00974bb`.
- TASK-008 is implemented on `codex/task-008-incident-view`: persistent alert tracking, administrator APIs, and the dashboard alert list/details/status workflow. Local build and tests passed on 2026-10-02 with zero .NET warnings/errors. Tests cover migration/backfill, restart persistence, atomic rollback, lifecycle/history, filters/pagination, authorization/HTTPS, stale/concurrent edits, 13 rule cases, Agent integration, and 13 dashboard tests (including nine rendered workflow tests). Core publication passed and included the new dashboard assets. Final diff review found only TASK-008 changes and no new external dependencies.

## Current architecture

- Agent remains the .NET 10 user-mode Windows Service/console host and self-contained Windows x64 EXE. Stable identity, enrollment credentials, pinned remote HTTPS, heartbeats, six-hour inventory refresh, and bounded explicit Windows configuration collection are unchanged by TASK-008.
- Core remains an ASP.NET Core service with SQLite administrator/identity/enrollment/heartbeat/latest-inventory persistence. Additive `TrackedAlerts` and `AlertStatusHistory` tables store one posture alert per enrolled endpoint and rule, typed evidence, severity, first/latest observation times, operator status, version, and status-change history. Accepting a newer inventory and recording its positive detections share one transaction. Existing snapshots are backfilled on startup idempotently.
- The dependency-free deterministic rule library and TASK-007 current-findings API remain separate from persistent alert lifecycle state. Unknown/normal observations never automatically resolve tracked alerts. Repeated positive observations update evidence and last-observed time without creating duplicate rows. Investigating and Accepted are preserved; a strictly newer positive observation reopens Resolved.
- Administrator-only alert list/detail/status APIs use the existing bearer authentication and HTTPS outside loopback, with uncached responses, parameterized SQLite, bounded pagination, and version-checked status writes. Detail responses include the latest 100 status transitions and their total count; full status history stays in SQLite. Status changes record Core's time and authenticated administrator identity; automatic creation/reopening is attributed to Core.
- The dependency-free same-origin dashboard adds Alerts navigation, severity/status filters, pagination, detail evidence/recommended action, observation timestamps, and status editing/history. Tokens stay in browser memory; telemetry is rendered as text. Device views remain available. No status action changes endpoint configuration.

## Important decisions

See `.agent/DECISIONS.md` for atomic persistent alert tracking, duplicate prevention, manual lifecycle semantics, and version conflict handling, along with earlier rules, dashboard, enrollment, and inventory decisions.

## Known issues

- Findings describe reported configuration, not effective protection or Internet exposure. Inventory refreshes every six hours and may be stale during outages; observation timestamps are shown. BitLocker, live AV health, administrator baselines, and missing-patch indicators still require additional telemetry.
- One tracked alert retains its first observation and latest positive evidence rather than every evidence snapshot. Status history is durable. Normal/unknown telemetry does not close an alert automatically; administrators review and set status. Cross-rule correlation and risk scoring are not implemented in TASK-008.
- Lost Agent enrollment state or a lost first enrollment response still needs an explicit administrator recovery workflow; duplicate enrollment returns `409`.
- Operators must provision HTTPS and the Agent certificate fingerprint for LAN access. Dashboard remote HTTP sign-in and new administrator reads/mutations are rejected; the pre-existing direct `/api/auth/login` API still accepts remote HTTP if Core is explicitly exposed that way.
- The dashboard refreshes on navigation or Refresh, with reload/expiry requiring sign-in. The Agent artifact remains an unsigned development EXE; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic unencrypted-key warning; its repository is process-local and no key file is written by Core.

## TASK-008 Definition of Done

- Alerts persist in Core: additive SQLite alert/history storage with atomic inventory ingestion and startup backfill.
- Dashboard shows an alert list with severity/status filtering and pagination.
- Details show endpoint, reason, evidence, recommended remediation, observation times, and status history.
- Administrators can update Open, Investigating, Resolved, and Accepted with optimistic conflict checks.
- API tests cover persistence, authorization/transport, filtering, status changes/conflicts, and upgrade behavior.
- Frontend tests/build pass: all 13 dashboard tests, syntax checks, and dashboard build passed; full backend solution build and Agent/Core/rules tests passed as well.
- Status is updated with architecture, decisions, limitations, next task, and the verified commit when available.

## Next task

TASK-009 — Risk score. Do not start it as part of TASK-008.

## Last verified commit

`f306a414e1f11a9a723b0d62e99f0741912c5884` — TASK-008 implementation passed local solution/dashboard build, Agent/Core/rules/dashboard tests, and Core publication containing the new dashboard assets.
