# Development status

## Completed

- TASK-001 through TASK-006 are merged through PRs #1, #2, #4, #5, #6, and #7 respectively. The standalone Windows Agent EXE packaging merged through PR #3. TASK-007 started from current `main` at `7932e05f9fea045c092f1cf01ea55da0a5845f38`.
- TASK-007 is implemented on `codex/task-007-rules-v1`: a dependency-free reusable deterministic rule library, 13 individually testable configuration rules, optional normalized Windows posture telemetry, and an administrator-only API for current structured findings. The rule catalog is in `rules/README.md`.
- Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-02 with zero .NET build warnings/errors. Agent collection/enrollment/inventory tests, Core authentication/current-alert/restart/transport tests, all 13 individual rule tests, and all four dashboard tests passed. `./scripts/publish-agent-windows.sh` produced the standalone Windows x64 EXE successfully. Final diff review found only TASK-007 changes and no new external dependencies.

## Current architecture

- Agent remains a .NET 10 user-mode Windows Service/console host and self-contained Windows x64 EXE. Enrollment credentials, stable installation identity, pinned remote HTTPS, heartbeats, and six-hour inventory refresh remain in place. A bounded Windows registry allowlist adds explicit UAC, RDP, SMB, automatic logon, LSA, and automatic update configuration to the existing inventory. It never reads passwords, scans files, or launches commands. Missing, unreadable, or unrecognized values remain null; an unreadable or malformed policy does not fall back to a contradictory local value.
- Core remains an ASP.NET Core service with administrator authentication and SQLite persistence for identity, enrollment, heartbeats, and the latest inventory per endpoint. Optional configuration fields preserve old Agent payloads and stored inventories. Inventory validation checks enum bounds before persistence.
- `rules/SentinelAI.Rules.csproj` provides `IEndpointRule`, normalized `EndpointState`, `RuleEngine`, and structured `SecurityAlert` with rule ID, title, severity, reason, typed evidence, endpoint, observation timestamp, and recommended action. Rules use no clock, network, random inputs, LLM, or remediation. Windows applicability and observed prerequisites prevent unknown/inapplicable detections.
- `GET /api/admin/devices/{endpointId}/alerts` evaluates the newest stored snapshot on demand. It requires administrator authentication and HTTPS outside loopback, returns uncached findings and the inventory observation time, returns an empty list for no/unknown inventory, and returns 404 for unknown endpoints. Newer normal snapshots clear current findings; older uploads cannot replace current state. This is current detection output, without incident history or lifecycle state.
- Core still serves the dependency-free same-origin device dashboard. Device health is based on Core heartbeat time, separate from last-reported configuration. CI builds/tests on Linux and verifies Agent collection, enrollment, standalone EXE packaging, console startup, and Windows Service startup on Windows.

## Important decisions

See `.agent/DECISIONS.md` for the reusable stateless rule library, explicit configuration semantics, and on-demand current findings, along with earlier dashboard, enrollment, and inventory decisions.

## Known issues

- These findings describe reported configuration, not effective runtime protection or Internet exposure. An empty result does not prove all protections are enabled. BitLocker, live Defender/third-party AV health, local administrator baselines, and actual missing-patch indicators require additional telemetry and are not guessed from these settings.
- Configuration snapshots refresh every six hours. API responses retain the collection time so callers can identify stale observations. Alert/incident history and dashboard incident lifecycle belong to TASK-008; scoring belongs to TASK-009.
- A lost Agent enrollment state or lost first enrollment response requires an explicit administrator recovery workflow. Re-enrollment of an existing installation remains rejected with `409`.
- Operators must provision HTTPS and the Agent certificate fingerprint for LAN enrollment. The dashboard refuses remote HTTP sign-in and administrator device/finding reads reject remote HTTP; the pre-existing direct `/api/auth/login` API still accepts remote HTTP if Core is explicitly exposed that way.
- The dashboard refreshes on navigation or Refresh; reloads and expired tokens require another sign-in. The Agent CI artifact is an unsigned development build; signed pilot installation belongs to TASK-015.
- ASP.NET Core's unused key manager can log a generic warning about unencrypted key persistence. Its repository is process-local and no Data Protection key file is written by Core.

## TASK-007 Definition of Done

- Reusable rule interface exists: `IEndpointRule` and custom/default `RuleEngine`.
- At least 10 rules: 13 documented, separate rules covering firewall profiles, UAC, RDP, SMB, automatic logon, LSA protection, and update policy.
- Each rule has tests: isolated trigger, normal, unknown, non-Windows, and applicable prerequisites.
- Triggered rules generate structured alerts: typed evidence and all required metadata; API integration exercises accepted risky inventory and repeat reads.
- False/normal conditions are tested: missing values, RDP disabled/unknown, TLS-only RDP encryption applicability, UAC prerequisites, remediated snapshots, and policy parsing/precedence.
- Status is updated with architecture, decisions, limitations, and next task.

## Next task

TASK-008 — Incident view. Do not start it as part of TASK-007.

## Last verified commit

`7932e05f9fea045c092f1cf01ea55da0a5845f38` — merged TASK-006 base. The TASK-007 working tree passed the checks above before its implementation commit.
