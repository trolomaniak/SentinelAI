# Development status

## Completed

- TASK-001 through TASK-008 are merged through PRs #1, #2, #4, #5, #6, #7, #8, and #9 respectively. Standalone Windows Agent EXE packaging merged through PR #3. TASK-009 started from current `main` at `c5c54bbbe6915d2cadc28e018dee8e3a411cff1f`.
- TASK-009 is implemented on `codex/task-009-risk-score`: a dependency-free scoring library, endpoint/organization risk APIs, centralized validated policy/context configuration, and dashboard score explanations. Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-02 with zero .NET warnings/errors. Agent/Core integration, 13 rule cases, 59 scoring assertions, and 23 dashboard tests passed. Core publication included `SentinelAI.Scoring.dll` and the new risk view assets. Final diff review found only TASK-009 changes and no new external dependencies.

## Current architecture

- Agent remains the .NET 10 user-mode Windows Service/console host and self-contained Windows x64 EXE. Enrollment, pinned remote HTTPS, heartbeats, six-hour inventory refresh, and explicit bounded Windows configuration collection remain unchanged.
- Core keeps existing SQLite identity/enrollment/heartbeat/inventory/alert/history persistence and administrator authentication. TASK-009 adds read-only risk APIs computed from one consistent SQLite snapshot of enrolled endpoints, latest inventory, and tracked alerts, using a single explicit evaluation time. No score table or migration is introduced. Relevant status/inventory changes affect the next uncached read.
- `scoring/SentinelAI.Scoring.csproj` provides pure decimal scoring with an immutable validated policy snapshot. Alert contributions expose severity, confidence weight, asset criticality, declared exposure, observation age, status/remediation multiplier, points before mitigation, reduction, and final contribution. Correlation uses distinct supported groups with positive contributions confirmed by the same latest snapshot within the age policy window.
- Default severity points are 1/5/15/25/50; confidence weight is 1; default criticality is standard and exposure unknown, both neutral explicit policy assumptions. Age weights are 1 through seven days, 0.75 through 30 days, and 0.5 thereafter. Open/Investigating/Accepted use status multiplier 1; Resolved uses 0. Default correlation adds five base points per additional group, capped at 20 before asset/exposure multipliers. Raw score, weighted correlation, saturation, and final 0–100 rounded score are explained. Organization score is the highest endpoint score; ties have one bounded representative plus total count.
- `SentinelAI:RiskScoring` configures policy, optional per-endpoint declared criticality/exposure, and inventory freshness (default 12 hours, two inventory cycles). Invalid configuration fails startup. Context sources and the effective policy are exposed; confidence is a policy weight rather than a calibrated probability. Coverage distinguishes missing/unknown/partial/complete inputs for the 13 supported rules, plus stale inventory; it does not certify all Windows protections.
- Administrator-only `GET /api/admin/risk` returns organization/fleet coverage and a bounded ranked endpoint page. `GET /api/admin/devices/{endpointId}/risk` returns full factors/contributions. Both retain existing bearer authentication, HTTPS outside loopback, no-store, and credential separation. Existing device, alert, and current-findings APIs keep their contracts.
- The dependency-free same-origin dashboard adds Risk navigation, ranked endpoint pagination, organization explanation, endpoint factor breakdown, coverage/freshness, raw/capped values, and links from devices/alerts. Browser tokens remain in memory and data is rendered as text. Existing device and alert/status workflows remain available.

## Important decisions

See `.agent/DECISIONS.md` and `scoring/README.md` for the explainable prioritization policy, fixed remediation semantics, declared context defaults, correlation limits, organization maximum, and unknown-data/rounding limitations.

## Known issues

- Scores prioritize reported configuration findings; they do not establish effective protection, Internet exposure, attack probability, or telemetry completeness. A zero rounded score can reflect small positive raw values, explicit confidence discounts, resolved alerts, or missing observations. It never proves safety.
- Criticality/exposure are operator declarations or policy defaults. Confidence weights are not statistically calibrated. The default 12-hour coverage freshness label and seven-/30-day scoring age windows serve different purposes and are exposed separately.
- Scores use current policy and latest positive alert evidence, not historical risk/evidence snapshots. Investigating/Accepted do not remediate risk; Resolved removes its status contribution until newer positive evidence reopens it. Normal/unknown inventory never automatically closes stored alerts.
- Inventory may be stale during outages. BitLocker, live AV health, administrator baselines, and missing-patch indicators still need additional telemetry. No AI or remediation action is introduced by scoring.
- Lost Agent enrollment state still needs an administrator recovery workflow; duplicate enrollment returns `409`. Operators provision HTTPS/certificate pinning. The pre-existing direct `/api/auth/login` endpoint still accepts remote HTTP if Core is explicitly exposed that way; dashboard sign-in and new administrator risk reads reject it.
- Dashboard refresh/reload/expiry behavior remains manual/in-memory. Agent artifacts are unsigned development builds; signed pilot installation belongs to TASK-015. ASP.NET Core's unused key manager may emit its existing generic warning, without persisting a key file.

## TASK-009 Definition of Done

- Endpoint risk score exists with raw/rounded/capped values and explicit factors.
- Organization score exists with highest-endpoint explanation and fleet coverage.
- Relevant alert state changes affect on-demand scores without a stale score cache.
- API exposes every contributing factor, context source, and effective policy.
- Dashboard displays score and explanation, including missing/stale coverage and rounding limits.
- Scoring boundary tests pass: age/clock skew, status and confidence factors, declared contexts, current-snapshot correlation, decimal rounding/caps, organization aggregation/ties, and invalid policy. API integration and rendered frontend tests pass alongside previous regressions.
- Status is updated with architecture, decisions, limitations, next task, and verified commit when available.

## Next task

TASK-010 — License API. Do not start it as part of TASK-009.

## Last verified commit

`c5c54bbbe6915d2cadc28e018dee8e3a411cff1f` — merged TASK-008 base verified through PR #9 CI. The TASK-009 working tree passed the checks above before its implementation commit.
