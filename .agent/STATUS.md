# Development status

## Completed

- TASK-001 through TASK-009 are merged through PRs #1, #2, #4, #5, #6, #7, #8, #9, and #10 respectively. Standalone Windows Agent EXE packaging merged through PR #3. TASK-010 started from current `main` at `15c1aa75e8abbb9ed083fdce17d4ad38cb104865`, the verified TASK-009 merge.
- TASK-010 is implemented on `codex/task-010-license-api`: separate development License API, signed lease contract/format, public-only local Core verification, automatic development key generation, and generated-key unit/integration tests. Local `./scripts/build.sh` and `./scripts/test.sh` passed on 2026-10-02 with zero .NET warnings/errors: Agent/Core integration, 13 rule cases, 59 scoring assertions, 84 licensing crypto assertions, 105 License API/Core integration assertions, and 23 dashboard tests. Core and License API Release publication passed; Core output contains the public verifier and no cloud signer, and neither artifact contains key or activation credential files. Final diff review found only TASK-010 changes and no new external dependencies.

## Current architecture

- Agent remains the .NET 10 user-mode Windows Service/console host and self-contained Windows x64 EXE. Enrollment, pinned remote HTTPS, heartbeats, six-hour inventory refresh, and explicit bounded Windows configuration collection remain unchanged.
- Core keeps existing SQLite identity/enrollment/heartbeat/inventory/alert/history persistence and administrator authentication. TASK-009 adds read-only risk APIs computed from one consistent SQLite snapshot of enrolled endpoints, latest inventory, and tracked alerts, using a single explicit evaluation time. No score table or migration is introduced. Relevant status/inventory changes affect the next uncached read.
- `cloud/license-api` is a separate .NET 10 development issuer. It loads a server-only PKCS#8 P-256 private key and startup-validated static entitlements. A random 256-bit activation credential selects a matching organization/Core installation grant via its configured SHA-256 digest; request bodies cannot supply plan, limits, features, or duration. Leases expire exactly seven days after the server UTC issue time.
- `shared/crypto/SentinelAI.Licensing.csproj` contains only the strict compact JWS format and local public-key verification. Protected headers fix ES256 and `sentinelai-lease-v1`; signature covers the header and all required lease claims. Canonical base64url, exact JSON fields, bounded metadata, UTC timestamps, and a positive maximum seven-day lifetime are required. No private-key import or signing implementation is linked into Core.
- Core loads named public SPKI P-256 PEM trust anchors from absolute file paths under `SentinelAI:Licensing:TrustedPublicKeys`. Up to 32 overlapping keys support rotation; unknown settings, private PEMs, other curves, and ambiguous bundles fail configuration. Local verification binds both signed IDs to the existing persisted Core identity and distinguishes valid, expired, invalid, future-issued, and identity-mismatched leases. No schema or license-state persistence is introduced.
- Administrator-only `POST /api/admin/license/verify` verifies without network access; no public keys returns `503`. The new route keeps existing authentication and HTTPS outside loopback, no-store, bounded strict request parsing, and rate limiting. The cloud route has separate activation authentication, strict 4 KiB requests, no-store, rate limiting, and direct HTTPS outside loopback. Existing monitoring, enrollment, and dashboard workflows remain available regardless of lease state.
- `scoring/SentinelAI.Scoring.csproj` provides pure decimal scoring with an immutable validated policy snapshot. Alert contributions expose severity, confidence weight, asset criticality, declared exposure, observation age, status/remediation multiplier, points before mitigation, reduction, and final contribution. Correlation uses distinct supported groups with positive contributions confirmed by the same latest snapshot within the age policy window.
- Default severity points are 1/5/15/25/50; confidence weight is 1; default criticality is standard and exposure unknown, both neutral explicit policy assumptions. Age weights are 1 through seven days, 0.75 through 30 days, and 0.5 thereafter. Open/Investigating/Accepted use status multiplier 1; Resolved uses 0. Default correlation adds five base points per additional group, capped at 20 before asset/exposure multipliers. Raw score, weighted correlation, saturation, and final 0–100 rounded score are explained. Organization score is the highest endpoint score; ties have one bounded representative plus total count.
- `SentinelAI:RiskScoring` configures policy, optional per-endpoint declared criticality/exposure, and inventory freshness (default 12 hours, two inventory cycles). Invalid configuration fails startup. Context sources and the effective policy are exposed; confidence is a policy weight rather than a calibrated probability. Coverage distinguishes missing/unknown/partial/complete inputs for the 13 supported rules, plus stale inventory; it does not certify all Windows protections.
- Administrator-only `GET /api/admin/risk` returns organization/fleet coverage and a bounded ranked endpoint page. `GET /api/admin/devices/{endpointId}/risk` returns full factors/contributions. Both retain existing bearer authentication, HTTPS outside loopback, no-store, and credential separation. Existing device, alert, and current-findings APIs keep their contracts.
- The dependency-free same-origin dashboard adds Risk navigation, ranked endpoint pagination, organization explanation, endpoint factor breakdown, coverage/freshness, raw/capped values, and links from devices/alerts. Browser tokens remain in memory and data is rendered as text. Existing device and alert/status workflows remain available.

## Important decisions

See `.agent/DECISIONS.md`, `scoring/README.md`, `shared/crypto/README.md`, and `cloud/license-api/README.md` for scoring policy and the signed-lease trust boundary, ES256 choice, entitlement authority, rotation, and exact expiration semantics. Development keys/activation credentials are generated outside tracked source; tests use temporary generated keys and synthetic identities.

## Known issues

- Licensing is currently a development issuer with static configured grants and local verification only. Production entitlement/billing infrastructure, automated renewal/client TLS pinning, persisted protected lease state, clock rollback protection, grace/Safe Mode, and license enforcement are not introduced by TASK-010. An expired or invalid lease never stops existing monitoring in this task.
- License verification uses the explicit current UTC clock with no implicit skew allowance. Clock rollback resistance requires persisted trusted time/monotonic state in later licensing work. Operators distribute public keys and keep old/new trust anchors during rotation; Core has no automatic trust discovery. On Windows development key output must use an account-restricted directory ACL.
- Scores prioritize reported configuration findings; they do not establish effective protection, Internet exposure, attack probability, or telemetry completeness. A zero rounded score can reflect small positive raw values, explicit confidence discounts, resolved alerts, or missing observations. It never proves safety.
- Criticality/exposure are operator declarations or policy defaults. Confidence weights are not statistically calibrated. The default 12-hour coverage freshness label and seven-/30-day scoring age windows serve different purposes and are exposed separately.
- Scores use current policy and latest positive alert evidence, not historical risk/evidence snapshots. Investigating/Accepted do not remediate risk; Resolved removes its status contribution until newer positive evidence reopens it. Normal/unknown inventory never automatically closes stored alerts.
- Inventory may be stale during outages. BitLocker, live AV health, administrator baselines, and missing-patch indicators still need additional telemetry. No AI or remediation action is introduced by scoring.
- Lost Agent enrollment state still needs an administrator recovery workflow; duplicate enrollment returns `409`. Operators provision HTTPS/certificate pinning. The pre-existing direct `/api/auth/login` endpoint still accepts remote HTTP if Core is explicitly exposed that way; dashboard sign-in and new administrator risk reads reject it.
- Dashboard refresh/reload/expiry behavior remains manual/in-memory. Agent artifacts are unsigned development builds; signed pilot installation belongs to TASK-015. ASP.NET Core's unused key manager may emit its existing generic warning, without persisting a key file.

## TASK-010 Definition of Done

- License API issues a signed lease containing organization ID, installation ID, plan, endpoint limit, features, issue time, and full-mode expiration.
- Core validates the signature locally using public keys only and existing installation/organization identity.
- Modified claims, headers, and signatures fail verification; malformed tokens and unsupported algorithms/keys are rejected.
- Expired leases are detected at the exact full-mode expiration boundary.
- Development key generation is automated and never overwrites existing material; tests generate their own keys.
- Generated-key signing/verification unit and actual cloud/Core integration tests cover trust, binding, time, rotation, request limits, and authentication.
- Status documents completion, architecture, decisions, limitations, next task, and the verified commit when available.

## Next task

TASK-011 — Grace and Safe Mode. Do not start it as part of TASK-010.

## Last verified commit

`a2728f9d16b080136113ae9d438df0adf2afd856` — TASK-010 implementation verified by the local build, full regression suite, Core/License API publication, and final diff review listed above. Hosted CI and pull request review follow on this branch.
