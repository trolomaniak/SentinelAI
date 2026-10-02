# Architecture decisions

## 2026-09-30 — TASK-001 foundation

- Use .NET 10 for the initial backend solution. Agent is a console executable, Core is an empty ASP.NET Core host, and both reference a shared contracts library. Windows Service hosting, endpoints, and transport models belong to later tasks.
- Keep the dashboard as static HTML/CSS with a dependency-free Node build until its functional requirements call for a client framework.
- Run package-free executable assertions for the initial scaffold so CI can exercise the projects without external test packages. Replace or extend these with a standard test framework when application behavior warrants unit tests and NuGet access is available.

## 2026-10-01 — TASK-002 local Core authentication

- Bind Core to loopback HTTP by default. Operators can configure a different URL or HTTPS certificate through standard ASP.NET Core configuration.
- Store the first administrator in a local SQLite database. Bootstrap credentials come only from environment variables on the first start; later starts never replace that account. Hash passwords with ASP.NET Core Identity PBKDF2 at 310,000 iterations.
- Use ASP.NET Core bearer authentication with a 15-minute token lifetime and process-local Data Protection keys. Tokens become invalid when Core restarts, and no signing or protection key is written to disk. Login attempts are rate-limited.
- Keep TASK-002 integration checks in the existing executable Core test project. They exercise a real loopback server and temporary SQLite database without adding a test framework dependency.

## 2026-10-01 — TASK-003 provisional heartbeat

- Host the .NET Agent with `AddWindowsService` so one executable runs under the Windows Service Control Manager and as a console process for development. Persist a generated installation ID locally; it identifies an installation but does not authenticate it.
- Until TASK-004 provides secure enrollment, allow Agent heartbeats only to a loopback Core origin, reject non-loopback heartbeat clients in Core, rate-limit the endpoint, and mark device records `unverified`. No administrator credential is stored in the Agent.
- Use Core's server clock for `last_seen` and persist the last reported `reporting` state in the existing SQLite database. A consumer must use `last_seen` to determine freshness; TASK-003 does not define an online/offline threshold.

## 2026-10-01 — TASK-004 secure enrollment

- Treat one Core installation as one organization for the current local-first architecture. Generate and persist separate Core installation and organization GUIDs. An authenticated administrator issues a random 256-bit enrollment token that expires after ten minutes; Core stores only its hash and atomically consumes it when creating an endpoint enrollment.
- Preserve the existing Devices table and installation IDs. Store the Core-assigned endpoint ID, organization/Core association, and a hash of a distinct 256-bit Agent credential in an additive EndpointEnrollments table. A repeated enrollment for the same installation returns `409` without creating a duplicate or rotating the credential.
- Authenticate enrolled heartbeats with a separate `SentinelAgent` authorization scheme and reject anonymous updates to enrolled installations. Keep anonymous heartbeat limited to unverified loopback devices for TASK-003 compatibility. LAN enrollment and heartbeat require HTTPS; the Agent additionally requires TLS 1.3, normal certificate validation, and an explicit Core certificate SHA-256 fingerprint. Full mTLS certificate lifecycle management remains outside TASK-004.
- Bind Agent enrollment state to its installation ID, Core origin, and certificate fingerprint. Protect the credential with Windows DPAPI under the service account; use private file permissions for Unix development tests. Do not log enrollment tokens or Agent credentials.

## 2026-10-01 — TASK-005 endpoint inventory

- Send inventory through a separate authenticated Agent API after an enrolled heartbeat succeeds. The Agent refreshes every six hours and retries inventory failures after five minutes without interrupting heartbeat delivery. Anonymous loopback Agents cannot submit inventory.
- Keep only the newest report per Core-assigned endpoint ID in SQLite, ordered by Agent collection time. Validate field sizes and disk counts before storing reports; keep inventory separate from heartbeat freshness and health.
- Limit Windows collection to bounded system metadata queries for host, OS, CPU, physical memory, fixed local disks, and available firewall profile settings. Represent unavailable values as unknown instead of failing the Agent. Do not inspect arbitrary file contents or launch external scanners.

## 2026-10-02 — TASK-006 device dashboard

- Serve the dependency-free dashboard from Core's origin, with the static assets copied into Core build and publish output. Keep administrator bearer tokens only in browser memory and require HTTPS for non-loopback dashboard sign-in. No cross-origin API permission is introduced.
- Expose administrator-only list and detail views of enrolled endpoints. Join enrollment identity, Core heartbeat time, and the latest inventory without returning credentials or raw database records. Unverified loopback-only devices are excluded.
- Derive connectivity health from Core's last-seen time: healthy up to two minutes, warning up to five minutes, offline thereafter, and unknown before any heartbeat. Keep last reported firewall settings separate from connectivity health and label missing inventory as unknown.

## 2026-10-02 — TASK-007 deterministic rules

- Keep detection in a dependency-free stateless rules library with individually testable rules and explicit normalized observation inputs. Preserve the inventory timestamp and typed evidence; evaluation has no clock or LLM dependency and never performs remediation.
- Extend inventory with optional bounded Windows configuration observations. Do not infer default settings, effective runtime protection, account privilege, Internet exposure, or patch compliance. Missing, unreadable, malformed, and unsupported observations remain unknown; prerequisite checks suppress inapplicable UAC/RDP findings.
- Derive current structured findings from the newest accepted persisted inventory through an administrator-only API. This avoids a second snapshot store or premature incident lifecycle schema. Older uploads cannot replace findings, newer normal state clears them, and repeat reads are deterministic. Incident history/status and risk scoring remain later tasks.

## 2026-10-02 — TASK-008 persistent alert tracking

- Persist one tracked posture alert per enrolled endpoint and rule, in the same SQLite transaction as the accepted newer inventory. Preserve first observation and update the latest positive evidence/time; bootstrap existing inventory into alert tracking idempotently. Keep TASK-007 current findings as a separate, unchanged API.
- Treat alert status as an administrator decision with durable actor/time history. Repeated positive detections preserve Open, Investigating, and Accepted; a strictly newer positive observation reopens Resolved. Normal or unknown telemetry never automatically resolves an alert. No endpoint remediation occurs when status changes.
- Use version-checked status writes to reject stale administrator edits. Require existing administrator authentication and secure transport, and bound list pagination. Extend the same-origin, memory-token dashboard with alert list/detail/status controls without adding dependencies or premature scoring/correlation.

## 2026-10-02 — TASK-009 explainable risk policy

- Compute endpoint risk deterministically from explicit inputs and a centralized, validated policy. Show severity, confidence weight, asset criticality, declared exposure, observation age, remediation state, and confirmed rule-group correlation contributions. Confidence is a policy weight for reported configuration rather than a calibrated probability; missing asset/exposure context is an explicit default assumption.
- Keep the status multiplier at one for Investigating and Accepted because those states provide no remediation evidence; Resolved sets it to zero until a newer positive observation reopens it. Age multipliers stay positive, while explicitly configured confidence discounts and integer rounding can yield a zero displayed score. Correlation uses distinct supported rule groups confirmed in the same latest snapshot within the policy window, excluding older or contradictory historical evidence.
- Calculate scores on request from a consistent SQLite read snapshot instead of persisting a second score state. Apply an explained endpoint score cap and use the highest endpoint score for organization prioritization, with observation coverage alongside it. Unknown telemetry and a zero score never establish safety. Operator configuration provides per-endpoint criticality/exposure without introducing new remediation or AI workflows.

## 2026-10-02 — TASK-010 signed subscription leases

- Use built-in ECDSA P-256/SHA-256 (ES256) as the asymmetric equivalent permitted by TASK-010 and the product specification. A versioned compact JWS signs both the protected algorithm/key ID header and the bounded lease payload. Verification accepts one fixed algorithm, P-256 public keys, and fixed-length P1363 signatures; no algorithm negotiation or new crypto dependency is introduced.
- Keep the private-key signer in the separate cloud License API. Core references a public-only verification library and locally provisioned SPKI public PEM trust anchors, including overlapping key IDs for rotation. Bind leases to the organization and Core installation GUIDs already persisted by enrollment; no new identity or database migration is introduced.
- For the initial development issuer, map a high-entropy activation credential hash to server-side configured entitlements. Clients request only their bound identity, never the plan, feature list, limit, or duration. Issue exactly seven days from server time and enforce the same maximum duration and exact expiration boundary locally. Generate development keys automatically outside tracked source; tests use generated temporary keys and synthetic identities.
- Expose authenticated, bounded, uncached local verification and distinguish invalid, future-issued, identity-mismatched, valid, and expired leases. Only verified, identity-matching valid/expired claims are returned. Keep renewal, persistence, clock rollback protection, grace/Safe Mode, billing, and license enforcement outside TASK-010; a missing or invalid lease does not stop monitoring.
