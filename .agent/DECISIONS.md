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
