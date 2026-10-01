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
