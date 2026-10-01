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

## 2026-10-01 — Standalone Windows Agent package

- Package the Agent as a self-contained, single-file `win-x64` user-mode EXE. Bundle native runtime files into the EXE for extraction at launch, and leave trimming disabled to preserve future Agent compatibility.
- Verify the published EXE on a Windows CI runner and upload it as a development artifact. Windows Service hosting and heartbeat remain TASK-003; a signed installer remains TASK-015.
