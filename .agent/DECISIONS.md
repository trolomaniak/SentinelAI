# Architecture decisions

## 2026-09-30 — TASK-001 foundation

- Use .NET 10 for the initial backend solution. Agent is a console executable, Core is an empty ASP.NET Core host, and both reference a shared contracts library. Windows Service hosting, endpoints, and transport models belong to later tasks.
- Keep the dashboard as static HTML/CSS with a dependency-free Node build until its functional requirements call for a client framework.
- Run package-free executable assertions for the initial scaffold so CI can exercise the projects without external test packages. Replace or extend these with a standard test framework when application behavior warrants unit tests and NuGet access is available.
