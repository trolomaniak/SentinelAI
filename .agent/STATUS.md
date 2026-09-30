# Development status

## Completed

- TASK-001 implementation: .NET solution, Agent and Core executables, shared contracts library, two scaffold test projects, dashboard shell, repository settings, build/test scripts, and GitHub Actions CI.
- Local `./scripts/build.sh` and `./scripts/test.sh` passed. The Core host also started and returned HTTP 404 at `/`, as expected before TASK-002 adds endpoints.
- The review branch `codex/task-001-monorepo-ci` is pushed to GitHub.

## Current architecture

- Agent is a .NET 10 console entry point with no service behavior yet.
- Core is an empty ASP.NET Core host with no API endpoints yet.
- Agent and Core reference the shared contracts project; it contains no transport models yet.
- Dashboard is a static HTML/CSS shell with a dependency-free Node build.
- Two executable .NET test projects check the initial Agent entry point and Core host wiring. CI runs them through `scripts/test.sh`.

## Important decisions

See `.agent/DECISIONS.md` for the minimal initial toolchain and test approach.

## Known issues

- GitHub Actions results and Pull Request creation remain unverified because this cloud environment denies HTTPS access to `api.github.com`. The workflow has been pushed and should run on the branch.
- The initial test projects use executable assertions and are not discoverable by `dotnet test`. A standard test framework can be added when behavior needs broader unit coverage and NuGet access is available.
- Windows Service behavior requires a later task and a Windows validation environment.

## Next task

TASK-002 — Core API and Local Authentication, after TASK-001 CI is confirmed.

## Last verified commit

`088db6ec30f74e1c47277264cf2d2da68d35ea11` — local build and scaffold tests passed; GitHub Actions result pending.
