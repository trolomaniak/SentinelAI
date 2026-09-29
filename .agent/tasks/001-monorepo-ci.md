TASK-001 — Monorepo and CI

Objective

Create the initial SentinelAI monorepo structure and continuous integration pipeline.

Context

SentinelAI is a Windows-first, local-first cybersecurity platform.

Target repository structure:

agent/

core/

dashboard/

cloud/license-api/

cloud/ai-gateway/

cloud/update-service/

shared/contracts/

shared/crypto/

rules/

docs/

tests/

deploy/

Requirements

Create:

.NET solution for backend components.

Initial projects for Agent and Core.

Shared contracts project.

Basic test projects.

Dashboard project skeleton.

Repository-wide .editorconfig.

.gitignore.

build scripts.

test scripts.

GitHub Actions CI.

CI must at minimum:

restore dependencies,

build backend,

run unit tests,

build frontend if present,

fail when build or tests fail.

Constraints

Do not implement application functionality yet.

Do not add unnecessary frameworks or infrastructure.

Keep the initial architecture minimal and appropriate for the MVP.

Definition of Done

Repository structure exists.

.NET solution builds successfully.

Test projects execute successfully.

Dashboard skeleton builds.

GitHub Actions workflow exists.

CI passes on the task branch.

.agent/STATUS.md is updated.

Verification

Run all available build and test commands.

Inspect git diff before completing the task.
