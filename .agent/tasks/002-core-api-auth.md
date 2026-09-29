TASK-002 — Core API and Local Authentication

Objective

Create the first runnable SentinelAI Core service.

Requirements

Implement:

ASP.NET Core application.

local HTTP/HTTPS API.

health endpoint.

SQLite database initialization.

basic local administrator account.

administrator login.

secure password storage.

authenticated API endpoint proving authentication works.

application configuration.

structured logging.

Suggested health endpoint:

GET /api/health

Security Requirements

Never store plaintext passwords.

Do not hardcode credentials.

Authentication failures must not expose sensitive information.

Use secure defaults.

Do not implement cloud authentication.

Out of Scope

Do not implement:

Endpoint enrollment.

RBAC beyond initial administrator functionality.

licensing.

cloud connectivity.

AI.

security rules.

Definition of Done

Core starts locally.

SQLite database is created automatically.

Administrator can authenticate.

Protected endpoint rejects unauthenticated requests.

Health endpoint works.

Unit/integration tests exist.

Relevant tests pass.

.agent/STATUS.md is updated.

Relevant Documentation

docs/ARCHITECTURE.md

docs/SECURITY.md

docs/MVP.md
