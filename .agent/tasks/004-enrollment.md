TASK-004 — Secure Endpoint Enrollment

Objective

Allow a new SentinelAI Endpoint Agent to be securely associated with a SentinelAI Core installation.

Requirements

Implement an enrollment flow containing:

one-time or short-lived enrollment credential.

unique endpoint identifier.

organization/installation association.

explicit Core-side enrollment endpoint.

Agent-side enrollment client.

persistence of enrollment state.

rejection of invalid or expired enrollment attempts.

Establish the foundation for authenticated Agent ↔ Core communication.

Security Requirements

Do not rely on hostname as identity.

Enrollment tokens must not remain usable indefinitely.

Do not expose secrets in logs.

Design for future certificate-based or mTLS authentication.

Re-enrollment must not silently create duplicate endpoints.

Out of Scope

Do not implement full enterprise PKI or certificate lifecycle management unless required for the minimal secure design.

Definition of Done

Unenrolled Agent can enroll with valid credentials.

Invalid credential is rejected.

Core assigns/stores endpoint identity.

Agent persists its assigned identity securely.

repeated enrollment behaves predictably.

integration tests cover success and failure.

.agent/STATUS.md is updated.

Relevant Documentation

docs/ARCHITECTURE.md

docs/SECURITY.md
