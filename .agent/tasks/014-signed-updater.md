TASK-014 — Signed Update Pipeline

Objective

Implement a secure foundation for SentinelAI updates.

Requirements

Create an update manifest containing at minimum:

version,

artifact identifier/URL,

cryptographic hash,

signature,

release channel.

Implement verification before installation.

Support initial channels:

Stable

Pilot/Beta

Security Requirements

update must not be accepted without valid signature.

artifact hash must be verified.

malformed manifest must fail closed.

development/test signing keys must be separate from production.

private production keys must never enter the repository.

Reliability

Provide a rollback strategy if an update fails or the updated service does not become healthy.

Definition of Done

signed test manifest can be created.

client verifies manifest.

client verifies package hash.

tampered package is rejected.

invalid signature is rejected.

rollback behavior has automated coverage where practical.

.agent/STATUS.md is updated.
