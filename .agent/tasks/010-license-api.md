TASK-010 — License API and Signed Lease

Objective

Implement the first SentinelAI subscription license validation mechanism.

Architecture

Cloud License API issues signed lease tokens.

SentinelAI Core verifies leases locally.

Requirements

Lease must contain at minimum:

organization ID,

installation ID,

plan,

endpoint limit,

enabled features,

issue time,

full-mode expiration,

digital signature.

Use Ed25519 or an equivalent approved asymmetric signing mechanism.

Security Requirements

private signing key exists only in server-side development/test infrastructure.

Core contains only public verification key material.

never commit production private keys.

tests must use generated development keys.

invalid or modified leases must fail verification.

expired lease state must be detectable.

Definition of Done

License API can issue a signed lease.

Core can validate the signature locally.

modified lease fails validation.

expired lease is detected.

test key generation is automated.

tests exist for signing/verification.

.agent/STATUS.md is updated.
