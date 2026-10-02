# Signed lease verification

`SentinelAI.Licensing` contains the lease wire format and public verification code. It has no private-key import or signing implementation. Signing belongs exclusively to the cloud License API; tests generate disposable development keys in memory.

The token is compact JWS with a protected header containing exactly `alg: ES256`, `typ: sentinelai-lease-v1`, and `kid`. ES256 means ECDSA on named NIST P-256 with SHA-256 and a fixed 64-byte IEEE P1363 signature. The signing input is the ASCII text `base64url(header).base64url(payload)`. All three segments use canonical unpadded base64url.

The payload contains exactly these fields:

| Field | Type and constraint |
| --- | --- |
| `organization_id` | Nonempty GUID string |
| `installation_id` | Nonempty GUID string |
| `plan` | ASCII identifier, 1–64 letters/digits/underscore/hyphen |
| `endpoint_limit` | Integer from 1 through 1,000,000 |
| `enabled_features` | Up to 64 distinct identifiers with the same identifier bounds |
| `issued_at` | ISO 8601 timestamp with explicit UTC `Z` or `+00:00` |
| `full_mode_until` | Explicit UTC timestamp after issuance, at most seven days later |

Unknown or duplicate JSON fields, malformed values, unsupported algorithms or token types, noncanonical encodings, extra token segments, and tokens larger than 16 KiB fail closed. A lease does not carry a public key or key URL; `kid` only selects an explicitly configured trust anchor. Identifiers use ordinal case-sensitive comparison.

`LeaseTokenVerifier` snapshots up to 32 public trust anchors, supporting simultaneous old/new keys during rotation. Each anchor must be a sole SPKI `PUBLIC KEY` PEM for named P-256. Private PEMs, other curves or algorithms, ambiguous PEM bundles, and trailing material are rejected during configuration. The snapshot stores only public DER bytes; each verification creates an independent cryptographic instance.

Verification checks the signature before interpreting claims and binds the result to both expected IDs. `now < issued_at` is `NotYetValid`; `now >= full_mode_until` is `Expired`. No implicit clock grace is added. Only trusted `Valid` or `Expired` results return claims; expired status does not authorize full mode. Claims are returned with read-only feature collections. This task supplies issuance and validation, while renewal, offline state transitions and Safe Mode belong to later tasks.
