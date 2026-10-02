# Licensing lifecycle

TASK-011 keeps licensing independent of the local security baseline. Core alone fetches and verifies signed leases; the cloud signer and its private key stay in the separate License API. Agent telemetry, local detection, all tracked alerts, incident access, alert status changes, and risk reads remain available in every licensing state. No current runtime feature is premium, so this task does not add arbitrary gates to existing APIs.

| State | Condition | Optional signed features |
| --- | --- | --- |
| FULL | Last renewal succeeded and its authenticated lease has not reached its deadline | Available |
| GRACE | Renewal failed, with an authenticated lease still inside its seven-day deadline | Available |
| SAFE_MODE | No usable lease, or the deadline has been reached | Withheld |
| RECOVERING | A renewal request is in flight | Retain underlying state's permissions; never extend a deadline |

The deadline is the earlier of signed `full_mode_until` and signed `issued_at` plus seven days. GRACE ends at the exact boundary; it does not add another seven days after lease expiry. A failed response, timeout, invalid signature/identity, expired token, or stale replay cannot refresh the deadline. A successfully authenticated current lease after an outage returns Core to FULL. The existing API has no authoritative revocation signal, so `401` is a failed renewal, not REVOKED.

## Renewal configuration

Public trust keys still use `SentinelAI:Licensing:TrustedPublicKeys:<keyId>` with absolute public SPKI PEM paths. Optional settings under `SentinelAI:Licensing:Renewal` are:

| Setting | Meaning |
| --- | --- |
| `Url` | Fixed License API origin, HTTPS except loopback HTTP for isolated development; no path, user info, query or fragment |
| `ActivationCredentialPath` | Absolute protected file containing exactly the generated 43-character activation credential, without a newline |
| `IntervalSeconds` | Retry/renewal interval, 60–86400 seconds; default 21600 (six hours) |
| `TimeoutSeconds` | Complete request/response timeout, 1–60 seconds; default 10 |
| `Automatic` | Start renewal on host startup and repeat automatically; default true; false supports controlled development tests/manual renewal |

Configure URL, credential path, and at least one public trust key together. Empty renewal configuration makes no network requests. The client posts only Core's persisted organization/installation IDs to `/api/licenses/lease`, sends the separate activation bearer only to the fixed issuer, disables redirects, and retains normal TLS certificate verification. Responses are size-bounded and must contain exactly one signed lease. Credential files must be private to the account on Unix; operators must provision account-restricted ACLs on Windows. Never put credential values or private signing keys in Core configuration, logs, APIs, dashboard, or source control.

## Persistence and time

An additive `LicenseState` singleton table in Core's existing private SQLite database stores the signed lease, signed last-successful-validation time, effective UTC high-water, and last outcome. The signature is rechecked against the current trust anchors and Core identity when status is read. Existing identity/enrollment and incident tables are preserved.

Effective time is the maximum of local UTC, persisted effective UTC, and monotonic elapsed time while Core is running. Only authenticated signed server issuance time can advance trusted time; unsigned responses never influence it. Backward changes beyond one minute are reported, and effective time never moves backward. Replaying a lease never substitutes its local receipt time for signed issuance.

This protects against obvious rollback, including restart after expiry. It is not tamper-proof against a privileged local account deleting/replacing the database, and it cannot measure time while the machine is off with a rolled-back clock. A large erroneous forward wall-clock jump is retained conservatively; correcting UTC does not automatically lower the persisted floor and permit an old signed lease. Local monitoring continues in these cases. No destructive reset, automatic trust discovery, billing, new lease wire format, or vendor-controlled monitoring shutoff is introduced.

## Administrator APIs

All new routes require Core administrator authentication, HTTPS outside loopback, and `Cache-Control: no-store`:

- `GET /api/admin/license` reports the explicit state, effective time, signed validation/expiry times, rollback flag, permitted capabilities and enabled optional features. It never returns the activation credential or stored lease.
- `POST /api/admin/license/renew` accepts no body or query overrides and attempts validation against the configured issuer. It is rate limited. An unconfigured client returns `503`; a completed failed attempt returns the resulting GRACE/SAFE_MODE status.
- `GET /api/admin/incidents/export?offset=0&limit=50` exports recent tracked incidents in `sentinelai-emergency-incidents-v1` JSON, with evidence, recommendations, and the latest 100 history entries per incident. Pages are ordered by newest observation, use one consistent SQLite read snapshot, and permit limits 1–200; `total` and pagination metadata allow retrieving additional pages. Export is available regardless of license state and contains no enrollment credentials or password hashes.

`POST /api/admin/license/verify` remains stateless local verification and does not renew or mutate licensing state. Integration tests use generated temporary keys and synthetic telemetry to simulate issuer outage beyond seven days, recovery, replay, restart and rollback, and actual Safe Mode monitoring/export.
