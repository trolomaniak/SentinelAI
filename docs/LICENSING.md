# Licensing lifecycle

TASK-011 keeps licensing independent of the local security baseline. Core alone fetches and verifies signed leases; the cloud signer and its private key stay in the separate License API. Agent telemetry, local detection, all tracked alerts, incident access, alert status changes, and risk reads remain available in every licensing state. TASK-012 introduces the optional cloud AI explanation feature, requiring signed `cloud_ai` permission and currently enabled premium capabilities. Safe Mode withholds that cloud request while local security APIs continue.

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

Configure URL, credential path, and at least one public trust key together. Empty renewal configuration makes no network requests. The client posts only Core's persisted organization/installation IDs to `/api/licenses/lease`, sends the separate activation bearer only to the fixed issuer, disables redirects, and retains normal TLS certificate verification. Responses are size-bounded and must contain exactly one signed lease. Credential files must be private to the account on Unix; operators must provision account-restricted ACLs on Windows. Never put credential values or private signing keys in Core configuration, logs, APIs, Desktop, or source control.

## Persistence and time

An additive `LicenseState` singleton table in Core's existing private SQLite database stores the signed lease, signed last-successful-validation time, effective UTC high-water, and last outcome. The signature is rechecked against the current trust anchors and Core identity when status is read. Existing identity/enrollment and incident tables are preserved.

Effective time is the maximum of local UTC, persisted effective UTC, and monotonic elapsed time while Core is running. Only authenticated signed server issuance time can advance trusted time; unsigned responses never influence it. Backward changes beyond one minute are reported, and effective time never moves backward. Replaying a lease never substitutes its local receipt time for signed issuance.

This protects against obvious rollback, including restart after expiry. It is not tamper-proof against a privileged local account deleting/replacing the database, and it cannot measure time while the machine is off with a rolled-back clock. A large erroneous forward wall-clock jump is retained conservatively; correcting UTC does not automatically lower the persisted floor and permit an old signed lease. Local monitoring continues in these cases. No destructive reset, automatic trust discovery, billing, new lease wire format, or vendor-controlled monitoring shutoff is introduced.

## Administrator APIs

All new routes require Core administrator authentication, HTTPS outside loopback, and `Cache-Control: no-store`:

- `GET /api/admin/license` reports the explicit state, effective time, signed validation/expiry times, rollback flag, permitted capabilities and enabled optional features. It never returns the activation credential or stored lease.
- `POST /api/admin/license/renew` accepts no body or query overrides and attempts validation against the configured issuer. It is rate limited. An unconfigured client returns `503`; a completed failed attempt returns the resulting GRACE/SAFE_MODE status.
- `GET /api/admin/incidents/export?offset=0&limit=50` exports recent tracked incidents in `sentinelai-emergency-incidents-v1` JSON, with evidence, recommendations, and the latest 100 history entries per incident. Pages are ordered by newest observation, use one consistent SQLite read snapshot, and permit limits 1–200; `total` and pagination metadata allow retrieving additional pages. Export is available regardless of license state and contains no enrollment credentials or password hashes.

## Pilot license key (MVP-3)

The free pilot uses a separate, offline key. It changes nothing above: the lease, its routes, `cloud/license-api` and every local security function stay as they are, and a pilot key grants no lease, premium feature or `cloud_ai` permission. Monitoring never depends on it.

- **Format.** A compact signed text like the lease: `base64url(header).base64url(payload).base64url(signature)`, ES256 with a fixed 64-byte P1363 signature, at most 1024 characters. Header: exactly `alg` `ES256`, `typ` `sentinelai-pilot-v1` and `kid`. Payload: exactly `version` 1, `plan` `pilot`, `customer` (1–64 characters, no surrounding spaces or control characters), `issued_at` and `expires_at` (explicit UTC, whole seconds, at most 365 days apart). No endpoint limit and no installation binding, so a key can be sent before Setup runs. Duplicate or unknown properties, another algorithm or type, an unknown key ID and a wrong signature are all simply "invalid" (`shared/crypto/PilotLicense.cs`).
- **Issuer** (`tools/pilot-license`, on the owner's computer only): `keygen --directory <new folder> --key-id <id>` creates an owner-only folder (Unix 0700, or a protected Windows DACL for the current user) with `<id>.private.pem` and `<id>.public.pem` (0600), refuses an existing folder and any folder inside a repository, and prints only the two paths. `issue --private-key <path> --key-id <id> --customer "<name>" --days <1-365> [--start yyyy-mm-dd]` prints the key; the start defaults to today (UTC midnight). Typical durations are 30, 60 and 90 days. `issue` refuses a private key that others can read (Unix group/other bits; on Windows any reader besides the current user, SYSTEM and Administrators). `check --public-key <path>` accepts exactly what Core and Setup accept, and Setup packaging runs it for every pilot public key.
- **Trust.** Pilot public keys are build-time inputs of the full Setup, by key ID, separate from update and lease keys: `publish-setup-windows.ps1 -PilotLicensePublicKey <id>=<path> [...]` (at most 32) with `-PilotContactCompany/-Email/-Phone/-Website`. They are deployed in the signed Core package as `pilot-license/trust/<id>.pem` and `pilot-license/contact.json` next to `SentinelAI.Core.exe`, and the same public keys go to Setup. Core refuses to start on a private key, a non-PEM file or invalid contact details there. A build without pilot keys has no pilot licensing (`unavailable`). Tests use keys generated for each run; no private key is in the repository or any artifact.
- **Core.** `GET /api/admin/license/pilot` and `POST /api/admin/license/pilot` with `{"key":"..."}` (administrator, HTTPS outside loopback, `no-store`; POST at most 4 KiB and rate limited like verification). The key is verified offline when entered and whenever status is read, at the license effective time, under the same lock as lease state, so turning the clock back cannot extend a pilot or admit an expired key. A key valid now or starting later replaces the stored one (`200`); a malformed or untrusted key is `400`, an expired one `409`, and a build without pilot keys `404`. The key is stored additively in the `LicenseState` row (`PilotKey` column; existing databases gain it on start). States: `unavailable`, `none`, `invalid`, `scheduled`, `active`, `ending` (7 days or less left: "Pilot ends in N days — contact us") and `ended`, with customer, start, expiry, days left (rounded up) and the build's contact details. Anything that fails verification is "no valid pilot key".
- **Ended.** All monitoring continues. Desktop shows a persistent notice with the contact details and, at the bottom, **Uninstall SentinelAI**, which opens the installed Setup with `/uninstall` and then closes Desktop (Setup does not uninstall beside a running Desktop): data is kept by default and removed only after typing `DELETE`. The warning and the notice can be hidden until sign-out. Desktop rereads the status at sign-in, on navigation and hourly, and keeps the last reported state if a read fails.
- **No network.** Pilot licensing has no server, network call or telemetry.

`POST /api/admin/license/verify` remains stateless local verification and does not renew or mutate licensing state. Integration tests use generated temporary keys and synthetic telemetry to simulate issuer outage beyond seven days, recovery, replay, restart and rollback, and actual Safe Mode monitoring/export.
