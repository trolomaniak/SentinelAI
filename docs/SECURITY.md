# Implemented security boundaries

This records the current pilot's controls and limits, not an independent audit or compliance certification. See [architecture](ARCHITECTURE.md), [Setup](SETUP.md) and the individual contracts for implementation details.

## Authority and local state

- Core owns administrator authentication, enrollment, SQLite state, deterministic detections and scores. Desktop is a separately authenticated local client and does not control service lifetime.
- Core runs as its limited virtual service account; Agent runs as LocalService with its own service SID for the configured Windows event access. Protected Program Files code is separate from ProgramData state. Administrators and SYSTEM control installation and maintenance; these controls do not protect against a malicious local administrator.
- Agent enrollment credentials use current-user Windows DPAPI under the service account. Changing that account is not an enrollment migration. Enrollment codes are secrets, displayed once; Core retains token hashes and refuses expired, used or revoked codes.
- Installation and update ownership receipts, configuration, signing trust and update transactions are protected from ordinary users. Maintenance refuses ambiguous ownership and unsafe filesystem links instead of adopting unknown installations.

## Network trust

- Desktop uses the trusted local Core origin. The local-network HTTPS listener exposes Agent routes and refuses administrator/Desktop routes.
- Agents trust the central Core by the exact certificate SHA-256 fingerprint provided with the enrollment code. No public certificate authority is installed for this purpose.
- TLS 1.3 is used where supported; the documented Windows 10 fallback permits TLS 1.2 with the restricted AEAD policy. The owned firewall rule permits only the Domain/Private profiles and local subnet. See [network deployment](SETUP.md#central-computer-and-the-local-network).

## Update trust and recovery

Signed manifests bind the artifact, version, environment, channel, hash and length to explicitly provisioned public keys. Package verification and bounded extraction precede service control. Private signing keys belong outside repositories and are not distributed to customer installations.

Code replacement uses the existing transactional updater, health checks and rollback with state outside the code directories. Interrupted transaction state is retained for recovery. The Agent's ownership receipt is published by an atomic adjacent replacement so an interrupted write leaves the previous complete document available for reconciliation.

Pilot package signatures are separate from Authenticode. The pilot uses the owner's development-environment update trust by explicit product decision; SmartScreen or application-control policy may still block an unsigned installer. See [updates](UPDATES.md).

## Data and optional services

Inventory, minimized event observations, incidents and business risks are stored locally. The event catalog and endpoint telemetry contracts specify which fields are collected, bounded and retained; raw logs, arbitrary files and credential values are not included in cloud AI context. See [security events](SECURITY-EVENTS.md) and [endpoint telemetry](ENDPOINT-TELEMETRY.md).

Optional notification delivery is disabled by default and requires explicit administrator configuration. Public HTTPS webhooks and authenticated SMTP STARTTLS send a fixed minimized payload; destination checks, credential protection, retry semantics and recovery suppression are described in [notifications](NOTIFICATIONS.md). The local notification center does not require external delivery.

Optional cloud explanations require configuration, entitlement, session consent and an explicit request. Core sends only the supported minimized alert context; provider credentials stay in the gateway. Optional update checks contact the configured owner server when enabled. These are separate from local monitoring; see [AI configuration and privacy](AI.md).

Central uninstall retains security history and configuration by default; destructive removal requires the existing explicit confirmation flow. Agent uninstall removes that computer's local Agent installation and enrollment state, while its retained history stays in Core. Reports and diagnostic artifacts may still contain customer identifiers or security findings and should be handled as customer data.

## Interpretation and validation

Unknown, stale, unavailable or denied sources do not establish safety. Findings are evidence-based observations rather than proof of compromise or compliance. There is no automatic remediation executor.

Portable tests, native Windows CI and the [release checklist](pilot/PILOT-TEST-CHECKLIST.md) have distinct scopes. The pilot has no recorded independent security audit or penetration-test certification; broader hardening work remains in the development backlog.
