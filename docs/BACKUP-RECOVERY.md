# Encrypted Core backups and recovery

The Windows pilot can create consistent SQLite backups while monitoring continues. **Settings → Encrypted backups and recovery** provides key setup, scheduling, creation, verification and export. Recovery is also available from the signed-out screen when Core cannot start.

## First setup

1. Enter and repeat a recovery password of 12–1,024 characters.
2. Choose **Save recovery key and configure backups** and save the encrypted `.sakey` file. Existing recovery key files are never overwritten. Cancelling the picker leaves Core unconfigured.
3. Keep this file and its password available outside the central computer. The file is encrypted; it is still recovery material and should have controlled access.
4. Explicitly save the desired schedule and retention. The defaults are disabled, every 24 hours, and seven copies. The supported interval is 1–168 hours and retention is 1–30 copies.
5. Create a manual backup, wait for its completed result and export its `.sab` archive to separate storage.

Recovery requires the archive, its matching recovery key file and the password. Retained copies on the central disk protect against logical data loss; an exported copy is needed to survive loss of that disk or computer. Scheduled retention does not manage the operator's exported copies.

Core stores its local recovery key using Windows machine protection and private installation ACLs. Passwords are not sent to Core's backup HTTP APIs or retained in configuration. The separately encrypted recovery key is portable. Backups use authenticated streaming encryption; archive metadata, order, lengths and completion are checked during decryption. This recovery key is separate from the owner's update-signing key and the LAN certificate.

## Creation, scheduling and verification

SQLite's backup API creates an isolated consistent database snapshot; live database files and their journals are not copied directly. The package contains only `manifest.json`, `configuration.json` and `core.db`. The configuration entry is a descriptive connection reference. Trusted installed configuration, ownership receipts, executables and certificate private keys are not replayed from an archive.

Each newly created archive is decrypted, checked against its manifest hashes and inspected as a Core database before publication. **Verify selected backup** repeats these checks. The list records the verification time; a previously verified row is not a continuous guarantee against later media corruption. Export checks the exact encrypted size and SHA-256 before publishing the chosen destination file.

Only one create/verify operation runs at a time. An overdue schedule catches up once rather than replaying every missed interval. A failed replacement must preserve a verified retained copy. Interrupted work is reported and cleaned up conservatively; completed authenticated copies can be reconciled with their metadata after recovery. Missing historical files are shown separately. Unknown or damaged files are not silently deleted.

The plaintext package limit is 1 GiB, including its database and metadata. Creation requires working free space of at least six times the snapshot size plus 64 MiB, in addition to retained archives and the live database. A size, space or permission failure is reported. The installed fixed storage directory is `%ProgramData%\SentinelAI\Core\backups`; Settings never grants Core access to an arbitrary export path.

## Recover on the same computer

1. Retain the archive and recovery file in readable storage. Install or repair a compatible trusted SentinelAI release if its code is damaged. Keep the existing data and certificate.
2. Choose **Open Core recovery** in Settings or on the signed-out screen and approve Windows administrator elevation.
3. Select the archive and `.sakey`, enter the password and verify the restore point. Preview checks the complete encrypted package and database before stopping Core. It shows the organization, time and record counts.
4. Review the rollback of business data: observations, decisions, settings and enrollments newer than the restore point may be lost. An unreadable current database cannot supply its later security changes.
5. Enter the password again and type `RESTORE`. The recovery process validates ownership, stops its own Core service, retains the current database, replaces only the permitted data and starts Core.
6. Successful health and identity checks commit the operation. Sign in with the administrator account contained in the restored database. Review backup settings and explicitly re-enable the schedule.

Unused enrollment codes are invalidated. Where healthy current state is available, later Agent revocations, license-clock protections and operational backup records are retained rather than silently rolled back. Configuration, service registration, certificate/pin and local Agent DPAPI state remain local. Agents enrolled after the restore point may need operator recovery.

Recovery has a journal and safety copy. If an operation is unfinished, reopen recovery, refresh its status and review the identified restore point. **Undo unfinished restore** requires the corresponding confirmation word and restores the previous data. Do not delete the journal, safety copy, SQLite sidecars or identity anchor manually. A failed health check attempts rollback; a corrupt pre-existing database may remain stopped after rollback and still require recovery.

## Migrate after loss of the central computer

1. Prepare a fresh trusted central installation for the same organization on the new computer. Use a compatible release and the owner's normal public trust/pilot-key configuration.
2. Run migration before enrolling remote Agents, configuring another backup key or beginning business work on that installation. The target must be newly created within 24 hours, with one administrator, at most its own local Agent and no existing business decisions or backup configuration.
3. Open recovery, choose migration, provide the exported archive and recovery file, and verify the restore point.
4. Re-enter the password and type `MIGRATE`. This explicitly replaces the new installation's database with the recovered organization.
5. After successful recovery, sign in using the restored account. The new machine retains its own configuration and LAN certificate. Its newly enrolled local Agent is preserved and rebound to the recovered organization.
6. Reinstall remote Agents using new enrollment codes and the new certificate pin. Old remote enrollments are retired; historical observations remain associated with their previous endpoint records. Review those records when comparing reports.

The former LAN certificate uses a non-exportable Windows key. Copying a database does not reproduce its trust on a different machine. Recovery does not automatically repin remote Agents or copy their DPAPI secrets. Keep the previous machine off the network during migration to avoid running two active Cores for the same recovered organization.

## Interfaces and security boundaries

Backup APIs require the existing administrator session on the administration listener and use `Cache-Control: no-store`. They are unavailable on the Agent-only LAN listener.

| Route | Purpose |
| --- | --- |
| `GET /api/admin/backups` | Policy, availability, current operation and bounded archive metadata |
| `PUT /api/admin/backups/key` | Initial exact 32-byte key with the current `If-Match` policy version |
| `PUT /api/admin/backups/policy` | Explicit version-checked schedule/retention change |
| `POST /api/admin/backups` | Start one create operation; poll status for completion |
| `POST /api/admin/backups/{id}/verify` | Start complete read-only archive verification |
| `GET /api/admin/backups/{id}/download` | Stream that retained encrypted archive |

The local recovery worker accepts bounded input through private standard input, not a password argument or an HTTP restore endpoint. Production recovery requires an elevated Windows administrator, an owned registered Core service, matching protected configuration/executable receipts and validated local paths. A restored archive cannot choose an output path, run code, replace installation proofs or expand service permissions.

Portable regressions cover cryptography, strict packages, SQLite consistency, authentication, scheduling, retention, recovery and fault injection. Native Windows acceptance additionally exercises actual SCM transitions, protected storage and certificate/ACL preservation. These tests use synthetic state only.
