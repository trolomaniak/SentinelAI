# Expanded pilot 01 — Encrypted backup and recovery

The owner approved the expanded pilot plan and sequential implementation on 2026-11-15, reaffirmed on 2026-11-16. This task is first in that sequence; it implements the backup/recovery portion of TASK-040 without claiming the later global audit feature is complete.

## Scope

- Consistent online SQLite snapshots, encrypted authenticated archives and a separately saved password-encrypted recovery key.
- Windows-protected local key storage; unattended schedules, bounded retention and visible success/failure/interrupted states.
- Authenticated bounded create/status/verify/export operations. Core writes only its fixed protected backup directory.
- Native Settings controls and recovery available when Core cannot start. Passwords and keys must not be retained in view models, logs, arguments, environment variables or unencrypted temporary files.
- Full archive/package/database verification, a preview of the restore point and an explicit restore confirmation.
- Elevated offline replacement of the fixed owned database, with service ownership validation, journal, safety copy, health verification, rollback and cleanup.
- Same-machine recovery retains the current installation configuration, certificate and local Agent state. Fresh-machine migration preserves historical organization data, uses the new machine's installation/certificate, preserves its newly enrolled local Agent and requires remote Agents to join the new trust explicitly.

## Acceptance

- Wrong keys/passwords, tampering, truncation, reordered frames, trailing bytes, unsupported packages, traversal, links and mismatched identities are refused.
- Backups made during writes contain an intact consistent database. Failed work never destroys the last successful backup.
- Schedules and retention survive restart; an interrupted job is reported and cleaned up conservatively.
- A saved recovery key is required before schedules can be enabled. Cancelling export or losing a configuration race cannot overwrite the original recovery key.
- Restore is tested against changed and damaged databases; unused enrollment codes are invalidated and post-backup revocations are preserved where current state is readable.
- Native Windows tests verify service privilege boundaries, protected storage, backup/export/verify, actual stopped-service recovery and installation maintenance.
- Documentation distinguishes a local retained copy from an exported copy surviving disk/machine loss, and describes same-host recovery versus migration.
- Build, relevant regressions and native CI pass; `.agent/STATUS.md` records evidence.

## Following work

Continue the owner-approved sequence in [the expanded pilot plan](../../docs/EXPANDED-PILOT.pl.md). Each feature gets its own reviewable implementation and verification before the next feature starts.
