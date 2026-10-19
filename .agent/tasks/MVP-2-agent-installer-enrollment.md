MVP-2 — Agent Installer, Enrollment Codes and Agent Uninstall

Objective

Install, enroll and remove the Agent on the other company computers (Windows 10 22H2 x64 and Windows 11 x64) without technical knowledge, connected to the central Core from MVP-1.

Current state

- Enrollment tokens are random, stored as hashes and one-use. `POST /api/admin/enrollment-tokens` issues one 10-minute token. `EnrollmentStore.IssueTokenAsync` already accepts a lifetime, but the route does not expose it (`core/CoreHost.cs`, `core/Persistence/EnrollmentStore.cs`).
- Setup and the pilot installer hand a token to Agent through an ACL-restricted handoff file, never through process arguments (`docs/SETUP.md`, `docs/PILOT.md`).
- The full `SentinelAI-Setup.exe` is large (about 450 MB as a CI artifact) and always installs Core and Desktop.
- Neither installer registers an entry in Windows "Apps / Programs and Features".

Requirements

Desktop, "Add computers" on the Devices page:

- The administrator creates enrollment codes, 1 to 50 at a time.
- The administrator picks a validity from 1 hour to 7 days; the default is 24 hours.
- Each code is valid for one computer only.
- Unused codes are listed with their expiry and can be revoked.
- Expired, used and revoked codes are refused by Core.

Each code contains Core's local-network address and port, the certificate SHA-256 pin and one enrollment token.

- The format is versioned, carries a checksum that catches copy errors, and can be pasted as text or saved as a small `.sentinelai-enroll` file.
- The address is the central computer's DNS name when it resolves, otherwise its IPv4 address. The administrator may choose. The UI recommends a fixed IP address or the name.
- The code is a secret: the UI says so, and Core, Desktop and the installer never log it.

New `SentinelAI-Agent-Setup.exe`:

- Installs only Agent and Updater, using the existing native wrapper, protected staging and signed package verification. It contains no Core or Desktop and must be much smaller than the full Setup.
- Interactive flow:
  1. The user pastes the code or opens the code file.
  2. Before anything is installed, the installer checks that Core is reachable and that its certificate matches the pin, and fails closed otherwise.
  3. It installs the Agent service as today (LocalService, automatic start) with `Agent:CoreUrl` and the pin.
  4. It hands the token over through the existing protected handoff.
  5. It reports success only once Core acknowledges enrollment.
- Silent mode for many computers: `SentinelAI-Agent-Setup.exe /quiet /codefile <path>`.
  - The code is read from a file, never from the command line.
  - Documented exit codes make it usable from GPO, Intune or remote scripts.
- Registers "SentinelAI Agent" in Windows Apps with a working Uninstall entry. `/uninstall /quiet` is supported.
- Uninstall stops and removes the Agent service, its code, its DPAPI-protected credential and its data directory.

Central installation and Desktop:

- The full Setup also registers "SentinelAI" in Windows Apps, with Uninstall opening its existing uninstall flow: retained data by default, removal only after the exact DELETE confirmation.
- Desktop offers "Remove computer". It revokes that endpoint's Agent credential on Core and hides the endpoint; its history is kept.

The co-located Agent on the central computer keeps working as today.

Constraints

- Tokens stay one-use and hashed at rest, live at most 7 days, and are never logged or passed through process arguments or the environment.
- No administrator credential ever reaches an endpoint.
- The Agent package signature verification is unchanged.
- A pin mismatch or unreachable Core changes nothing on the endpoint.
- Tests use synthetic data only.

Definition of Done

- Windows CI builds `SentinelAI-Agent-Setup.exe`. On the same runner as an MVP-1 central installation:
  - Codes created through Core's administrator API let the silent Agent installer enroll over the non-loopback address, and the Agent then reports telemetry.
  - A wrong pin, an expired code, a used code and a revoked code are each refused before any service change.
  - Uninstall removes the service, code, credential and Apps entry.
- Portable tests cover the code format: round-trip, version, checksum, tampering and limits.
- Core tests cover batch issuance, revocation, the expiry bounds and "Remove computer".
- The native WPF tests cover "Add computers" and "Remove computer".
- `docs/SETUP.md` and `docs/MVP.md` are updated, and `.agent/STATUS.md` is updated.

Development sequence

MVP-1 → MVP-2 → MVP-3 → MVP-4, before TASK-030. One scoped branch and one Pull Request; do not merge to main.
