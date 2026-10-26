MVP-7 — Automatic Updates

Objective

Installed computers stay on the current version without manual reinstallation (owner decision of 2026-10-26).

Requirements

- Agents update automatically from the central Core over the existing pinned local-network channel: after the central computer is upgraded, each Agent downloads the signed Agent package from Core, verifies it with its pinned public trust key, installs it transactionally and keeps its identity and enrollment.
- Optional, off by default: Core checks the owner's update server over HTTPS and upgrades the central installation from signed packages. An administrator enables it in Desktop Settings. When off, the pilot makes no internet connection.
- Signatures, versions, channel and environment are verified exactly as Setup verifies them; a failed update rolls back and monitoring continues.
- No private key in the repository or any artifact; tests use generated development keys.

Definition of Done

- Portable tests for the update decision, verification and rollback; native Windows acceptance updates an enrolled Agent after a central upgrade.
- Documents describe automatic updates and the optional server setting.
- `.agent/STATUS.md` and `.agent/DECISIONS.md` are updated.
