MVP-7 — Automatic Updates

Objective

Installed computers stay on the current version without manual reinstallation (owner decision of 2026-10-26).

Requirements

- Agents update automatically from the central Core over the existing pinned local-network channel: after the central computer is upgraded, each Agent downloads the signed Agent package from Core, verifies it with its pinned public trust key, installs it transactionally and keeps its identity and enrollment.
- Optional, off by default: Core checks the owner's update server over HTTPS and upgrades the central installation from signed packages. An administrator enables it in Desktop Settings. When off, the pilot makes no internet connection.
- Signatures, versions, channel and environment are verified exactly as Setup verifies them; a failed update rolls back and monitoring continues.
- No private key in the repository or any artifact; tests use generated development keys.

Owner decisions (2026-10-27)

- Agents: the Agent (LocalService) downloads the signed Agent package from Core into its own data directory; a Windows scheduled task running as SYSTEM, installed by Agent Setup, copies it into a protected directory, verifies the signature with the pinned public key, a newer version, channel and environment, and installs it transactionally with rollback. Nothing unsigned runs as SYSTEM.
- Central computer: checking the owner's server is off by default (no internet connection). When an administrator enables it in Desktop Settings, automatic night-time installation is on by default; with it off, Desktop offers **Install** for an available update.
- The owner's update server address is built into the installer at build time (like the contact details); customers can only enable or disable checking.
- Delivery in two PRs: part 1 Agents from Core, part 2 the optional central update from the owner's server.

Definition of Done

- Portable tests for the update decision, verification and rollback; native Windows acceptance updates an enrolled Agent after a central upgrade.
- Documents describe automatic updates and the optional server setting.
- `.agent/STATUS.md` and `.agent/DECISIONS.md` are updated.
