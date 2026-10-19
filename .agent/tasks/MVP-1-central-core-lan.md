MVP-1 — Central Core on the Local Network

Objective

Let one always-on Windows computer in a company run Core for the whole company, so Agents on the other computers in the same local network can enroll and report to it securely. This is the deployment model of the pilot MVP described in `docs/MVP.md`.

Current state

- `SentinelAI-Setup.exe` installs Core, Agent, Desktop and Updater together on one machine. Core listens only on `http://127.0.0.1:5000` (`core/CoreHost.cs`), and Setup provisions no remote listener, TLS certificate or firewall rule (`docs/SETUP.md`).
- Core already accepts an explicit URL or Kestrel configuration and refuses non-loopback plaintext (`IsLocalOrHttps` in `core/CoreHost.cs`).
- Agent already supports a remote Core: `Agent:CoreUrl` must be HTTPS and `Agent:CoreCertificateSha256` pins the certificate (`agent/AgentOptions.cs`). Today it enables only TLS 1.3 and requires a fully valid chain and name in addition to the pin (`CoreCertificateTrust` in `agent/AgentHost.cs`).
- Windows 10 has no TLS 1.3 in SChannel, as client or as server.

Requirements

Setup, for the central computer:

- A fresh install keeps today's complete deployment (Core, local Agent, Desktop, Updater) and also enables local-network access by default. A clearly labelled option keeps the installation local-only.
- Setup generates one TLS server certificate for Core at install time. Use ECDSA P-256 or RSA 3072, valid for 10 years. Its subject names are the computer's DNS name and FQDN.
  - The private key is usable only by Core's service account (`NT SERVICE\SentinelAICore`), SYSTEM and Administrators.
  - The key never appears in logs, process arguments, environment variables, Setup output or the repository.
  - The implementer chooses between the LocalMachine certificate store with a key ACL and a protected file under Core's ProgramData directory, and records the choice in `.agent/DECISIONS.md`.
- Core serves HTTPS for the local network on a fixed default port, 5443. The loopback HTTP listener on 5000 stays for the local Desktop.
- The local-network listener serves only the Agent routes: enrollment, heartbeat, inventory, posture, security events and endpoint telemetry. Administrator, authentication and Desktop routes are refused there. Desktop stays on the Core computer in the MVP.
- TLS policy, decided by the owner on 2026-10-19:
  - Use TLS 1.3 whenever both sides support it. Allow TLS 1.2 only when one side's Windows lacks TLS 1.3 (Windows 10). Never allow TLS 1.1 or lower.
  - On the local-network listener, Core aborts any connection whose negotiated protocol is below TLS 1.2, or whose TLS 1.2 cipher suite is not ECDHE with AES-GCM. Check this through Kestrel's `ITlsHandshakeFeature`, because Windows does not support per-application cipher suite policies.
  - Agent enables TLS 1.2 and 1.3 for a pinned remote Core; TLS 1.3 is negotiated whenever both support it.
- Certificate trust, decided by the owner on 2026-10-19: Agent trusts the Core certificate when, and only when, its exact SHA-256 (of the raw certificate, as today) matches the configured pin.
  - Chain and name errors are accepted only together with a matching pin.
  - Without a pin, the existing full validation stays.
  - Nothing is added to any Windows trusted root store.
- Windows Firewall: Setup adds one owned inbound rule for Core's local-network port.
  - Scoped to the Core program and to the LocalSubnet remote address, on the Domain and Private profiles only, never Public.
  - Uninstall removes it, and repair restores it.
- Desktop (Settings) shows the local-network addresses, the port and the certificate's SHA-256 fingerprint, so an administrator can check them. MVP-2's enrollment codes embed the same values.
- Upgrade and repair keep the certificate and key, because every Agent pins them. Uninstall with retained data keeps them; confirmed data removal deletes them.
- The central role supports Windows 10 22H2 x64 and Windows 11 x64. Windows Server 2022 or later, which CI uses, must keep working.

Constraints

- No plaintext local-network listener, no Public-profile firewall rule and no administrator route on the local-network listener.
- No change to Setup's ownership, signature, upgrade, repair, recovery or uninstall guarantees, or to retained-data behavior.
- Do not weaken validation for loopback or unpinned connections.
- Tests use synthetic data and generated certificates only.

Definition of Done

- Native Windows CI acceptance covers the following:
  - The central installation is created, and an Agent configured with the runner's own non-loopback IPv4 address and the exported pin enrolls and reports over the local-network listener.
  - Administrator routes are refused on that listener.
  - A wrong pin is refused.
  - The firewall rule exists with Domain/Private profiles and LocalSubnet, and uninstall removes it.
  - The certificate survives upgrade and repair.
- Tests cover the TLS gate (protocol and cipher-suite decision), certificate creation and its ACL, pin export, and the pin-only trust rule, including that an unpinned connection still requires full validation.
- `docs/SETUP.md`, `docs/ARCHITECTURE.md` and `docs/MVP.md` describe the central role, port, firewall rule, TLS policy and pin trust.
- A manual Windows 10 check is documented, because CI has no Windows 10 runner.
- `.agent/STATUS.md` is updated.

Development sequence

MVP track, decided by the owner on 2026-10-19 and run before TASK-030: MVP-1 → MVP-2 → MVP-3 → MVP-4.

Each task should normally result in one scoped branch and one Pull Request. Do not merge to main.
