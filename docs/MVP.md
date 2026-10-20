# Pilot MVP

The pilot MVP lets small companies try SentinelAI for free and give feedback. It is distributed directly by the owner, for example after a first contact by e-mail. The owner defined this scope on 2026-10-19. It is delivered by tasks MVP-1 to MVP-4 in `.agent/tasks/`, before TASK-030.

## Deployment model

- One always-on Windows computer in the company runs the central installation: Core, Desktop, Updater and its own Agent.
- Every other company computer runs only the Agent and reports to the central Core over the local network.
- Data stays inside the company. No customer telemetry is sent to the owner.
- Supported: Windows 10 22H2 x64 and Windows 11 x64, for both the central computer and the Agents. Linux is later work.

## Pilot scope

| Area | Pilot behavior | Task |
| --- | --- | --- |
| Central Core | HTTPS listener for Agents on the local network, with Core's own certificate and a Windows Firewall rule for the Domain/Private profiles and the local subnet only | MVP-1 |
| Agent connection | TLS 1.3, or TLS 1.2 only when Windows 10 lacks TLS 1.3, with AEAD cipher suites only; Agents trust Core only by the exact certificate fingerprint delivered with the enrollment code | MVP-1 |
| Adding computers | One-use enrollment codes created in Desktop; a separate Agent installer, interactive or silent with a code file | MVP-2 |
| Removing | Uninstall entries in Windows Apps for the Agent and the central installation; "Remove computer" in Desktop | MVP-2 |
| License | Free signed pilot key, verified offline, valid for a chosen 30–90 days, with no endpoint limit and no license server | MVP-3 |
| Pilot end | Monitoring continues; Desktop asks the company to get in touch and offers uninstallation | MVP-3 |
| Documentation | For the business and for IT, in Polish and English, plus a release script with checksums and a two-computer test checklist | MVP-4 |

## Central Core (MVP-1)

- Setup installs the central computer with local-network access enabled by default; **Allow Agents on other computers in this local network to connect** can be cleared for a local-only installation.
- Core serves Agents on HTTPS port **5443** with its own certificate (ECDSA P-256, 10 years, the computer's DNS name and FQDN) in `LocalMachine\My`; its private key is usable only by Core's service account, SYSTEM and Administrators. The local Desktop keeps `http://127.0.0.1:5000`.
- The local-network listener serves only the Agent routes (enrollment, heartbeat, inventory and posture, security events, endpoint telemetry); administrator, authentication and Desktop routes are refused there.
- TLS: TLS 1.3 whenever both computers support it, TLS 1.2 only when one is Windows 10, and on TLS 1.2 only ECDHE with AES-GCM; Core aborts any other negotiated connection.
- Trust: an Agent trusts Core only by the exact SHA-256 fingerprint of its certificate; no certificate authority is installed anywhere. Desktop Settings shows the addresses, port and fingerprint; MVP-2's enrollment codes carry them.
- Windows Firewall: one owned inbound rule for Core's program, TCP 5443, from the local subnet on the Domain and Private profiles only. A network classified as **Public** blocks Agents; set the company network to **Private**.
- Upgrade and repair keep the certificate (Agents pin it) and restore the firewall rule; uninstall removes the rule; confirmed data removal deletes the certificate and key.
- Details, the manual Windows 10 check and limitations: [Setup](SETUP.md#central-computer-and-the-local-network).

## Decisions and known limitations

- The installers are not code-signed for the pilot because of the cost. Windows SmartScreen warns on first run. Smart App Control or a company antivirus/EDR may block unsigned programs. Do not attach the installer to e-mails: link to a download page over HTTPS that publishes SHA-256 checksums, or install together with the company.
- Vulnerability and patch management (TASK-030) waits for pilot feedback.
- Desktop runs only on the central computer. The local-network listener serves Agent routes only.
- The existing seven-day lease licensing and `cloud/license-api` remain for later commercial licensing (TASK-041).
- The pilot is not independently security-audited (TASK-043) and makes no compliance claims (TASK-044).
