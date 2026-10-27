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
| License | Free signed pilot key, verified offline, valid for a chosen 1–365 days (typically 30–90), with no endpoint limit and no license server | MVP-3 |
| Pilot end | Monitoring continues; Desktop asks the company to get in touch and offers uninstallation | MVP-3 |
| Documentation | For the business and for IT, in Polish and English, plus a release script with checksums and a two-computer test checklist | MVP-4 |
| Single delivery | The two installers are the only packages; no browser dashboard or manual installation | MVP-5 |
| Detection | Works on Windows in any display language; Setup lets the Agent read the Security log and enables the auditing of new scheduled tasks | MVP-6 |

## Central Core (MVP-1)

- Setup installs the central computer with local-network access enabled by default; **Allow Agents on other computers in this local network to connect** can be cleared for a local-only installation.
- Core serves Agents on HTTPS port **5443** with its own certificate (ECDSA P-256, 10 years, the computer's DNS name and FQDN) in `LocalMachine\My`; its private key is usable only by Core's service account, SYSTEM and Administrators. The local Desktop keeps `http://127.0.0.1:5000`.
- The local-network listener serves only the Agent routes (enrollment, heartbeat, inventory and posture, security events, endpoint telemetry); administrator, authentication and Desktop routes are refused there.
- TLS: TLS 1.3 whenever both computers support it, TLS 1.2 only when one is Windows 10, and on TLS 1.2 only ECDHE with AES-GCM; Core aborts any other negotiated connection.
- Trust: an Agent trusts Core only by the exact SHA-256 fingerprint of its certificate; no certificate authority is installed anywhere. Desktop Settings shows the addresses, port and fingerprint; MVP-2's enrollment codes carry them.
- Windows Firewall: one owned inbound rule for Core's program, TCP 5443, from the local subnet on the Domain and Private profiles only. A network classified as **Public** blocks Agents; set the company network to **Private**.
- Upgrade and repair keep the certificate (Agents pin it) and restore the firewall rule; uninstall removes the rule; confirmed data removal deletes the certificate and key.
- Details, the manual Windows 10 check and limitations: [Setup](SETUP.md#central-computer-and-the-local-network).

## Adding and removing computers (MVP-2)

- Desktop → **Devices** → **Add computers** creates 1–50 one-use enrollment codes valid for 1 hour to 7 days (default 24 hours), shown once, copied or saved as `.sentinelai-enroll` files; unused codes are listed with their expiry and can be revoked. Core refuses expired, used and revoked codes and stores only token hashes.
- A code holds Core's address (the computer name when it resolves, or a fixed IPv4 address; the administrator chooses), port, certificate pin and one token, versioned and with a checksum. It is a secret and is never logged.
- `SentinelAI-Agent-Setup.exe` installs only the Agent and Updater: paste a code or open a code file, or run `/quiet /codefile <path>`. It checks Core and the code over the pinned connection before changing anything, installs the LocalService Agent, and reports success only after Core acknowledged the enrollment; failures remove everything. Documented exit codes: [Setup](SETUP.md#agent-setup).
- Windows Apps lists **SentinelAI Agent** (Uninstall, also `/uninstall /quiet`) and **SentinelAI** (Uninstall opens the central Setup's uninstall flow, data kept by default). Each keeps an installed copy of its Setup EXE for this, which costs its file size on disk.
- **Remove computer** in Desktop revokes the computer's credential and hides it; its history is kept.
- One Agent per computer: Agent Setup refuses the central computer and any computer with an Agent already.
- Details: [Setup](SETUP.md#adding-computers-enrollment-codes-and-agent-setup).

## Pilot license (MVP-3)

- The owner creates a key pair once with `tools/pilot-license keygen` (outside every repository) and builds the full Setup with the public key and the company's contact details. For each company: `tools/pilot-license issue --customer "<company>" --days 30` prints the key to send, for example by e-mail.
- A fresh central Setup asks for the key first and checks it on the computer before installing anything; Core verifies it again and stores it. The Agent Setup needs no key.
- Desktop → **Settings** → **Pilot license** shows the customer, expiry and days left and takes a new key to extend or replace the pilot.
- From seven days before the end, Desktop shows "Pilot ends in N days — contact us" with the contact details. After the end, all monitoring continues and Desktop shows a notice with the contact details and **Uninstall SentinelAI** (Setup's uninstall flow, data kept unless DELETE is typed). Both can be hidden until sign-out.
- Details: [Licensing](LICENSING.md#pilot-license-key-mvp-3).

## Documentation and release (MVP-4)

- Customer documents in `docs/pilot/`, equivalent in Polish and English, checked against the implementation:
  - for the business: [SentinelAI dla firm](pilot/SentinelAI-dla-firm.pl.md), [SentinelAI for business](pilot/SentinelAI-for-business.en.md);
  - for IT: [przewodnik IT](pilot/SentinelAI-przewodnik-IT.pl.md), [IT guide](pilot/SentinelAI-IT-guide.en.md).
- `scripts/publish-pilot-release-windows.ps1` builds both installers and writes one new release folder, ready to upload. The business documents in it carry the contact details given to the script instead of their placeholder line:
  - inputs: the owner's update signing key (outside every repository, used only to sign and never copied), the update public key, the pilot public keys and the contact details. The pilot license private key is never an input;
  - output: `SentinelAI-Setup.exe`, `SentinelAI-Agent-Setup.exe`, the four documents and `SHA256SUMS.txt` (sha256sum format), and nothing else.
  - Windows CI runs it with development keys, and the native Setup and Agent Setup acceptance test its installers.
- [Pilot test checklist](pilot/PILOT-TEST-CHECKLIST.md) (internal): central installation, adding a second computer, an alert, a pilot key near and after its end, removing a computer, and both uninstalls, on one Windows 10 and one Windows 11 computer in one network.

## Detection on every Windows (MVP-6)

- The Agent recognizes the Service Control Manager's service-type and start-type texts (7045, 7040) in every installed display language through services.exe's own messages, so the driver-installation and protection-service rules work on Polish and every other Windows.
- Setup and Agent Setup give the Agent service its own SID (`NT SERVICE\SentinelAIAgent`) with read-only access to the Security log, and turn on success auditing of Other Object Access Events (4698). Repair and upgrade keep both; uninstall removes the access and restores the audit setting it found.
- Details: [Security event collection](SECURITY-EVENTS.md#channel-access-and-localservice).

## Decisions and known limitations

- The installers are not code-signed for the pilot because of the cost. Windows SmartScreen warns on first run. Smart App Control or a company antivirus/EDR may block unsigned programs. Do not attach the installer to e-mails: link to a download page over HTTPS that publishes SHA-256 checksums, or install together with the company.
- Vulnerability and patch management (TASK-030) waits for pilot feedback.
- Desktop runs only on the central computer. The local-network listener serves Agent routes only.
- The existing seven-day lease licensing and `cloud/license-api` remain for later commercial licensing (TASK-041).
- The pilot is not independently security-audited (TASK-043) and makes no compliance claims (TASK-044).
- Pilot releases are signed with the owner's own update key in the existing `development` trust environment (key IDs `dev-…`); Setup, the worker and the Updater accept nothing else (owner decision of 2026-10-26). A production signing environment is later work.
- Agents must be in the central computer's subnet: the firewall rule allows only the local subnet on the Domain and Private profiles.
- A domain Group Policy for audit policy or the Security log's access takes precedence over what Setup sets (MVP-6).
- Agents on other computers cannot be upgraded in place: Agent Setup refuses a computer with an Agent. A newer Agent means uninstall, a new code and removing the old device entry.
- Maintenance of the central installation (repair, upgrade, uninstall) can be run by any Windows administrator. Core's program and data folders, like every other folder Setup installs, are writable only by Administrators and SYSTEM (and Core's service where it writes its own state), never by the installing account's non-elevated programs. An installation made by an earlier Setup granted the installing account full control; the first maintenance by any administrator removes it (see `.agent/DECISIONS.md`).
- There are no automatic updates, and the user interface is in English only.
