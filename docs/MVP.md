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

## Decisions and known limitations

- The installers are not code-signed for the pilot because of the cost. Windows SmartScreen warns on first run. Smart App Control or a company antivirus/EDR may block unsigned programs. Do not attach the installer to e-mails: link to a download page over HTTPS that publishes SHA-256 checksums, or install together with the company.
- Vulnerability and patch management (TASK-030) waits for pilot feedback.
- Desktop runs only on the central computer. The local-network listener serves Agent routes only.
- The existing seven-day lease licensing and `cloud/license-api` remain for later commercial licensing (TASK-041).
- The pilot is not independently security-audited (TASK-043) and makes no compliance claims (TASK-044).
