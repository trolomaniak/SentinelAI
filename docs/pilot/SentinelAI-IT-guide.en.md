# SentinelAI IT guide

*Pilot version. Polish version: [przewodnik IT](SentinelAI-przewodnik-IT.pl.md). For a plain-language overview see [SentinelAI for business](SentinelAI-for-business.en.md).*

## 1. Architecture

| Component | Where it runs | What it does |
| --- | --- | --- |
| **Core** | Central computer, Windows service `SentinelAICore` ("SentinelAI Local Core"), account `NT SERVICE\SentinelAICore`, delayed automatic start | Receives Agent data, evaluates the rules, keeps alerts, risk and the pilot license, serves Desktop. |
| **Desktop** | Central computer only, runs as the signed-in Windows user | The administration application: Devices, Alerts, Risk, Reports, Settings. You sign in with the SentinelAI administrator account created during setup. |
| **Agent** | Every computer, including the central one; Windows service `SentinelAIAgent` ("SentinelAI Endpoint Agent"), account `NT AUTHORITY\LocalService`, automatic start | Reads the computer's inventory, security settings, security status and selected Windows events and sends them to Core. It changes nothing on the computer. |
| **Updater** | Installed with Core and with each Agent | Verifies signed packages during installation, upgrade and repair. It does not download anything. |

**Data locations**

| Location | Contents |
| --- | --- |
| `%ProgramFiles%\SentinelAI\{Core,Agent,Desktop,Updater}` | Program code of the central installation, writable only by Administrators and SYSTEM. `Core\pilot-license` holds the pilot public keys and the contact details. |
| `%ProgramData%\SentinelAI\Core` | Core's SQLite database `sentinelai.db`, configuration and ownership receipts. The database holds the administrator account (password hash), devices, alerts and the pilot key. |
| `%ProgramData%\SentinelAI\Agent` | The central computer's Agent: enrollment state and its credential, protected with the LocalService account's DPAPI. |
| `%ProgramData%\SentinelAI\Setup` | Setup's pinned public trust key and ownership receipt. No passwords or tokens. |
| `%ProgramFiles%\SentinelAI Setup\SentinelAI-Setup.exe` | Installed copy of Setup, run by Windows **Settings → Apps → SentinelAI → Uninstall**. |
| `%ProgramFiles%\SentinelAI Agent\…`, `%ProgramData%\SentinelAI Agent\…` | On the other computers: the Agent, the Updater, the installed copy of Agent Setup, the Agent's configuration and DPAPI-protected credential. |
| `LocalMachine\My`, certificate "SentinelAI Core local network" | Core's own TLS certificate for the local network. Its private key is non-exportable and usable only by Core's service account, SYSTEM and Administrators. |

All data stays on the central computer. Core makes no outbound connections in the pilot: there is no cloud service, license server, telemetry to the vendor or automatic update.

## 2. Network

- **One port.** Core listens on TCP **5443** (HTTPS) on every IPv4 interface of the central computer, for Agents only. Every administrator, sign-in and Desktop function is served only on `http://127.0.0.1:5000`, which is reachable from the central computer itself. Requests for them on port 5443 are answered with `404`.
- **Firewall rule.** Setup adds one inbound rule, `SentinelAI-Core-LocalNetwork` ("SentinelAI Core (Agents on the local network)"): TCP 5443, program `SentinelAI.Core.exe`, remote address **LocalSubnet**, profiles **Domain and Private** only, never Public. Consequences:
  - Agents must be in the same subnet as the central computer. Computers in another VLAN or reached through VPN are not supported by the default rule.
  - Windows does not apply the rule while the network is classified as **Public**, which is the default for a new network. Set the company network to **Private** in Windows Settings on the central computer.
- **TLS.** TLS 1.3 is used whenever both sides support it. TLS 1.2 is accepted only when one side is Windows 10, which has no TLS 1.3. Core accepts only AES-GCM cipher suites (with ECDHE key exchange for TLS 1.2) and drops any other connection before any data is exchanged. TLS 1.1 and older are never enabled.
- **Certificate pinning.** Setup creates Core's own certificate (ECDSA P-256, self-signed, valid for 10 years). No certificate authority is installed anywhere. Each Agent trusts Core only if the SHA-256 fingerprint of its certificate exactly matches the pin from the enrollment code. A wrong certificate ends the connection during the TLS handshake, before any token or credential is sent. Desktop → **Settings → Local network** shows the addresses, the port and the fingerprint.
- **Agent traffic.** Every 30 seconds the Agent sends a short heartbeat. It sends the inventory every six hours and immediately after a monitored setting changes, the security status every hour, and new events in batches.

## 3. Requirements

- Windows 10 version 22H2 x64 or Windows 11 x64, on the central computer and on every Agent computer. Windows on ARM and 32-bit Windows are not supported.
- A central computer that stays switched on, with a fixed IP address (static or a DHCP reservation) or a DNS name the other computers resolve.
- All computers in the same subnet, with the network set to Private or Domain.
- An administrator account on each computer for installation. Setup uses the built-in Windows PowerShell 5.1 and never changes its execution policy or other controls; enforced application control or constrained language mode can therefore block it.
- TCP port 5443 free on the central computer.
- No internet access, .NET installation or browser is needed; the programs include their runtime.

## 4. Central installation

1. **Check the downloads.** Compare the SHA-256 checksum of each file with `SHA256SUMS.txt` from the same release:
   ```powershell
   Get-FileHash .\SentinelAI-Setup.exe -Algorithm SHA256
   Get-Content .\SHA256SUMS.txt
   ```
   The hash must be identical. If it differs, do not run the file.
2. **Run `SentinelAI-Setup.exe`.** The installer is not code-signed, so Windows SmartScreen shows **Windows protected your PC**. Select **More info**, check the file name, then select **Run anyway**. Approve the administrator (UAC) prompt.
3. **Wait** while Setup verifies its embedded packages and checks the computer. A computer that already has SentinelAI, part of it or another program on port 5443 is refused.
4. **Enter the pilot key** you received. Setup checks it on the computer, offline, before installing anything. A malformed, foreign or expired key is refused with support code `SETUP-PILOT-KEY` or `SETUP-PILOT-EXPIRED`.
5. **Create the SentinelAI administrator:** a username and a password of 12–1024 characters. This account signs in to Desktop; it is not a Windows account.
6. **Keep "Allow Agents on other computers in this local network to connect" selected.** Clearing it makes a local-only installation that monitors only the central computer.
7. **Select Install SentinelAI.** Setup creates Core's certificate, installs Core, creates the administrator, starts Core, stores the pilot key, adds the firewall rule, installs and enrolls the central computer's own Agent, then installs Desktop, the Updater and the Start menu shortcut. If any step fails, Setup reports it and does not report success.
8. **Open Desktop** from Setup or **Start → SentinelAI** and sign in. **Devices** shows the central computer.

## 5. Adding computers

**Create codes.** In Desktop → **Devices → Add computers**, choose:

- the address the Agents use: the computer name, recommended when it resolves, or an IPv4 address, which must stay fixed;
- the number of codes (1–50);
- their validity: 1 hour, 8 hours, 24 hours (default), 3 days or 7 days.

**Copy** puts the codes on the clipboard, excluded from clipboard history. **Save** writes one `.sentinelai-enroll` file per code. Each code is a secret that enrolls exactly one computer; pass it only to the person installing that computer. Unused codes are listed with their expiry and can be revoked.

**Interactive installation.** On the computer to add, check `SentinelAI-Agent-Setup.exe` against `SHA256SUMS.txt`, run it (SmartScreen: **More info → Run anyway**), approve UAC, paste the code or select **Open code file…**, then **Install SentinelAI Agent**. Before changing anything, Setup connects to Core at the address in the code, checks the certificate pin, and asks Core whether the code is still valid. On success the computer appears in Desktop → **Devices**.

**Silent installation.** Run elevated or as SYSTEM:

```
SentinelAI-Agent-Setup.exe /quiet /codefile <path to .sentinelai-enroll>
```

No window appears. The exit code reports the result:

| Code | Meaning |
| --- | --- |
| 0 | Installed and enrolled. |
| 2 | Invalid command line. |
| 3 | Not a valid enrollment code. Nothing changed. |
| 4 | Core not reachable at the address in the code. Nothing changed. |
| 5 | Certificate does not match the pin in the code. Nothing changed. |
| 6 | Code expired, used or revoked. Nothing changed. |
| 7 | An Agent is already installed on this computer. Nothing changed. |
| 8 | Installation failed; Setup removed what it installed. |
| 9 | Core did not confirm the enrollment; Setup removed the Agent. Issue a new code. |
| 12 | Installation failed and cleanup did not complete: run `/uninstall`, then install again. |
| 1603 | The installer could not prepare its protected workspace. Nothing changed. |
| 1460 | Setup was still running after 30 minutes. |

**Group Policy example.** One code per computer, saved as `<COMPUTERNAME>.sentinelai-enroll` on a share that only the domain computers can read, together with `SentinelAI-Agent-Setup.exe`. Create a computer startup script under **Computer Configuration → Policies → Windows Settings → Scripts → Startup**, which runs as SYSTEM:

```powershell
$share = '\\fileserver\SentinelAI$'
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAIAgent') { exit 0 }
$code = Join-Path $share "codes\$env:COMPUTERNAME.sentinelai-enroll"
if (-not (Test-Path -LiteralPath $code)) { exit 0 }
# A folder only administrators can write, so nobody can swap the installer before it runs.
$work = Join-Path $env:ProgramFiles 'SentinelAI Deploy'
New-Item -ItemType Directory -Path $work -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $share 'SentinelAI-Agent-Setup.exe'), $code -Destination $work -Force
$codeFile = Join-Path $work "$env:COMPUTERNAME.sentinelai-enroll"
$setup = Start-Process -FilePath (Join-Path $work 'SentinelAI-Agent-Setup.exe') -ArgumentList '/quiet', '/codefile', "`"$codeFile`"" -Wait -PassThru
Remove-Item -LiteralPath $work -Recurse -Force
exit $setup.ExitCode
```

Codes are valid for at most 7 days, so issue them shortly before deployment, and delete the code files after the computers appear in Desktop. Test the script on one computer first.

**Microsoft Intune example.** Because each code enrolls one computer, create one Win32 app per computer, for a few computers, or use a script like the Group Policy example above.

1. Package a folder with `SentinelAI-Agent-Setup.exe` and that computer's `code.sentinelai-enroll` using the Microsoft Win32 Content Prep Tool.
2. Configure the app:
   - **Install command:** `SentinelAI-Agent-Setup.exe /quiet /codefile code.sentinelai-enroll`. Agent Setup resolves a relative path against the current folder, which for a Win32 app is the folder Intune extracts it to.
   - **Uninstall command:** `SentinelAI-Agent-Setup.exe /uninstall /quiet`.
   - **Install behavior:** System.
   - **Detection rule:** the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAIAgent` exists.
   - **Return codes:** 0 is success; use the table above for the others.
3. Assign the app to that computer only. Test it on one computer first.

## 6. Removing computers and uninstalling

- **Remove a computer.** In Desktop, open the computer in **Devices**, select **Remove computer** and confirm. Its credential is revoked, so its Agent can no longer report, and it disappears from Devices, Risk and reports; its history is kept. The central computer's own Agent cannot be removed.
- **Uninstall the Agent** on that computer:
  - interactively: **Settings → Apps → Installed apps → SentinelAI Agent → Uninstall**;
  - silently: `"%ProgramFiles%\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" /uninstall /quiet`. Exit code 0 means done, 10 means it did not complete (run it again), and 11 means no Agent installed by Agent Setup was found.

  This removes the service, the program files, the Agent's data and credential, the Apps entry and the installed copy of Setup. When that copy is the one running the uninstall, Windows deletes it at the next restart; a new installation does not have to wait for that.
- **Uninstall the central installation.**
  1. Close Desktop.
  2. Open **Settings → Apps → Installed apps → SentinelAI → Uninstall**. Setup opens with **Uninstall** selected.
  3. **Keep security history and protected configuration** is checked by default. Uninstall then removes the services, the firewall rule, the program files and the shortcut, and keeps the database, the configuration and Core's certificate. A later Setup of the same release line restores the installation with the same identity, and the existing Agents trust it again.
  4. To delete the data as well, clear the checkbox and type **DELETE**. This also deletes Core's certificate and key; existing Agents can then never connect again.

  Run maintenance with the same Windows administrator account that installed SentinelAI: the pilot's folder permissions are tied to that account. Desktop's **Uninstall SentinelAI** button, shown when the pilot has ended, opens the same Setup flow and closes Desktop.

## 7. Pilot key and its expiry

- The key is a signed text the vendor sends you. It holds the company name and the start and end dates, and is verified offline against the public keys built into this release. It has no computer limit and no installation binding.
- Setup asks for it during the central installation. Desktop → **Settings → Pilot license** shows the customer, the expiry date and the days left, and accepts a new key to extend or replace the current one.
- Core checks the key when it is entered and every time its status is read, using its own record of time, so turning the clock back does not extend the pilot.
- Seven days before the end, Desktop shows "Pilot ends in N days — contact us". After the end, **all monitoring continues**, and Desktop shows a notice with the vendor's contact details and an **Uninstall SentinelAI** button. Both notices can be hidden until sign-out.
- The pilot key never switches security functions off and grants no cloud features.

## 8. Updates and repair

- There are no automatic updates. The vendor provides a newer `SentinelAI-Setup.exe` from the same release line, signed with the same key.
- To **upgrade**, close Desktop, run the newer Setup on the central computer and choose **Upgrade**. Setup verifies the signed package, replaces Core, the central computer's Agent, Desktop and the Updater together, and restores the previous version automatically if the new one does not start healthy. Data, the administrator account, enrollments, the pilot key and Core's certificate are kept.
- To **repair**, run the same version of Setup and choose **Repair**. This also recreates the firewall rule if it was removed or changed.
- An older Setup can only uninstall; it cannot downgrade.
- **Agents on other computers** cannot be updated in place in the pilot: Agent Setup refuses a computer that already has an Agent (exit code 7). To install a newer Agent:
  1. Uninstall the old Agent.
  2. Install the new Agent Setup with a new code. The computer then appears as a new device.
  3. Remove the old entry in Desktop.

## 9. Troubleshooting

**The Agent cannot connect (exit code 4, or a computer stops reporting)**
- On the central computer:
  - Desktop → **Settings → Local network** must say the listener is on.
  - The network must be **Private** or Domain, not Public.
  - The firewall rule `SentinelAI-Core-LocalNetwork` must exist and be enabled. **Repair** recreates it.
  - Another program must not use port 5443. `netsh interface ipv4 show excludedportrange protocol=tcp` shows ranges Windows has reserved. Core keeps working locally and logs that the network listener is disabled; free the port and restart the "SentinelAI Local Core" service.
- From the Agent computer, run `Test-NetConnection <central computer> -Port 5443`. The Agent must be in the same subnet as the central computer.

**Pin mismatch (exit code 5)**
- The certificate of the computer at that address is not the one in the code. Either the code belongs to another central installation, or the central installation was reinstalled with its data deleted, which creates a new certificate.
- Create new codes in Desktop and check the fingerprint in **Settings → Local network**. Agents enrolled with the old certificate must be uninstalled and installed again with a new code.

**Firewall**
- Only the Domain and Private profiles and the local subnet are allowed. A third-party firewall on the central computer needs an equivalent rule for inbound TCP 5443 from the local subnet to `SentinelAI.Core.exe`.

**IP address change**
- Agents keep using the address from their code.
  - Codes that use the computer name keep working when the IP address changes.
  - Codes that use an IP address stop working.
- Restore the previous address, for example with a DHCP reservation, or reinstall the affected Agents with new codes that use the computer name.

**Smart App Control, antivirus or EDR blocks the installer**
- The installers are not code-signed.
  - If Smart App Control is on, Windows may block them, and Smart App Control has no exception for a single program. On many Windows 11 versions, Smart App Control cannot be switched back on without reinstalling Windows, so decide deliberately before switching it off, or use another computer.
  - For antivirus or EDR products, allow the files by their SHA-256 hash from `SHA256SUMS.txt`, following your company policy.
- Setup does not switch off application control, constrained language mode or other security controls; if they block it, Setup reports a failure.

**The Agent reports the Security log as "access denied"**
- This is expected. The Agent runs as LocalService, which cannot read the Windows Security log, so detections based on sign-in events do not work in the standard installation. Detections from the System, PowerShell and Microsoft Defender logs do work.

## 10. Security model summary

- **Local only.** Data stays on the central computer. Core opens one network port, for Agents only, limited to the local subnet and the Private and Domain profiles. Administration is reachable only on the central computer itself.
- **Strong, pinned TLS.** TLS 1.3, or TLS 1.2 only on Windows 10, with AES-GCM only. Agents trust Core only by its exact certificate fingerprint, and no certificate authority is installed.
- **One-use enrollment codes.**
  - Each code is valid for at most 7 days and Core stores only a hash of its token.
  - Codes are never logged, and Agent Setup checks the pin before it sends the token.
  - Each Agent's credential is protected with DPAPI under its LocalService account.
- **Least privilege.**
  - The Agent runs as LocalService and only reads; it never changes settings or files.
  - Core runs under its own virtual service account.
  - Program folders are writable only by Administrators and SYSTEM.
- **Signed packages.** Setup verifies the signature and hash of every package against the public key built into it, and replaces program code transactionally with automatic rollback.
- **Administrator access.** Desktop requires the SentinelAI administrator account created during setup.
- **Minimal data.**
  - Only fixed, listed values and event fields are collected.
  - Passwords, file contents, script text and user names are never collected.
- **Offline pilot license.** The license is verified offline with public keys; monitoring never depends on it.
- **Limitations.**
  - This is pilot software without an independent security audit or certifications.
  - The installers are not code-signed.
  - The protections assume the central computer's Windows administrators are trusted.
