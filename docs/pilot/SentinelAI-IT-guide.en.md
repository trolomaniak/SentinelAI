# SentinelAI IT guide

*Pilot version. Polish version: [przewodnik IT](SentinelAI-przewodnik-IT.pl.md). For a plain-language overview see [SentinelAI for business](SentinelAI-for-business.en.md).*

## 1. Architecture

| Component | Where it runs | What it does |
| --- | --- | --- |
| **Core** | Central computer, Windows service `SentinelAICore` ("SentinelAI Local Core"), account `NT SERVICE\SentinelAICore`, delayed automatic start | Receives Agent data, evaluates the rules and vulnerabilities, keeps alerts, risk, the risk register and the pilot license, serves Desktop. |
| **Desktop** | Central computer only, runs as the signed-in Windows user | The administration application: Overview, Devices, Alerts, Risk, Risk Register, Reports, Settings. You sign in with the SentinelAI administrator account created during setup. |
| **Agent** | Every computer, including the central one; Windows service `SentinelAIAgent` ("SentinelAI Endpoint Agent"), account `NT AUTHORITY\LocalService`, automatic start | Reads the computer's inventory, security settings, security status and selected Windows events and sends them to Core. It writes only its own state files and never changes Windows settings or your files. |
| **Updater** | Installed with Core and with each Agent | Public-only package verification client. During installation, upgrade and repair, Setup verifies the signed packages with its own embedded copy. On the other computers the scheduled task `\SentinelAI\SentinelAI Agent Update` runs it as SYSTEM to install a newer Agent (section 8). It does not download anything. |

**Data locations**

| Location | Contents |
| --- | --- |
| `%ProgramFiles%\SentinelAI\{Core,Agent,Desktop,Updater}` | Program code of the central installation, writable only by Administrators and SYSTEM (see section 10). `Core\pilot-license` holds the pilot public keys and the contact details. |
| `%ProgramData%\SentinelAI\Core` | Core's SQLite database `sentinelai.db`, configuration and ownership receipts. The database holds the administrator account (password hash), devices, alerts and the pilot key. |
| `%ProgramData%\SentinelAI\Agent` | The central computer's Agent: enrollment state and its credential, protected with the LocalService account's DPAPI. |
| `%ProgramData%\SentinelAI\Setup` | Setup's pinned public trust key and ownership receipt. No passwords or tokens. |
| `%ProgramFiles%\SentinelAI Setup\SentinelAI-Setup.exe` | Installed copy of Setup, run by **Uninstall** of **SentinelAI** in Windows **Settings → Apps → Installed apps** (Windows 10: **Apps & features**). |
| `%ProgramFiles%\SentinelAI Agent\…`, `%ProgramData%\SentinelAI Agent\…` | On the other computers: the Agent, the Updater, the installed copy of Agent Setup, the Agent's configuration and DPAPI-protected credential. |
| `LocalMachine\My`, certificate with the friendly name "SentinelAI Core local network" (subject: the computer name) | Core's own TLS certificate for the local network. Its private key is non-exportable and usable only by Core's service account, SYSTEM and Administrators. |

All data stays on the central computer. There is no cloud service, license server or telemetry to the vendor. Core makes no outbound connection unless an administrator turns on checking for updates (section 8); even then it only downloads from the vendor's update server and sends no data. Agents update only from the central computer.

**Windows settings Setup changes for the Agent**

So that the Agent can read the events its detections need, both installers change three Windows settings, and repair and upgrade keep them:

- The `SentinelAIAgent` service gets its own service SID, `NT SERVICE\SentinelAIAgent` (SID type *unrestricted*).
- That SID gets read-only access to the Windows **Security** log, and to nothing else. No account, group membership or other log changes.
- **Audit Other Object Access Events** is set to audit **Success**, so Windows records the creation of scheduled tasks (event 4698). Failure auditing stays as it was.

Uninstalling the Agent or the central installation removes the Security log access, and turns success auditing off again if it was off before Setup. A domain Group Policy that sets the audit policy or the Security log's access takes precedence and can undo these settings at its next refresh; if you manage them centrally, set the same values there.

## 2. Network

- **One port.** Core listens on TCP **5443** (HTTPS) on every IPv4 interface of the central computer, for Agents only. Every administrator, sign-in and Desktop function is served only on `http://127.0.0.1:5000`, which is reachable from the central computer itself. Requests for them on port 5443 are answered with `404`.
- **Firewall rule.** Setup adds one inbound rule, `SentinelAI-Core-LocalNetwork` ("SentinelAI Core (Agents on the local network)"): TCP 5443, program `SentinelAI.Core.exe`, remote address **LocalSubnet**, profiles **Domain and Private** only, never Public. Consequences:
  - Agents must be in the same subnet as the central computer. Computers in another VLAN or reached through VPN are not supported by the default rule.
  - Windows does not apply the rule while the network is classified as **Public**, which is the default for a new network. Set the company network to **Private** in Windows Settings on the central computer.
- **TLS.** TLS 1.3 is used whenever both sides support it. TLS 1.2 is used only when one side is Windows 10, which has no TLS 1.3. Core accepts only AES-GCM cipher suites (with ECDHE key exchange for TLS 1.2) and drops any other connection before any data is exchanged. TLS 1.1 and older are never enabled.
- **Certificate pinning.** Setup creates Core's own certificate (ECDSA P-256, self-signed, valid for 10 years). No certificate authority is installed anywhere. Each Agent trusts Core only if the SHA-256 fingerprint of its certificate exactly matches the pin from the enrollment code. A wrong certificate ends the connection during the TLS handshake, before any token or credential is sent. Desktop → **Settings → Local network** shows the addresses, the port and the fingerprint.
- **Updates (optional).** Only while an administrator has turned on checking for updates, the central computer connects over HTTPS (port 443) to the vendor's update server named in Desktop → **Settings → Updates**, to download new versions and vulnerability data. Off by default.
- **Agent traffic.** Every 30 seconds the Agent sends a short heartbeat. It sends the inventory every six hours and within seconds after a monitored setting changes (at most every 30 seconds), the security status every hour, and new events in batches.

## 3. Requirements

- Windows 10 version 22H2 x64 or Windows 11 x64, on the central computer and on every Agent computer. Windows on ARM and 32-bit Windows are not supported.
- A central computer that stays switched on, with a fixed IP address (static or a DHCP reservation) or a DNS name the other computers resolve.
- All computers in the same subnet, with the network set to Private or Domain.
- An administrator account on each computer for installation. Setup uses the built-in Windows PowerShell 5.1 and never changes its execution policy or other controls; enforced application control or constrained language mode can therefore block it.
- TCP port 5443 free on the central computer. Check it before installing: `Get-NetTCPConnection -LocalPort 5443 -ErrorAction SilentlyContinue` must show nothing. Setup checks the port only during installation, and a failed fresh installation leaves partial state that the next Setup refuses (support code `SETUP-OWNERSHIP`); contact the vendor in that case.
- No internet access, .NET installation or browser is needed; the programs include their runtime.

## 4. Central installation

1. **Check the downloads.** Compare the SHA-256 checksum of each file with `SHA256SUMS.txt` from the same release:
   ```powershell
   Get-FileHash .\SentinelAI-Setup.exe -Algorithm SHA256
   Get-Content .\SHA256SUMS.txt
   ```
   The hash must match; letter case does not matter. If it differs, do not run the file.
2. **Run `SentinelAI-Setup.exe`.** The installer is not code-signed, so Windows SmartScreen shows **Windows protected your PC**. Select **More info**, check the file name, then select **Run anyway**. Approve the administrator (UAC) prompt.
3. **Choose the language** under **Język / Language** at the top of the window; Windows' language is the default. Desktop, reports and the texts Core writes use it. An administrator can change it later in Desktop → **Settings → Language** (it applies when Desktop next starts).
4. **Wait** while Setup verifies its embedded packages and checks the computer. On a computer that already has this SentinelAI installation, Setup offers Repair, Upgrade or Uninstall instead. Partial or unrecognized installation state is refused (support code `SETUP-OWNERSHIP`).
5. **Enter the pilot key** you received. Setup checks it on the computer, offline, before installing anything. A malformed, foreign or expired key is refused with support code `SETUP-PILOT-KEY` or `SETUP-PILOT-EXPIRED`.
6. **Create the SentinelAI administrator:** a username and a password of 12–1024 characters. This account signs in to Desktop; it is not a Windows account.
7. **Keep "Allow Agents on other computers in this local network to connect" selected.** Clearing it makes a local-only installation that monitors only the central computer.
8. **Select Install SentinelAI.** Setup creates Core's certificate, installs Core, creates the administrator, starts Core and adds the firewall rule, stores the pilot key, installs and enrolls the central computer's own Agent, then installs Desktop, the Updater and the Start menu shortcut. If a step fails, Setup reports the failure and does not report success. The exceptions are the pilot key and the language: if Core cannot store them, installation completes and Setup asks you to set them in Desktop.
9. **Open Desktop** from Setup or **Start → SentinelAI** and sign in. **Devices** shows the central computer.

## 5. Adding computers

**Create codes.** In Desktop → **Devices → Add computers**, choose:

- the address the Agents use: the computer name, recommended when it resolves, or an IPv4 address, which must stay fixed;
- the number of codes (1–50);
- their validity: 1 hour, 8 hours, 24 hours (default), 3 days or 7 days.

**Copy codes** puts the codes on the clipboard, excluded from clipboard history. **Save codes as files** writes one `.sentinelai-enroll` file per code, named `SentinelAI-computer-NN-….sentinelai-enroll`. Each code is a secret that enrolls exactly one computer; pass it only to the person installing that computer. Unused codes are listed with their expiry and can be revoked.

**Interactive installation.** On the computer to add, check `SentinelAI-Agent-Setup.exe` against `SHA256SUMS.txt`, run it (SmartScreen: **More info → Run anyway**), approve UAC, optionally choose **Język / Language** at the top (for that window only), paste the code or select **Open code file...**, then **Install SentinelAI Agent**. Before changing anything, Setup connects to Core at the address in the code, checks the certificate pin, and asks Core whether the code is still valid. On success the computer appears in Desktop → **Devices**.

**Silent installation.** Run elevated or as SYSTEM:

```
SentinelAI-Agent-Setup.exe /quiet /codefile <path to .sentinelai-enroll>
```

No window appears. Agent Setup is a Windows (GUI) program, so PowerShell does not wait for it or set `$LASTEXITCODE`; read the exit code like this:

```powershell
(Start-Process .\SentinelAI-Agent-Setup.exe -ArgumentList '/quiet', '/codefile', '"C:\Codes\PC01.sentinelai-enroll"' -Wait -PassThru).ExitCode
```

The exit code reports the result:

| Code | Meaning |
| --- | --- |
| 0 | Installed and enrolled. |
| 1 | Unexpected failure. |
| 2 | Invalid command line. |
| 3 | Not a valid enrollment code. Nothing changed. |
| 4 | Core not reachable at the address in the code. Nothing changed. |
| 5 | Certificate does not match the pin in the code. Nothing changed. |
| 6 | Code expired, used or revoked. Nothing changed. |
| 7 | An Agent is already installed on this computer. Nothing changed. |
| 8 | Installation failed; Setup removed what it installed. |
| 9 | Core did not confirm the enrollment; Setup removed the Agent. Issue a new code. |
| 12 | Installation failed and cleanup did not complete: run `/uninstall`, then install again. |
| 1603 | The installer could not start, validate itself or prepare its protected workspace. Nothing changed. |
| 1460 | Setup was still running after 30 minutes. |

**Group Policy example.** One code per computer: rename each saved code file to `<COMPUTERNAME>.sentinelai-enroll` and put it in a `codes` folder on a share that only the domain computers can read, together with `SentinelAI-Agent-Setup.exe`. Create a computer startup script under **Computer Configuration → Policies → Windows Settings → Scripts → Startup**, which runs as SYSTEM:

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

1. Rename that computer's code file to `code.sentinelai-enroll` and package it with `SentinelAI-Agent-Setup.exe` in one folder, using the Microsoft Win32 Content Prep Tool.
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
  - interactively: **Settings → Apps → Installed apps** (Windows 10: **Apps & features**) **→ SentinelAI Agent → Uninstall**;
  - silently: `"%ProgramFiles%\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" /uninstall /quiet`. Exit code 0 means done, 10 means it did not complete (run it again), and 11 means no Agent installed by Agent Setup was found.

  This removes the service, the program files, the Agent's data and credential, the Apps entry and the installed copy of Setup. When that copy is the one running the uninstall, it is moved into `%ProgramData%\SentinelAI-Setup` and Windows deletes it at the next restart; the product folders go at once, and a new installation does not have to wait.
- **Uninstall the central installation.**
  1. Close Desktop.
  2. Open **Settings → Apps → Installed apps** (Windows 10: **Apps & features**) **→ SentinelAI → Uninstall**. Setup opens with **Uninstall** selected; select **Continue** to run it.
  3. **Keep security history and protected configuration** is checked by default. Uninstall then removes the services, the firewall rule, the program files and the shortcut, and keeps the database, the configuration and Core's certificate. A later Setup of the same release line restores the installation with the same identity, and the existing Agents trust it again.
  4. To delete the data as well, clear the checkbox and type **DELETE**. This also deletes Core's certificate and key; existing Agents can then never connect again.

  Any Windows administrator account can run maintenance, not only the one that installed SentinelAI. Desktop's **Uninstall SentinelAI** button, shown when the pilot has ended, opens the same Setup flow and closes Desktop.

## 7. Pilot key and its expiry

- The key is a signed text the vendor sends you. It holds the company name and the start and end dates, and is verified offline against the public keys built into this release. It has no computer limit and no installation binding.
- Setup asks for it during the central installation. Desktop → **Settings → Pilot license** shows the customer, the expiry date and the days left, and accepts a new key to extend or replace the current one.
- Core checks the key when it is entered and every time its status is read, using its own record of time, so turning the clock back does not extend the pilot.
- Seven days before the end, Desktop shows "Pilot ends in N days — contact us". After the end, **all monitoring continues**, and Desktop shows a notice with the vendor's contact details and an **Uninstall SentinelAI** button. Both notices can be hidden until sign-out.
- The pilot key never switches security functions off and grants no cloud features.

## 8. Updates and repair

- **Updates of the central computer from the vendor's server (optional, off by default).** If your release includes an update server, Desktop → **Settings → Updates** shows it:
  - While **Check the provider's update server for new versions** is off, SentinelAI makes no internet connection.
  - When it is on, Core checks the server every six hours (and on **Check now**) and downloads a newer version into `%ProgramData%\SentinelAI\Core\central-update`, and newer vulnerability data.
  - **Install downloaded updates automatically at night** is on by default: between 02:00 and 04:00 the task `\SentinelAI\SentinelAI Update` (SYSTEM) verifies the download with the key pinned at installation, closes Desktop and upgrades. If the new version does not start healthy, the previous one is restored. A version that does not install in three nights is not tried again automatically.
  - With it off, or at any time, select **Install now**: Windows asks for administrator approval, Desktop closes and Setup opens with **Upgrade** selected.
  - Silent upgrade for deployment tools: `SentinelAI-Setup.exe /upgrade /quiet` (exit code 0 upgraded, 13 nothing to upgrade, 14 Desktop is running, 15 failed and the previous version restored, 16 run Setup interactively to recover).
- Otherwise the vendor provides a newer `SentinelAI-Setup.exe` from the same release line, signed with the same key.
- To **upgrade**, close Desktop, run the newer Setup on the central computer and choose **Upgrade**. Setup verifies the signed package, replaces Core, the central computer's Agent, Desktop and the Updater together, and restores the previous version automatically if the new one does not start healthy. Data, the administrator account, enrollments, the pilot key and Core's certificate are kept.
- To **repair**, run the same version of Setup and choose **Repair**. This also recreates the firewall rule if it was removed or changed.
- An older Setup can only uninstall; it cannot downgrade.
- An installation made by an earlier Setup also gave the Windows account that installed it full control of Core's folders. The first upgrade, repair or uninstall, run by any administrator, removes that access.
- **Vulnerability data.** Core assesses vulnerabilities in installed programs and in the Windows release with signed data from the vendor (built from the NVD and the CISA KEV catalog); without that data it shows no vulnerabilities.
  - While update checking is on, Core downloads newer data together with the updates.
  - Otherwise the vendor sends two files, `vulnerability-feed.json` and `vulnerability-feed.manifest.json`. Put them in one folder, and in Desktop → **Settings → Vulnerability data** select **Import vulnerability data…**, then the `.manifest.json` file.
  - Core accepts only data signed with the key pinned at installation and newer than its current data. Desktop → **Devices** → a computer → **Vulnerabilities** shows the results; known exploited vulnerabilities and those with a critical or high CVSS score become alerts. SentinelAI never installs or updates anything in the programs itself.
- **Agents on other computers update automatically** from the central computer after its upgrade:
  - Each Agent checks Core one minute after it starts and then hourly, and downloads the newer signed Agent into `%ProgramData%\SentinelAI Agent\Agent\update`.
  - The scheduled task `\SentinelAI\SentinelAI Agent Update` (SYSTEM, hourly and 5 minutes after startup) verifies it with the key pinned at installation, replaces the Agent and restores the previous one if the new one does not keep running. A release restored three times is not tried again.
  - The computer stays the same device with its history; Desktop shows the new Agent version in the device details, usually within two hours.
  - To install at once, run `Start-ScheduledTask -TaskPath '\SentinelAI\' -TaskName 'SentinelAI Agent Update'` in an elevated PowerShell after the download. The task's last result 0 means no update or installed; 3 rejected; 4 restored the previous Agent; 5 the restore failed and is retried at the next run.
  - The Updater and the installed Agent Setup copy on those computers keep their installed version. Agent Setup still refuses a computer that already has an Agent (exit code 7).

## 9. Troubleshooting

**The Agent cannot connect (exit code 4, or a computer stops reporting)**
- On the central computer:
  - Desktop → **Settings → Local network** must say that Agents can connect.
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

**The Agent reports the Security log as "access denied", or new scheduled tasks raise no alert**
- Setup grants the Agent read access to the Security log and turns on the auditing of new scheduled tasks (section 1). On the central computer, run Setup and choose **Repair**; on another computer, reinstall the Agent.
- If a domain Group Policy sets **Configure log access** for the Security log, add read access for `NT SERVICE\SentinelAIAgent` there. If it sets the advanced audit policy, enable **Audit Other Object Access Events** for Success there.
- `auditpol /get /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}` shows the current setting in any Windows language.

## 10. Security model summary

- **Local only.** Data stays on the central computer. Core opens one network port, for Agents only, limited to the local subnet and the Private and Domain profiles. Administration is reachable only on the central computer itself.
- **Strong, pinned TLS.** TLS 1.3, or TLS 1.2 only on Windows 10, with AES-GCM only. Agents trust Core only by its exact certificate fingerprint, and no certificate authority is installed.
- **One-use enrollment codes.**
  - Each code is valid for at most 7 days and Core stores only a hash of its token.
  - Codes are never logged, and Agent Setup checks the pin before it sends the token.
  - Each Agent's credential is protected with DPAPI under its LocalService account.
- **Least privilege.**
  - The Agent runs as LocalService and only reads; it writes only its own state and never changes Windows settings or your files. Its own service SID may read the Security log, and no other log or object (section 1).
  - Core runs under its own virtual service account.
  - Program and data folders are writable only by Administrators and SYSTEM, and by each service only where it writes its own state. No folder gives the Windows account that installed SentinelAI its own access, so that account's programs running without elevation cannot change what Core or the Agent runs, and any administrator can maintain the installation.
- **Signed packages.** Setup verifies the signature and hash of every package against the public key built into it, and replaces program code transactionally with automatic rollback. Automatic Agent updates are verified on each computer with the key pinned at installation, by SYSTEM; the Agent only downloads them and cannot install anything. Updates from the vendor's server are verified the same way on the central computer before anything runs; Core only downloads them.
- **Administrator access.** Desktop requires the SentinelAI administrator account created during setup.
- **Minimal data.**
  - Only fixed, listed values and event fields are collected.
  - Passwords, file contents, script text and user names are never collected.
- **Offline pilot license.** The license is verified offline with public keys; monitoring never depends on it.
- **Limitations.**
  - This is pilot software without an independent security audit or certifications.
  - The installers are not code-signed.
  - The protections assume the central computer's Windows administrators are trusted.
