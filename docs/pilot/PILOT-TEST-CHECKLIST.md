# Pilot release test checklist (internal)

Run this checklist for every pilot release before it is sent to a company. Use at least two real computers in one network: **A**, the central computer, and **B**, an Agent computer. One must run Windows 10 22H2 x64 and the other Windows 11 x64; swap the roles on the next release. At least one must use a Polish display language. Record the release version, the date, both Windows builds and the result of each step. Use only test computers and synthetic data, never a customer's computers.

## 0. Build and publish

- [ ] Build the release on the owner's Windows build computer with `scripts/publish-pilot-release-windows.ps1`, using the owner's update signing key and pilot public key, and `-UpdateServerUrl` with the owner's update server. Keep both private keys outside every repository and off the test computers.
- [ ] The release folder holds exactly these files:
  - `SentinelAI-Setup.exe` and `SentinelAI-Agent-Setup.exe`;
  - `SentinelAI-Setup.manifest.json`, the signed manifest for the update server;
  - the four documents, whose business versions show the contact details given to the script instead of placeholders;
  - `SHA256SUMS.txt`.
- [ ] Issue test pilot keys with `tools/pilot-license issue`, using a test customer name:
  - 30 days, starting today;
  - one that ends in 5 days: `--start` 25 days ago with `--days 30`;
  - one that has already ended, for the Setup refusal test only: `--start` 31 days ago with `--days 30`. Core and Desktop refuse an expired key too.
- [ ] Keep an Agent Setup with a lower version, signed with the same key, outside the release folder: the previous release's `SentinelAI-Agent-Setup.exe`, or one built with `scripts/publish-setup-windows.ps1 -Product Agent -Version <lower version>` and the same keys.
- [ ] Upload the folder to the download server. On A and on B, download the files over HTTPS and check them with `Get-FileHash` against `SHA256SUMS.txt`.

## 1. Central installation on A

- [ ] Set the network on A to **Private**.
- [ ] Run `SentinelAI-Setup.exe`. SmartScreen warns; **More info → Run anyway**, then approve UAC.
- [ ] A tampered key and the ended key are refused (`SETUP-PILOT-KEY`, `SETUP-PILOT-EXPIRED`), and nothing is installed (no `%ProgramFiles%\SentinelAI`, no services).
- [ ] Enter the 30-day key, create the administrator, keep local-network access selected and install. Setup reports success.
- [ ] Open Desktop from **Start → SentinelAI** and sign in. **Devices** shows A with a fresh heartbeat and inventory.
- [ ] **Settings → Pilot license** shows the test customer, the expiry date and 30 days left.
- [ ] **Settings → Local network** shows A's addresses, port 5443, the fingerprint and that Agents can connect.
- [ ] `Get-NetFirewallRule -Name SentinelAI-Core-LocalNetwork` shows an inbound rule for the Domain and Private profiles, and `Get-NetFirewallRule -Name SentinelAI-Core-LocalNetwork | Get-NetFirewallAddressFilter` shows the remote address LocalSubnet.
- [ ] Windows **Settings → Apps** lists **SentinelAI**.

## 2. Adding B

- [ ] In Desktop on A, **Devices → Add computers**:
  - create two codes for the computer name and two for A's IPv4 address;
  - check **Copy codes** and **Save codes as files**;
  - revoke one code.
- [ ] Before installing on B, note the output of `auditpol /get /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}` in an elevated PowerShell (normally no auditing).
- [ ] On B, run Agent Setup with the revoked code: it is refused and nothing changes.
- [ ] Run Agent Setup interactively with a valid code. It installs, and B appears in **Devices** on A within a minute.
- [ ] Uninstall the Agent on B from **Settings → Apps → SentinelAI Agent**. Remove B in Desktop.
- [ ] Reinstall silently from an elevated PowerShell. Agent Setup is a GUI program, so read its exit code with `(Start-Process .\SentinelAI-Agent-Setup.exe -ArgumentList '/quiet', '/codefile', '"<file>"' -Wait -PassThru).ExitCode`. It must be 0.
- [ ] Run Agent Setup again on B the same way: exit code 7 (already installed), nothing changes.
- [ ] Run Agent Setup on A: exit code 7.
- [ ] On B, `Test-NetConnection <A> -Port 5443` succeeds.
- [ ] In Desktop, open the details of A and of B. The endpoint telemetry sections (BitLocker, antivirus, Defender, local administrators, Windows Update, pending restart, services, applications) show their values or a stated reason on both Windows 10 and Windows 11. Note any section that is not collected; the build system tests only Windows Server.

## 3. An alert appears

- [ ] On B, cause one harmless finding, for example:
  - turn off the Private firewall profile for a moment;
  - or create and delete a test service with a program path in a temporary folder.
- [ ] Within a few minutes, **Alerts** on A shows the alert for B with its evidence and recommended action, and **Risk** ranks B.
- [ ] Set the alert to **Investigating**, then **Resolved**. Restore the setting on B.
- [ ] On B, in an elevated PowerShell, create and delete a scheduled task and a never-started test driver entry:
  ```powershell
  schtasks /Create /TN \SentinelAITest /TR "cmd.exe /c exit 0" /SC ONCE /ST 23:59 /F; schtasks /Delete /TN \SentinelAITest /F
  sc.exe create SentinelAITestDriver type= kernel binPath= C:\Users\Public\sentinelai-test.sys start= demand; sc.exe delete SentinelAITestDriver
  ```
  Within a few minutes **Alerts** shows "Scheduled task created outside the Microsoft task folder" and "Driver installed outside the Windows system folders" for B, also on the Polish computer.
- [ ] In **Reports**, generate and save a report for the current month and open it.

## 4. Automatic Agent update

Run this on B; do it once on Windows 10 and once on Windows 11 across releases (B's Windows changes when the roles swap).

- [ ] Uninstall the Agent on B from **Settings → Apps → SentinelAI Agent** and remove B in Desktop. Install the lower-version Agent Setup on B with a new code. **Settings → Apps → SentinelAI Agent** shows the lower version.
- [ ] In an elevated PowerShell on B, `Get-ScheduledTask -TaskPath '\SentinelAI\' | Select-Object TaskName, State, @{n='User';e={$_.Principal.UserId}}` shows `SentinelAI Agent Update`, Ready, SYSTEM.
- [ ] Within about two minutes, `%ProgramData%\SentinelAI Agent\Agent\update` holds `agent-update.zip` and `agent-update.manifest.json`.
- [ ] Run `Start-ScheduledTask -TaskPath '\SentinelAI\' -TaskName 'SentinelAI Agent Update'`. After about a minute, `(Get-ScheduledTaskInfo -TaskPath '\SentinelAI\' -TaskName 'SentinelAI Agent Update').LastTaskResult` is 0. Check that:
  - **Settings → Apps → SentinelAI Agent** shows this release's version;
  - in Desktop, B is still one device with its history, and its details show the new Agent version with a fresh heartbeat;
  - within a few minutes, the `update` folder is empty;
  - no alert for B names the SentinelAI task.
- [ ] Once per release cycle, do not start the task: install the lower version again (as in the first step) and check that B updates by itself within two hours.

## 5. Pilot key near and after the end

These steps move A's clock forward. Core never lets its time go backwards, so A's pilot dates stay shifted by that amount: do this only on test computers.

- [ ] In **Settings → Pilot license**, enter the key ending in 5 days. The shell notice says "Pilot ends in 5 days — contact us" with the contact details.
- [ ] **Hide until sign-out** hides it, and it comes back after signing out and in.
- [ ] Set A's clock 6 days ahead and sign in again. Check that:
  - the ended notice is shown with the contact details and **Uninstall SentinelAI**;
  - Devices, Alerts and Risk still update (B keeps reporting).
- [ ] Set A's clock back to the real time, restart A and sign in: the pilot is still ended. Leave it ended for step 7.

## 6. Removing B

- [ ] In Desktop, open B in **Devices** and select **Remove computer**. B disappears from Devices and Risk, and its alerts' history is kept.
- [ ] Uninstall the Agent on B silently from an elevated PowerShell: `(Start-Process "$env:ProgramFiles\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" -ArgumentList '/uninstall', '/quiet' -Wait -PassThru).ExitCode` must be 0. Check:
  - the service is gone, and `Get-ScheduledTask -TaskPath '\SentinelAI\'` finds no task;
  - `%ProgramFiles%\SentinelAI Agent` and `%ProgramData%\SentinelAI Agent` are gone, and the running Setup copy waits in `%ProgramData%\SentinelAI-Setup` for deletion at the next restart;
  - the **SentinelAI Agent** entry in **Settings → Apps** is gone;
  - `auditpol /get /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}` shows what you noted before installing, and `wevtutil gl Security` no longer lists `S-1-5-80-3260565588-2217304288-1438658577-528527895-932542736` under `channelAccess`.

## 7. Uninstalling the central installation

- [ ] Uninstall with data kept:
  1. With the pilot ended (step 5), select **Uninstall SentinelAI** in Desktop. Desktop closes, and UAC appears.
  2. Setup opens with **Uninstall** selected and **Keep security history and protected configuration** checked. Select **Continue**.
  3. Check that the services, the firewall rule and `%ProgramFiles%\SentinelAI` are gone, and that `%ProgramData%\SentinelAI\Core\sentinelai.db` remains.
- [ ] Sign in to Windows on A with a different administrator account than the one that installed SentinelAI, and run the same `SentinelAI-Setup.exe` again: it offers **Repair**. Repair, sign in, and check that the history and the ended pilot are still there. Enter the 30-day key: the pilot is active again (with fewer days left, because of step 5).
- [ ] Check that no folder names a Windows account: `icacls "%ProgramFiles%\SentinelAI" /T` and `icacls "%ProgramData%\SentinelAI" /T` list only `BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`, the service accounts and, for Desktop, `BUILTIN\Users`.
- [ ] Uninstall with data removed:
  1. Uninstall again from **Settings → Apps → SentinelAI**.
  2. Clear **Keep security history and protected configuration**, type **DELETE** and select **Continue**.
  3. Check that `%ProgramData%\SentinelAI` and the certificate with the friendly name "SentinelAI Core local network" in `LocalMachine\My` are gone.

## 8. Central update from the update server

Do it once on Windows 10 and once on Windows 11 across releases.

- [ ] On A, install an older full Setup built with the same keys and the same `-UpdateServerUrl` (the previous release, or one built with a lower version), with the 30-day key.
- [ ] Upload this release's `SentinelAI-Setup.manifest.json` to `<URL>/SentinelAI-Setup.manifest.json` and `SentinelAI-Setup.exe` to `<URL>/<version>/SentinelAI-Setup.exe`.
- [ ] Desktop → **Settings → Updates** shows the server and "Off". `Get-ScheduledTask -TaskPath '\SentinelAI\' -TaskName 'SentinelAI Update' | Select-Object State, @{n='User';e={$_.Principal.UserId}}` shows Ready, SYSTEM.
- [ ] Turn on **Check the provider's update server**; **Install downloaded updates automatically at night** is checked. Select **Check now**, then **Refresh updates**: within a few minutes the status says this version is downloaded and installs tonight.
- [ ] Keep Desktop open and run `Start-ScheduledTask -TaskPath '\SentinelAI\' -TaskName 'SentinelAI Update'` in an elevated PowerShell (instead of waiting for the night). Desktop closes. Within about five minutes **Settings → Apps → SentinelAI** shows this version. Open Desktop: history, devices and the pilot key are kept, Updates says up to date and checking is still on.
- [ ] Once per release cycle, with automatic installation off and a newer build on the server: **Install now** asks for administrator approval, Desktop closes and Setup opens with **Upgrade** selected.
- [ ] Uninstall with data removed. The task `\SentinelAI\SentinelAI Update` is gone.

## 9. Record

- [ ] Note any SmartScreen, Smart App Control or antivirus behavior seen on each computer.
- [ ] Note anything the customer documents describe differently from what you saw, and correct the documents before release.
