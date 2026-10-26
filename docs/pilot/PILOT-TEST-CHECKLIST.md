# Pilot release test checklist (internal)

Run this checklist for every pilot release before it is sent to a company. Use at least two real computers in one network: **A**, the central computer, and **B**, an Agent computer. One must run Windows 10 22H2 x64 and the other Windows 11 x64; swap the roles on the next release. Record the release version, the date, both Windows builds and the result of each step. Use only test computers and synthetic data, never a customer's computers.

## 0. Build and publish

- [ ] Build the release on the owner's Windows build computer with `scripts/publish-pilot-release-windows.ps1`, using the owner's update signing key and pilot public key. Keep both private keys outside every repository and off the test computers.
- [ ] The release folder holds exactly these files:
  - `SentinelAI-Setup.exe` and `SentinelAI-Agent-Setup.exe`;
  - the four documents, whose business versions show the contact details given to the script instead of placeholders;
  - `SHA256SUMS.txt`.
- [ ] Issue test pilot keys with `tools/pilot-license issue`, using a test customer name:
  - 30 days, starting today;
  - one that ends in 5 days: `--start` 25 days ago with `--days 30`;
  - one that has already ended, for the Setup refusal test only: `--start` 31 days ago with `--days 30`. Core and Desktop refuse an expired key too.
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
- [ ] In **Reports**, generate and save a report for the current month and open it.

## 4. Pilot key near and after the end

These steps move A's clock forward. Core never lets its time go backwards, so A's pilot dates stay shifted by that amount: do this only on test computers.

- [ ] In **Settings → Pilot license**, enter the key ending in 5 days. The shell notice says "Pilot ends in 5 days — contact us" with the contact details.
- [ ] **Hide until sign-out** hides it, and it comes back after signing out and in.
- [ ] Set A's clock 6 days ahead and sign in again. Check that:
  - the ended notice is shown with the contact details and **Uninstall SentinelAI**;
  - Devices, Alerts and Risk still update (B keeps reporting).
- [ ] Set A's clock back to the real time, restart A and sign in: the pilot is still ended. Leave it ended for step 6.

## 5. Removing B

- [ ] In Desktop, open B in **Devices** and select **Remove computer**. B disappears from Devices and Risk, and its alerts' history is kept.
- [ ] Uninstall the Agent on B silently from an elevated PowerShell: `(Start-Process "$env:ProgramFiles\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" -ArgumentList '/uninstall', '/quiet' -Wait -PassThru).ExitCode` must be 0. Check:
  - the service is gone;
  - `%ProgramFiles%\SentinelAI Agent` and `%ProgramData%\SentinelAI Agent` are gone, and the running Setup copy waits in `%ProgramData%\SentinelAI-Setup` for deletion at the next restart;
  - the **SentinelAI Agent** entry in **Settings → Apps** is gone.

## 6. Uninstalling the central installation

- [ ] Uninstall with data kept:
  1. With the pilot ended (step 4), select **Uninstall SentinelAI** in Desktop. Desktop closes, and UAC appears.
  2. Setup opens with **Uninstall** selected and **Keep security history and protected configuration** checked. Select **Continue**.
  3. Check that the services, the firewall rule and `%ProgramFiles%\SentinelAI` are gone, and that `%ProgramData%\SentinelAI\Core\sentinelai.db` remains.
- [ ] Run the same `SentinelAI-Setup.exe` again: it offers **Repair**. Repair, sign in, and check that the history and the ended pilot are still there. Enter the 30-day key: the pilot is active again (with fewer days left, because of step 4).
- [ ] Uninstall with data removed:
  1. Uninstall again from **Settings → Apps → SentinelAI**.
  2. Clear **Keep security history and protected configuration**, type **DELETE** and select **Continue**.
  3. Check that `%ProgramData%\SentinelAI` and the certificate with the friendly name "SentinelAI Core local network" in `LocalMachine\My` are gone.

## 7. Record

- [ ] Note any SmartScreen, Smart App Control or antivirus behavior seen on each computer.
- [ ] Note anything the customer documents describe differently from what you saw, and correct the documents before release.
