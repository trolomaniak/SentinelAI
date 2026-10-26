# Pilot release test checklist (internal)

Run this checklist for every pilot release before it is sent to a company. Use at least two real computers in one network: **A**, the central computer, and **B**, an Agent computer. One must run Windows 10 22H2 x64 and the other Windows 11 x64; swap the roles on the next release. Record the release version, the date, both Windows builds and the result of each step. Use only test computers and synthetic data, never a customer's computers.

## 0. Build and publish

- [ ] Build the release on the owner's Windows build computer with `scripts/publish-pilot-release-windows.ps1`, using the owner's update signing key and pilot public key. Keep both private keys outside every repository and off the test computers.
- [ ] The release folder holds exactly these files:
  - `SentinelAI-Setup.exe` and `SentinelAI-Agent-Setup.exe`;
  - the four documents;
  - `SHA256SUMS.txt`.
- [ ] Issue test pilot keys with `tools/pilot-license issue`, using a test customer name:
  - 30 days, starting today;
  - one that ends in 5 days: `--start` 25 days ago with `--days 30`;
  - one that has already ended: `--start` 31 days ago with `--days 30`.
- [ ] Upload the folder to the download server. On A and on B, download the files over HTTPS and check them with `Get-FileHash` against `SHA256SUMS.txt`.

## 1. Central installation on A

- [ ] Set the network on A to **Private**.
- [ ] Run `SentinelAI-Setup.exe`. SmartScreen warns; **More info → Run anyway**, then approve UAC.
- [ ] A tampered or expired pilot key is refused, and nothing is installed (no `%ProgramFiles%\SentinelAI`, no services).
- [ ] Enter the 30-day key, create the administrator, keep local-network access selected and install. Setup reports success.
- [ ] Open Desktop from **Start → SentinelAI** and sign in. **Devices** shows A with a fresh heartbeat and inventory.
- [ ] **Settings → Pilot license** shows the test customer, the expiry date and 30 days left.
- [ ] **Settings → Local network** shows A's addresses, port 5443, the fingerprint and that the listener is on.
- [ ] `Get-NetFirewallRule -Name SentinelAI-Core-LocalNetwork` shows the rule: inbound, Domain and Private profiles, LocalSubnet.
- [ ] Windows **Settings → Apps** lists **SentinelAI**.

## 2. Adding B

- [ ] In Desktop on A, **Devices → Add computers**:
  - create two codes for the computer name and two for A's IPv4 address;
  - check **Copy** and **Save**;
  - revoke one code.
- [ ] On B, run Agent Setup with the revoked code: it is refused and nothing changes.
- [ ] Run Agent Setup interactively with a valid code. It installs, and B appears in **Devices** on A within a minute.
- [ ] Uninstall the Agent on B from **Settings → Apps → SentinelAI Agent**. Remove B in Desktop.
- [ ] Reinstall silently from an elevated PowerShell: `SentinelAI-Agent-Setup.exe /quiet /codefile <file>`. Check `$LASTEXITCODE` is 0.
- [ ] Run Agent Setup again on B: exit code 7 (already installed), nothing changes.
- [ ] Run Agent Setup on A: exit code 7.
- [ ] On B, `Test-NetConnection <A> -Port 5443` succeeds. Note which TLS version is used: TLS 1.2 if either computer is Windows 10, otherwise TLS 1.3.

## 3. An alert appears

- [ ] On B, cause one harmless finding, for example:
  - turn off the Private firewall profile for a moment;
  - or create and delete a test service with a program path in a temporary folder.
- [ ] Within a few minutes, **Alerts** on A shows the alert for B with its evidence and recommended action, and **Risk** ranks B.
- [ ] Set the alert to **Investigating**, then **Resolved**. Restore the setting on B.
- [ ] In **Reports**, generate and save a report for the current month and open it.

## 4. Pilot key near and after the end

- [ ] In **Settings → Pilot license**, enter the key ending in 5 days. The shell notice says "Pilot ends in 5 days — contact us" with the contact details.
- [ ] **Hide until sign-out** hides it, and it comes back after signing out and in.
- [ ] Enter the ended key. **Before** confirming the uninstall in step 6, check:
  - the ended notice is shown with the contact details and **Uninstall SentinelAI**;
  - Devices, Alerts and Risk still update (B keeps reporting).
- [ ] Turn the clock on A back by two months, restart A, and check the pilot is still ended. Restore the clock.
- [ ] Enter the 30-day key again: the pilot is active.

## 5. Removing B

- [ ] In Desktop, open B in **Devices** and select **Remove computer**. B disappears from Devices and Risk, and its alerts' history is kept.
- [ ] Uninstall the Agent on B silently: `"%ProgramFiles%\SentinelAI Agent\Setup\SentinelAI-Agent-Setup.exe" /uninstall /quiet`, exit code 0. Check:
  - the service is gone;
  - the program folders are gone, except the Setup copy, which is deleted at restart;
  - the **SentinelAI Agent** entry in **Settings → Apps** is gone.

## 6. Uninstalling the central installation

- [ ] Uninstall with data kept:
  1. With the ended key entered, select **Uninstall SentinelAI** in Desktop. Desktop closes, and UAC appears.
  2. Setup opens with **Uninstall** selected and **Keep security history** checked. Uninstall.
  3. Check that the services, the firewall rule and `%ProgramFiles%\SentinelAI` are gone, and that `%ProgramData%\SentinelAI\Core\sentinelai.db` remains.
- [ ] Run the same `SentinelAI-Setup.exe` again: it offers to restore (Repair). Restore, sign in, and check that the history and the pilot key are still there.
- [ ] Uninstall with data removed:
  1. Uninstall again from **Settings → Apps → SentinelAI**.
  2. Clear **Keep security history**, type **DELETE** and uninstall.
  3. Check that `%ProgramData%\SentinelAI` and the certificate "SentinelAI Core local network" in `LocalMachine\My` are gone.

## 7. Record

- [ ] Note any SmartScreen, Smart App Control or antivirus behavior seen on each computer.
- [ ] Note anything the customer documents describe differently from what you saw, and correct the documents before release.
