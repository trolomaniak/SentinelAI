# SentinelAI for your business

*Pilot version. Polish version: [SentinelAI dla firm](SentinelAI-dla-firm.pl.md). Technical details for IT: [IT guide](SentinelAI-IT-guide.en.md).*

## What SentinelAI is

SentinelAI watches the security of the Windows computers in a small company and tells you, in one place, what needs attention. It answers questions such as: Is disk encryption on? Is the antivirus healthy? Are automatic updates switched on, and when were updates last installed? Is a computer waiting for a restart? Did Microsoft Defender find malware? Which computer is the biggest risk right now?

It is meant for companies without a security team. It does not replace your antivirus; it checks that the protection you already have is switched on and working, and it points out risky settings and suspicious events.

## What it monitors

Only what is listed here is implemented today:

- **Devices and software:** computer name, Windows version, processor, memory, disks, and the list of installed applications (name, version, publisher) installed for the whole computer.
- **BitLocker:** whether the Windows system drive is encrypted and protected.
- **Antivirus and Microsoft Defender:** antivirus health reported by Windows Security, and Defender's real-time and tamper protection and how old its signatures are.
- **Windows Firewall:** whether each firewall profile is switched on, and whether the firewall service is running.
- **Windows Update:** the automatic update setting and when updates were last searched for and installed.
- **Pending restarts:** whether Windows is waiting for a restart to finish updates.
- **Risky settings:** for example User Account Control switched off, Remote Desktop without network-level authentication, the old SMB1 file sharing protocol, automatic sign-in, and local administrator accounts.
- **Security event detections:** for example Microsoft Defender finding malware or being switched off, an event log being cleared, a service or driver installed from an unusual place, or PowerShell flagging a suspicious script. This includes detections from the Windows Security log (repeated failed sign-ins, risky Remote Desktop sign-ins, new scheduled tasks and clearing of the Security log): Setup gives the Agent read-only access to that log and turns on the Windows auditing of new scheduled tasks, and uninstalling undoes both. Detections work on Windows in any language, including Polish.
- **Risk score:** each computer gets a score from 0 to 100 with an explanation, and the company's score is that of its riskiest computer.
- **Alerts and incidents:** each finding becomes an alert with evidence and a recommended action. You mark it as investigating, accepted or resolved.
- **Reports:** a security report for a chosen period, saved as an HTML file.

Alerts are raised for risky settings and detections. The other values, such as pending restarts, Defender details and local administrators, are shown in Desktop for you to review.

## How it works

- **One central computer** in the company runs SentinelAI: the central service (Core), the Desktop application where you see everything, and its own Agent.
- **Every other computer** runs only the small SentinelAI Agent, which reports to the central computer over your local network.
- **Your data stays in your company.** Everything is stored on the central computer. SentinelAI does not send your data to us or to any cloud service, and the pilot makes no internet connections.

## What is collected and what is not

**Collected:** the device information, security settings and status listed above, the names, versions and publishers of installed applications, and a fixed list of Windows events (from the System, PowerShell and Microsoft Defender logs) with only the fields needed for detection. User accounts appear only as technical identifiers (SIDs), never as names.

**Not collected:** passwords or other credentials, BitLocker recovery keys, the content of files, documents or e-mails, browser history, the text of PowerShell scripts, event message texts, user, group or domain names, and apps installed only for one user or from the Microsoft Store.

## Pilot terms

- **Free** for the pilot period.
- **Time-limited:** your pilot key is valid for the period we agree, typically 30 to 90 days. Desktop shows how many days are left and reminds you seven days before the end.
- **No limit** on the number of computers.
- **At the end of the pilot:** all monitoring keeps working. Desktop shows a notice asking you to get in touch, with our contact details, and offers **Uninstall SentinelAI**. Uninstalling keeps your data unless you explicitly choose to delete it. A new key extends the pilot at any time.

## Requirements

- Windows 10 version 22H2 (64-bit) or Windows 11 (64-bit) on every computer.
- One central computer that stays switched on, with a fixed IP address or a computer name the other computers can find.
- All computers in the same local network (the same subnet), with Windows set to a **Private** or domain network, not **Public**.
- A Windows administrator account to install, on each computer.

## How to start in three steps

1. **Install on the central computer.** Download the files, check them as described in the IT guide, run `SentinelAI-Setup.exe`, enter your pilot key and create the SentinelAI administrator account.
2. **Add the other computers.** In Desktop, open **Devices → Add computers** to create one code per computer. On each computer, run `SentinelAI-Agent-Setup.exe` and paste its code.
3. **Review the results.** In Desktop, look at **Devices**, **Alerts** and **Risk**, and generate a report in **Reports**.

## Honest limitations

- **This is pilot software.** It is tested automatically on Windows, including real installations in our build system, but it is not yet used in many companies. It has not been audited by an independent security firm, and we make no compliance or certification claims.
- **The installers are not code-signed.** Windows SmartScreen will warn that the publisher is unknown. Always check the downloads against the published SHA-256 checksums before running them. Smart App Control or some antivirus or EDR products may block unsigned programs.
- **Windows only.** There is no Linux or macOS version yet.
- **Desktop only on the central computer.** Alerts and reports are viewed there; there is no web or mobile access.
- **No automatic updates.** We provide new versions; you run them on the central computer, and the Agents on the other computers are reinstalled with new codes.
- **English interface.** The program itself is in English.

## Contact

[Company name] · [e-mail address] · [phone number] · [website]

## Frequently asked questions

**Will SentinelAI slow my computers down?** The Agent reads a fixed set of settings and events: a short status message every 30 seconds, the device inventory every six hours and within seconds after a monitored setting changes, the security status every hour, and new events as they happen.

**Does SentinelAI change anything on our computers?** The Agent only reads; it never changes Windows settings or your files. Changing a setting or removing a threat is always done by you. Setup itself changes only what monitoring needs: the firewall rule on the central computer, and on every computer the Agent's read access to the Security log and the auditing of new scheduled tasks. Uninstalling undoes these changes.

**Do you see our data?** No. Everything stays on your central computer and nothing is sent to us.

**What if the central computer is switched off?** The Agents keep trying to reach it and report again when it is back. Desktop shows when each computer last reported.

**What happens when the pilot ends?** Monitoring continues. Desktop asks you to contact us and offers an uninstall option.

**How do we remove SentinelAI?** Remove each computer in Desktop and uninstall **SentinelAI Agent** from Windows **Settings → Apps**. Uninstall SentinelAI on the central computer the same way; your data is kept unless you type **DELETE** to remove it.
