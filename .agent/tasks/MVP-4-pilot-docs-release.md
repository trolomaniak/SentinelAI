MVP-4 — Pilot Documentation and Release Checklist

Objective

Give pilot companies clear documentation of what SentinelAI is and how it works. There is one document for the business and one for IT, each in Polish and English. Also give the owner a repeatable way to build the pilot release and test it on real computers.

Requirements

Write exactly four customer documents in `docs/pilot/`, with equivalent content in both languages:

- `SentinelAI-dla-firm.pl.md` — for the business, Polish
- `SentinelAI-for-business.en.md` — for the business, English
- `SentinelAI-przewodnik-IT.pl.md` — for IT, Polish
- `SentinelAI-IT-guide.en.md` — for IT, English

The business documents, in plain language, cover:

- what SentinelAI is and which problems it addresses;
- what it monitors, listing only implemented capabilities: device and software inventory, BitLocker, Defender, firewall and Windows Update status, pending restarts, security event detections, risk score, alerts and incidents, and reports;
- how it works: one central computer and an Agent on each computer, with data staying inside the company;
- what is collected and what is not;
- the pilot terms: free, time-limited (30–90 days), no endpoint limit, and what happens at the end (monitoring continues, a request to get in touch, an uninstall option);
- requirements;
- how to start in three steps;
- honest limitations:
  - pilot software;
  - the installer is not code-signed, so Windows SmartScreen warns;
  - Windows only, with no Linux or macOS yet;
  - Desktop only on the central computer;
- a contact placeholder;
- a short FAQ.

The IT documents cover:

- architecture: components, services, accounts and data locations;
- network: the port, the firewall rule and its profiles, local network only, TLS 1.3 with 1.2 only on Windows 10, and certificate pinning by fingerprint;
- requirements: Windows 10 22H2 or Windows 11 x64, and an always-on central computer with a fixed IP address or DNS name;
- central installation step by step, including the SmartScreen "More info → Run anyway" step and SHA-256 verification of the downloads;
- adding computers: codes, the interactive install, and silent install with a code file, with GPO and Intune examples;
- removing a computer, uninstalling the Agent and uninstalling the central installation (retained data versus confirmed removal);
- the pilot key and its expiry;
- updates and repair;
- troubleshooting:
  - Agent cannot connect;
  - pin mismatch;
  - firewall;
  - IP address change;
  - Smart App Control or antivirus/EDR blocking unsigned programs;
- a security model summary.

Every statement must match the behavior implemented by MVP-1 to MVP-3 and the existing code. Claim nothing that is not implemented, and check each one against the code and tests before writing it.

Also:

- `docs/MVP.md` is completed as the source of truth for the pilot scope, decisions and known limitations, and `README.md` links the four documents.
- A release script, for example `scripts/publish-pilot-release-windows.ps1`, builds `SentinelAI-Setup.exe` and `SentinelAI-Agent-Setup.exe`. It:
  - takes the owner's production pilot and update public keys and the contact settings as inputs, never private keys;
  - writes `SHA256SUMS.txt`;
  - copies the four documents into one release folder ready to upload to the owner's server.
- An internal checklist, `docs/pilot/PILOT-TEST-CHECKLIST.md`, covers a manual test on at least two real computers in one network, one Windows 10 and one Windows 11:
  - central install;
  - adding the second computer;
  - an alert appearing;
  - a pilot key near expiry and after expiry;
  - removing a computer;
  - both uninstalls.

Constraints

- No secrets, private keys, real customer data or personal contact details in the repository; use placeholders.
- No marketing claims beyond the implemented behavior, and no compliance or certification claims.

Definition of Done

- The four documents are complete, equivalent in both languages and consistent with the code.
- An independent review compares every factual statement with the implementation.
- The release script runs in Windows CI with development keys and produces both installers, the checksums and the documents.
- The checklist exists.
- `.agent/STATUS.md` is updated.

Development sequence

MVP-1 → MVP-2 → MVP-3 → MVP-4, before TASK-030. One scoped branch and one Pull Request; do not merge to main.
