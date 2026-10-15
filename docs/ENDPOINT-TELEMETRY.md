# Endpoint security telemetry

The Agent collects a fixed, bounded set of endpoint security state that the configuration inventory cannot express: BitLocker, antivirus health, Microsoft Defender status, local Administrators membership, Windows Update configuration and results, pending restart markers, the state of important security services and the machine-wide installed applications that vulnerability management needs. It sends one report, `EndpointTelemetryReport` schema version 1 (`shared/contracts/EndpointTelemetryContracts.cs`), to Core every hour. Core keeps the newest accepted report per endpoint, evaluates four deterministic rules in the same transaction and shows the state in the native Desktop endpoint details.

## Unknown is never safe

Every report section states how it was observed:

| Availability | Meaning |
| --- | --- |
| `collected` | The source was read. Individual values can still be Unknown (null). |
| `unsupported` | The platform or edition does not provide the source (for example Windows Security Center on Windows Server). |
| `accessDenied` | The Agent's account may not read the source. |
| `unavailable` | The source failed, timed out, or returned nothing usable. |

A section that is not `collected` carries no values; the contract rejects any that do. A null value is Unknown. Neither is ever shown or scored as protected, compliant or absent: rules fire only on explicit collected values, Desktop shows **Unknown** with the reason, and Risk coverage names uncollected rule inputs. Absence is turned into a value only where Windows defines it: an absent Windows Update policy is `notConfigured`, an absent restart marker means no restart is pending by that mechanism, and a service the Service Control Manager does not know is `notInstalled`.

## What is collected and why

Only the values named here are read, through documented Windows interfaces. Nothing is written, no process is started and no file content is opened.

| Section | Source | Values | Used by |
| --- | --- | --- | --- |
| `bitLocker` | WMI `root\CIMV2\Security\MicrosoftVolumeEncryption`, `Win32_EncryptableVolume` for the operating system drive only, with packet privacy | `protectionStatus` (`on`, `off`), `conversionStatus` (fully/partially encrypted or decrypted, paused) | Desktop, SA-DISK-001 |
| `antivirus` | Windows Security Center, `WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)` | `securityCenterHealth` (`good`, `notMonitored`, `poor`, `snooze`) for the registered antivirus products together | Desktop, SA-AV-001 |
| `defender` | WMI `root\Microsoft\Windows\Defender`, `MSFT_MpComputerStatus` | `runningMode` (`normal`, `passive`, `edrBlock`, `sxsPassive`), antivirus, real-time and tamper protection enabled, `signatureAgeDays` | Desktop |
| `localAdministrators` | `NetLocalGroupGetMembers` (level 1) on the group with SID S-1-5-32-544; `NetUserModalsGet` (level 2) for the machine's account domain SID | `memberCount`; up to 64 members sorted by SID, each with its SID, a derived `scope` (`local`, `domain`, `entra`, `wellKnown`) and `accountType` | Desktop least-privilege review |
| `windowsUpdate` | Registry policy `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` (`NoAutoUpdate`, `AUOptions`, `UseWUServer`); Windows Update Agent `Microsoft.Update.AutoUpdate` results | `automaticUpdatesPolicy`, `managedUpdateServer`, last successful search and installation (UTC) | Desktop; patch management input |
| `pendingReboot` | Presence of `Component Based Servicing\RebootPending` and `WindowsUpdate\Auto Update\RebootRequired`; the value names of `Session Manager` | Three restart indicators | Desktop |
| `services` | Service Control Manager, fixed catalog: WinDefend, WdNisSvc, Sense, MpsSvc, BFE, EventLog, wscsvc, SecurityHealthService, wuauserv | `state`, `startType` (the TASK-027 start-type vocabulary) | Desktop, SA-SVC-001, SA-SVC-002 |
| `software` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, 64-bit and 32-bit views | Application `name`, `version`, `publisher`, `architecture` | Stored for vulnerability management; Desktop shows counts |

Justification for local administrator data: least-privilege review needs to know how many principals hold local administrator rights and which ones, so an administrator can remove unexpected members. A SID is the minimum stable identifier for that; it can be resolved only by someone with access to the endpoint or directory. Account, group and domain names are never read into a report (the API's name field is never marshalled), and the scope is derived from the SID alone. A group larger than 64 members reports its full count and the first 64 SIDs.

Installed applications: entries without a display name, hidden system components (`SystemComponent=1`), and updates of another product (`ParentKeyName`, or `ReleaseType` Update, Hotfix, Security Update or Service Pack) are not applications. Names are trimmed; a name longer than 256 characters or containing control or format characters is not sent and is counted in `skippedCount`, as is an entry that cannot be read. Versions and publishers that cannot be carried become Unknown. The list is deduplicated, sorted, and bounded by a 192 KiB serialized budget and 2,048 items, with the full `totalCount` and `truncated` flag.

### Never collected

Passwords, credentials, BitLocker recovery keys or protectors, account, group or domain names, profile or install paths, uninstall command lines, the file paths in pending rename operations, Defender detections, exclusions or scan history, browser history, per-user registry hives and any user file. Per-user and Microsoft Store applications are therefore not covered.

## Agent collection and bounds

`EndpointTelemetryWorker` is a separate background service so that a slow platform source can never delay heartbeats, inventory or posture monitoring. It is dormant until the heartbeat worker reports an enrolled Agent that Core acknowledged (`AgentLink`). It then collects and sends one report at once, every hour after an accepted report, five minutes after a failed delivery and six hours after Core answers 400, 404, 405, 413 or 415. A newly linked endpoint reports at once; a heartbeat outage does not shorten the interval. Nothing is queued or written to disk: the next report replaces any that was not delivered.

`EndpointTelemetryCollector` reads each section on its own dedicated thread and waits at most 30 seconds in total. A section that has not returned is reported `unavailable`; its thread is kept, and that section is not read again until it returns, so a hung source occupies at most one thread per section (eight in all). A section that throws is classified (access denied, unsupported, otherwise unavailable). A section whose values the contract rejects is reported `unavailable` without values, so an Agent defect cannot make Core reject the whole report.

| Resource | Bound |
| --- | --- |
| Request | 256 KiB; the largest report the Agent can build measures 211,757 bytes |
| Applications | 8,192 uninstall keys scanned per registry view; 2,048 items and 192 KiB sent; counts up to 65,536 |
| Administrators | 64 members listed; count up to 100,000 |
| Time | 30 seconds per collection; at most one in-flight read per section |
| Frequency | One report per hour; retries no sooner than five minutes |
| Disk | None |
| Logging | Each section's availability once per change; values are never logged |

## Core persistence

`POST /api/agent/security-telemetry` checks transport (loopback or HTTPS) and authenticates the Agent before reading any body byte, then reads at most 256 KiB with strict JSON options (duplicate keys, missing required members, quoted numbers and excessive depth fail; unknown members are ignored and never stored) and validates the whole report against the contract. The body must name the authenticated endpoint. The route is rate-limited to 30 requests per minute per address and logs refusals with the endpoint ID and status code only.

Core stores one row per enrolled endpoint in `EndpointSecurityTelemetry` (created with `IF NOT EXISTS`; no existing table changes). A report replaces the stored one only when its collection time is strictly newer; an older or equal report is acknowledged with 204 and changes nothing, so retries and replays are harmless. The stored JSON is re-serialized from the validated contract. In the same immediate transaction, Core evaluates the telemetry rules on a newly stored report and records findings through the existing tracked-alert lifecycle.

Administrators read the newest report through the existing device detail route, `GET /api/admin/devices/{endpointId}`, as the additive optional `securityTelemetry` member: every section plus `collectedUtc`, `receivedUtc` and `schemaVersion`. Installed applications appear only as counts; the application list stays in Core for vulnerability management.

## Rules

Telemetry rules (`rules/TelemetryRules.cs`) are deterministic, read only collected sections and fire only on explicit values. Findings use each report's collection time, reopen a resolved alert only on newer positive evidence and are never resolved by normal or Unknown telemetry.

| Rule | Condition | Severity | Evidence | False positives |
| --- | --- | --- | --- | --- |
| SA-AV-001 Antivirus protection reported at risk | Security Center health `poor` or `snooze` | high | `antivirus.securityCenterHealth` | Short gaps while a product updates definitions or restarts; a product that registers but reports health incorrectly. |
| SA-DISK-001 Operating system volume without BitLocker protection | BitLocker `protectionStatus` `off` | medium | `bitLocker.protectionStatus`, `bitLocker.conversionStatus` | Protection suspended for planned maintenance (a real but temporary exposure); devices with an approved exception, such as some virtual machines. |
| SA-SVC-001 Windows Defender Firewall service not running | MpsSvc `stopped`, or start type `disabled` | high | `service.name`, `service.state`, `service.startType` | A third-party firewall product that replaces the Windows firewall service by design. |
| SA-SVC-002 Windows Event Log service not running | EventLog `stopped`, or start type `disabled` | high | `service.name`, `service.state`, `service.startType` | A report collected during shutdown. |

No rule is added where the evidence does not establish a weakness: Defender in passive mode or with real-time protection off is normal when another antivirus is registered (Security Center health covers that case), administrator membership is expected on many endpoints, a pending restart is routine for a short time and has no observed age, and update recency and installed applications are inputs for patch and vulnerability management.

## Risk, reports and AI

Risk policy groups the rules as `AV`, `DISK`, `FW` (with the firewall profile rules: a stopped firewall service and a disabled profile are one weakness) and `LOGGING`, with default confidence. A telemetry finding correlates only when the endpoint's latest telemetry report confirms it (`ScoringAlert.TelemetryDetection`); it is never confirmed by the inventory snapshot. The coverage caution states how many of the four telemetry rules have collected inputs, names uncollected sections with their availability, and flags a report older than three hours as stale; an endpoint without telemetry states that its rules cannot fire. The serialized Risk contract is unchanged.

Reports list telemetry findings with each rule's title, reason and recommended action and one recommendation per rule. Telemetry evidence is not on the AI evidence allowlist and is not included in report evidence or AI context.

## Desktop

The native endpoint detail adds an **Endpoint security telemetry** card: collection and receipt times, every value above with literal wording, Administrators members by SID with scope and type, each catalog service, and installed application counts. Every value that was not observed reads **Unknown** with its reason: no telemetry reported, not supported on this endpoint, not readable by the Agent's service account, or source unavailable. Desktop parses the projection strictly (types, bounds, section consistency); a vocabulary value it does not know is shown as Unknown, and an unknown schema version is not shown.

## Installed Agent account

The installed Agent runs as `NT AUTHORITY\LocalService`. That account reads the Service Control Manager, the machine-wide uninstall registry, the restart markers and the update policy. The BitLocker WMI class requires administrators, so the installed Agent reports BitLocker as `accessDenied`; Windows Security Center, the Defender WMI namespace, the local group API and the Windows Update Agent may also refuse it. Native Setup acceptance prints what the installed Agent can read. Granting more access changes a security boundary and needs the owner's decision, like Security channel access (see [security event collection](SECURITY-EVENTS.md)); the Agent collects a source at its next report after access is granted, without code change.

## Limits

- BitLocker covers the operating system volume only; fixed data volumes are not reported.
- Windows Security Center exists on client editions only; servers report `antivirus` as `unsupported`.
- Telemetry is an hourly snapshot. A change that is reverted between reports is not seen; the security event pipeline separately records Defender protection changes and protection service start-type changes.
- Windows Update Agent dates are as Windows reports them. No recent installation can also mean that no update was offered.
- Pending restart indicators carry no age.
- A local administrator can stop the Agent or falsify the sources; that remains outside the Agent's trust boundary.

## Validation

- **Contract and rules (all platforms).** Contract validation of every gate, the worst-case size proof, normalization of every raw value, application filtering, ordering and bounds, the four rules with benign, Unknown and uncollected inputs, and scoring correlation.
- **Agent (all platforms).** Bounded collection with failing, invalid and hung sections (no second concurrent read), the worker's dormancy, retry, interval and endpoint changes, and delivery to a real Core through the production Agent composition while heartbeats continue.
- **Core (all platforms).** Ingest, the device projection, newest-wins ordering, authentication before the body (bodies offered with `Expect: 100-continue` stay unsent), 23 rejection cases, rules through the alert lifecycle (open, resolve, reopen, placeholder rename), Risk correlation and coverage, report wording, restart persistence, rate limiting and log privacy.
- **Desktop.** Strict projection parsing, presentation of every Unknown reason, and the native WPF card on Windows.
- **Windows CI.** Every Windows Agent test run collects from the real sources and requires a valid report within the deadline. The elevated `--native-telemetry-acceptance` step compares each value with Windows' own tools (Get-Service, ADSI group members, CIM for BitLocker and Defender, the uninstall registry, restart markers and the Windows Update Agent) and delivers the real report to a real Core. Native Setup acceptance requires the installed LocalService Agent to deliver telemetry with services and applications collected and prints every section's availability.
