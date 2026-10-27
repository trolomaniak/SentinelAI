# Runtime event detections

Core evaluates a fixed set of deterministic rules over the Windows security event observations that the Agent collects ([security event collection](SECURITY-EVENTS.md)). A rule fires only on positive evidence in collected events, and its finding enters the same tracked-alert lifecycle and Risk scoring as the configuration rules.

These are detections, not verdicts. Every rule also matches benign activity, described under *False positives* below. An alert means "review this", never "the endpoint is compromised". No language model takes part: AI never decides whether a rule fires, and event-rule evidence is never sent to AI.

## How evaluation works

- **When.** Each batch the Agent delivers is stored in one Core transaction. Only the observations that batch newly stores are evaluated, in that same transaction, so an observation and the alert it raises commit together. A replayed or duplicate observation is never evaluated twice.
- **Time.** Events are ordered by their event time clamped to Core's receipt time, so a future-dated event can neither fire a rule early nor make old evidence look newer. Clamping can give a whole batch one instant, so a windowed rule also requires each counted event to be inside its window by the Agent's own event times (a constant skew keeps their spacing), and among events with the same instant it counts only those at or before the trigger in channel and record order. An Agent clock that is stepped back while events are written can therefore hide a detection, but cannot create one.
- **History.** Windowed rules read the same endpoint's stored observations of the needed kinds inside their window (at most 30 minutes, newest 4,096 rows). Observations arriving in different batches count together, while observations from other endpoints never do.
- **Alerts.** Like the configuration rules, there is at most one tracked alert per endpoint and rule. The first detection opens it. A later detection with newer evidence updates its evidence and last-observed time and reopens it if it was resolved. Older evidence never replaces newer evidence. Status changes (investigating, accepted, resolved) are made by administrators, as for every alert. Each newer detection also advances the alert's version, so while activity continues an administrator's status change can meet a conflict and is confirmed again on the latest evidence. An alert raised before the endpoint's first inventory is named `Endpoint <first 8 hex digits of its ID>` until that inventory reports the hostname.
- **Determinism.** Rules have no clock, network, storage, randomness or model input. The same observations always produce the same alerts.

## Rules

Every rule's evidence also includes `event.channel`, `event.eventId` and `event.recordId` of the triggering record, so it can be found in Event Viewer. Evidence values are typed (strings, integers, booleans) and contain only the minimized fields of [collected events](SECURITY-EVENTS.md#what-is-collected).

| Rule ID | Title | Severity | Prerequisites | Fires when |
| --- | --- | --- | --- | --- |
| SA-EVT-LOGON-001 | Repeated failed logons | medium | Security collected; logon failure auditing (Windows default) | At least 10 failed logons (4625) within 10 minutes |
| SA-EVT-RDP-001 | Remote interactive logon after repeated failures | high | Security collected; logon success and failure auditing | A logon of type 10 (RDP) succeeds from an address that had at least 5 failed logons in the previous 30 minutes |
| SA-EVT-DEF-001 | Microsoft Defender detected malware | high | Defender/Operational collected; Microsoft Defender is the active antivirus | Defender reports a detection (1116) |
| SA-EVT-DEF-002 | Microsoft Defender could not remediate a threat | critical | As DEF-001 | Defender reports that an action against a threat failed (1118, 1119) |
| SA-EVT-PROT-001 | Microsoft Defender protection disabled | high | As DEF-001 | Real-time, antispyware or antivirus protection is disabled (5001, 5010, 5012) |
| SA-EVT-PROT-002 | Protection service start type set to disabled | high | System collected | A monitored protection service (7040 for WinDefend, WdNisSvc, Sense, MpsSvc, BFE, EventLog, wscsvc or SecurityHealthService) is set to start disabled |
| SA-EVT-PROT-003 | Microsoft Defender exclusion added | medium | As DEF-001 | A path, process, extension or address exclusion is added (5007) |
| SA-EVT-LOG-001 | Windows event log cleared | high | Security collected (1102) or System collected (104) | The Security log or another event log is cleared |
| SA-EVT-PS-001 | PowerShell flagged a suspicious script block | medium | PowerShell/Operational collected; Windows PowerShell 5.1 | PowerShell logs a script block at warning level (4104, level 3), which it does automatically for content it considers suspicious |
| SA-EVT-PERSIST-001 | Service installed from a user-writable or remote location | high | System collected | A service is installed (7045) whose program is in a user profile, a temporary folder or a network location |
| SA-EVT-PERSIST-002 | Driver installed outside the Windows system folders | high | System collected | A kernel or file system driver service is installed (7045) whose program location is known and is not a Windows system folder (a temporary folder under Windows counts as outside) |
| SA-EVT-PERSIST-003 | Scheduled task created outside the Microsoft task folder | low | Security collected; Audit Other Object Access Events (Setup enables it) | A scheduled task is created (4698) outside `\Microsoft\` |

### Evidence, reasons and recommended actions

| Rule ID | Evidence (besides the event fields) | Recommended action |
| --- | --- | --- |
| SA-EVT-LOGON-001 | `logon.failedLogons`, `logon.windowMinutes`, `logon.distinctTargetAccounts` and `logon.distinctSourceAddresses` (over the failures where the value is known), `logon.failuresWithoutTargetAccount` and `logon.failuresWithoutSourceAddress` (when some are unknown), `logon.mostFrequentSourceAddress` | Identify the accounts and source addresses involved, check for password guessing or stale saved credentials, and enforce account lockout and strong authentication. |
| SA-EVT-RDP-001 | `logon.sourceAddress`, `logon.priorFailedLogons`, `logon.windowMinutes`, `logon.targetUserSid`, `logon.elevatedToken` | Confirm with the account owner that the remote session is legitimate. If it is not, disconnect it, reset the account's password, and restrict remote desktop exposure. |
| SA-EVT-DEF-001 | `malware.threatName`, `malware.threatId`, `malware.defenderSeverityId`, `malware.categoryId`, `malware.detectionId` | Review the detection in Windows Security, confirm that the threat was remediated, and investigate how the item reached the endpoint. |
| SA-EVT-DEF-002 | As DEF-001, plus `malware.actionId`, `malware.errorCode` | Isolate the endpoint if the threat is active, run a full or offline scan, and remove the threat manually if Defender cannot. |
| SA-EVT-PROT-001 | none | Confirm whether the change was authorized, re-enable protection, and check for tampering by other software or policies. |
| SA-EVT-PROT-002 | `service.name`, `service.newStartType` | Confirm whether the change was authorized, restore the service's start type, and check which account or software changed it. |
| SA-EVT-PROT-003 | `defender.settingArea`, `defender.change` | Review the exclusion in Windows Security or policy, remove it if it is not required, and confirm who added it. |
| SA-EVT-LOG-001 | `log.clearedChannel` (absent where the Windows build does not render it) | Confirm whether the clear was authorized maintenance. If not, treat earlier activity on the endpoint as unknown and review other evidence sources. |
| SA-EVT-PS-001 | `script.blockId`, `script.partCount` | Review the script block in the PowerShell/Operational log, identify the script and the account that ran it, and confirm whether it is expected. |
| SA-EVT-PERSIST-001 | `service.name`, `service.imageFileName`, `service.imageLocation`, `service.serviceType`, `service.startType`, `service.accountKind` | Identify the software that installed the service, verify the program's publisher and signature, and remove the service if it is not expected. |
| SA-EVT-PERSIST-002 | As PERSIST-001 | Identify the software that installed the driver, verify its publisher and signature, and check it against known vulnerable drivers before allowing it. |
| SA-EVT-PERSIST-003 | `task.name`, `task.subjectUserSid` | Review the task in Task Scheduler, identify the program it runs and the account that created it, and delete it if it is not expected. |

Absent evidence fields mean the value was not collected or not readable. The rule still fired on the rest of the evidence, and the missing value is not a negative result.

### False positives

| Rule ID | Common benign causes |
| --- | --- |
| SA-EVT-LOGON-001 | Mistyped or expired passwords; services, scheduled tasks or mapped drives with stale saved credentials; vulnerability scanners and authorized password audits. Windows usually logs a failed logon with the NULL SID, even for a wrong password on an existing account, so most alerts report the failures under `failuresWithoutTargetAccount` rather than as distinct accounts. |
| SA-EVT-RDP-001 | A legitimate user who mistyped a password several times; several users behind one NAT or VPN address, so the failures and the success may come from different people. |
| SA-EVT-DEF-001 | Test files such as EICAR; potentially unwanted applications the organization allows; Defender false positives on internal tools. A detection that Defender remediated is still reported. |
| SA-EVT-DEF-002 | Locked or in-use files that Defender remediates after a reboot; detections in archives or network locations Defender cannot modify. |
| SA-EVT-PROT-001 | Another antivirus product taking over (Defender turns real-time protection off); authorized troubleshooting; management policy. |
| SA-EVT-PROT-002 | Planned replacement by another security product; authorized troubleshooting. Start type changes to manual (demand) are not reported. |
| SA-EVT-PROT-003 | Exclusions added by administrators or management tools for developer, backup or database software. The exclusion value itself is not collected. |
| SA-EVT-LOG-001 | Authorized maintenance or lab resets; clearing of application logs by their own software. |
| SA-EVT-PS-001 | Legitimate administration and management scripts that use features PowerShell treats as suspicious (dynamic code, reflection, `Add-Type`, encoded content). The script text is never collected; review it on the endpoint. |
| SA-EVT-PERSIST-001 | Per-user installers and updaters that run services from the user profile; software deployed from a network share. |
| SA-EVT-PERSIST-002 | Hardware, virtualization, VPN and security software that installs drivers under Program Files or ProgramData. |
| SA-EVT-PERSIST-003 | Software updaters and installers (browsers, office suites, vendor tools) routinely create tasks outside `\Microsoft\`; hence low severity and reduced Risk confidence. |

## Missing telemetry is not safety

A rule that cannot see its channel cannot fire, and no alert is never the same as "nothing happened". Setup gives the installed Agent read access to the Security channel and enables the auditing 4698 needs (see [channel access](SECURITY-EVENTS.md#channel-access-and-localservice)); where a domain Group Policy removes either, SA-EVT-LOGON-001, SA-EVT-RDP-001 and SA-EVT-PERSIST-003 cannot fire and SA-EVT-LOG-001 sees only System 104. Gaps (overwritten, reset, dropped or rejected records, coverage restarts) also hide events from every rule.

Risk coverage states this for each endpoint. Its caution names the event channels that are not collecting (including `not reported` and statuses older than two hours, marked `stale`) and how many of the 12 event rules can fire, for example `11 of 12 event rules can fire; channels not collecting: Microsoft-Windows-PowerShell/Operational (accessDenied)`. The event-sources route lists gaps and per-channel states. Audit policy is not reported, so a disabled audit category (for example scheduled task auditing) is indistinguishable from no activity.

## Risk

Event alerts are scored like any tracked alert: severity points × confidence × asset × exposure × age × remaining risk. Policy defaults assign them their own correlation groups, and reduce confidence for rules that commonly match benign activity:

| Group | Rules |
| --- | --- |
| EVT-AUTH | SA-EVT-LOGON-001 (confidence 0.5), SA-EVT-RDP-001 |
| EVT-MALWARE | SA-EVT-DEF-001, SA-EVT-DEF-002 |
| EVT-DEFENSE | SA-EVT-PROT-001, SA-EVT-PROT-002, SA-EVT-PROT-003 (confidence 0.75), SA-EVT-LOG-001 |
| EVT-EXECUTION | SA-EVT-PS-001 (confidence 0.5) |
| EVT-PERSISTENCE | SA-EVT-PERSIST-001, SA-EVT-PERSIST-002, SA-EVT-PERSIST-003 (confidence 0.5) |

A configuration finding correlates only when the latest inventory snapshot reconfirms it. An event detection's evidence is the event itself, so it correlates while its evidence is fresh (at most 7 days). Its contribution reports `latestSnapshotConfirmed: false`. Age then weights it down as for every alert (0.75 after 7 days, 0.5 after 30), and it keeps contributing until an administrator resolves it.

## Privacy, AI and reports

Alerts store only the minimized observation fields listed above. These are SIDs, IP addresses, service and task names, a service program's file name and location class, and Defender threat metadata. Account names, script text, command lines and full file paths are never stored. Administrators see this evidence in alert details and incident exports. The evidence belongs to the tracked alert, so it is kept until a newer detection of the same rule on the same endpoint replaces it, independent of the 30-day observation retention. No event rule is on the AI evidence allowlist, so event alerts are never sent to the AI gateway. Reports list event alerts with their rule title, severity, status, reason and recommended action, with a separate recommendation per rule, and never include their evidence.

## Validation

- **Rules (`SentinelAI.Rules.Tests`).** One isolated positive case per rule with typed evidence and the trigger's effective time. The two windowed rules also have thresholds just below the limit, windows exceeded (failures spread over more than ten minutes, failures older than thirty minutes), failures from other or unknown addresses, non-RDP logon types, and failures without a target SID or address. Every payload-dependent rule (RDP-001, PROT-002, PROT-003 and the PERSIST rules) has benign and unknown-value cases that must not fire. Also covered: clamping of future event times, batches clamped to one instant by an Agent clock that is ahead, one finding per rule per batch with the latest evidence, determinism, and rejection of inconsistent rule sets.
- **Core (`SecurityEventApiTests`, C12).** A real Core with enrolled synthetic endpoints. It checks that failed logons below the threshold, or split across endpoints, raise nothing, and that a later batch completing the burst raises the alert with typed evidence and event time. It then checks that a replay changes nothing, that Risk scores, groups and correlates fresh event alerts, and that coverage names an uncollected channel and an endpoint without telemetry. Reports present the event alerts with their own rule wording and one recommendation per rule, without evidence. Finally, a resolved alert reopens on new evidence, older evidence never replaces newer, and the first inventory replaces the placeholder endpoint name without changing the alert's version.
- **Scoring (`SentinelAI.Scoring.Tests`).** Event detections correlate on freshness with policy groups and confidence, stale ones do not, and the snapshot rule still applies to every other alert.
