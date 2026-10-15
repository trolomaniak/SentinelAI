# Deterministic endpoint rules

`RuleEngine.CreateDefault().Evaluate(EndpointState.FromInventory(report))` evaluates
the latest normalized Windows inventory snapshot. `IEndpointRule` also supports
individual evaluation and custom rule engines. Rules use only explicit observed
configuration values. Missing values and non-Windows inventories produce no
detections; they never imply a secure or insecure state.

| Rule ID | Match condition | Severity |
| --- | --- | --- |
| SA-FW-001 | Domain firewall profile explicitly disabled | high |
| SA-FW-002 | Private firewall profile explicitly disabled | high |
| SA-FW-003 | Public firewall profile explicitly disabled | high |
| SA-UAC-001 | UAC explicitly disabled | high |
| SA-UAC-002 | UAC enabled and administrator prompt behavior is 0 | high |
| SA-RDP-001 | RDP enabled and NLA explicitly not required | high |
| SA-RDP-002 | RDP enabled and security layer is native RDP (0) | high |
| SA-RDP-003 | RDP enabled, security layer is native (0) or negotiate (1), and minimum encryption level is Low (1) | medium |
| SA-SMB-001 | SMB1 server explicitly enabled | high |
| SA-SMB-002 | Insecure SMB guest logons explicitly allowed | high |
| SA-LOGON-001 | Automatic Windows logon explicitly enabled | high |
| SA-LSA-001 | LSA protection explicitly disabled | medium |
| SA-UPDATE-001 | Automatic updates explicitly disabled | high |

Each detection includes its stable rule ID, title, readable severity, reason,
typed evidence values, endpoint ID, inventory observation timestamp, and a
recommended action. Default ordering is fixed. Evaluation has no clock, I/O,
randomness, remediation, or language model dependency. Alerts describe reported
settings rather than effective protection, active services, installed patches,
or Internet exposure. BitLocker, antivirus health and security service state
come from separate endpoint telemetry with its own rules (below); unexpected
local administrators and missing patches have no rules because that telemetry
does not establish a weakness on its own.

Snapshots are evaluated on demand; results are not an incident history, and
repeat evaluation of one snapshot returns the same serialized alerts.

## Runtime event rules

`EventRuleEngine.CreateDefault()` holds twelve `SA-EVT-*` rules over the Windows
security event observations that the Agent collects. Core evaluates each batch's
newly stored observations in its ingest transaction; windowed rules read bounded
per-endpoint history ordered by event time clamped to receipt. Rules fire only on
positive evidence, have no clock, I/O, randomness or model input, and return at
most one finding per rule per batch (the latest evidence). Rule IDs, prerequisites,
evidence, reasons, recommended actions and false-positive considerations are in
[docs/EVENT-RULES.md](../docs/EVENT-RULES.md).

## Endpoint telemetry rules

`TelemetryRuleEngine.CreateDefault()` holds four rules over the hourly endpoint
telemetry report. Core evaluates a newly stored report in its ingest transaction
and records findings in the tracked-alert lifecycle. A rule reads only sections
reported as collected and fires only on explicit values; Unknown or uncollected
values never match.

| Rule ID | Match condition | Severity |
| --- | --- | --- |
| SA-AV-001 | Windows Security Center reports antivirus health poor or snoozed | high |
| SA-DISK-001 | BitLocker protection explicitly off on the operating system volume | medium |
| SA-SVC-001 | Windows Defender Firewall service (MpsSvc) stopped or set to start disabled | high |
| SA-SVC-002 | Windows Event Log service (EventLog) stopped or set to start disabled | high |

Sources, evidence, false-positive considerations and the observations that
deliberately have no rule are in [docs/ENDPOINT-TELEMETRY.md](../docs/ENDPOINT-TELEMETRY.md).
