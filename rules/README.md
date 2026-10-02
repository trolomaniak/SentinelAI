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
or Internet exposure. BitLocker, antivirus health, unexpected local
administrators, and missing patches cannot be inferred from this telemetry and
have no rules until explicit supporting observations exist.

Snapshots are evaluated on demand; results are not an incident history, and
repeat evaluation of one snapshot returns the same serialized alerts.
