# SentinelAI product scope

This describes the implemented pilot. [MVP](MVP.md) defines its deployment and delivery; the development status in `.agent/STATUS.md` records validation. The original Word specification contains broader plans and is not a list of delivered features.

## Customer and outcome

SentinelAI helps the administrator of a small Windows environment identify supported security configuration problems, investigate selected security events, prioritize findings and produce a local report. A small IT provider can evaluate it with one customer installation; there is no shared multi-tenant MSP console.

One central computer runs Core, Desktop, Updater and its own Agent. Other computers in the same local subnet run only the Agent. The supported pilot platforms are Windows 10 22H2 x64 and Windows 11 x64. Core continues running when Desktop closes or the internet is unavailable.

## Delivered capabilities

| Area | Current behavior |
| --- | --- |
| Installation | Separate central and Agent installers; owned central upgrade, repair, rollback, recovery, retained-data restore and explicit uninstall. |
| Enrollment | Administrator-created one-use codes containing the local Core address and certificate pin; expired, revoked and used codes are refused. |
| Visibility | Inventory, connection/freshness status, configuration changes, selected minimized Windows events and endpoint security telemetry. Missing observations remain Unknown with their reason. |
| Findings | Deterministic configuration, event and endpoint-telemetry rules; known vulnerability findings when signed curated data covers the observed product/version. |
| Investigation | Alert evidence, recommendations, persisted decisions and history; conflicting edits require review. |
| Priorities | Explained local endpoint/organization risk scores, plus a separate business Risk Register with owners, treatment and reviews. |
| Reporting | Local HTML reports in the installation language, generated offline from retained data. Current posture is distinguished from period incident activity. |
| Updates | Automatic Agent updates from Core, explicit central Setup upgrades, and optional owner-server central updates when enabled by an administrator. |
| Pilot licensing | Signed offline key for a named company and a bounded period; monitoring continues after the pilot expires. |
| Language | Polish and English for Desktop, both installers, Core's user-facing texts and reports. |

## Boundaries of the offer

- Rules evaluate their documented observations. They do not establish that an endpoint is free of compromise. SentinelAI does not scan for malware, patch software or automatically remediate findings.
- Vulnerability matching needs signed owner data and covers a curated product list. An absent match or an absent feed does not establish that software is current or safe.
- Security event access and auditing depend on Windows permissions and domain policy. Coverage and observation times matter when interpreting results.
- Historical risk-score trends, a multi-tenant MSP service, Linux/macOS Agents and enterprise availability guarantees are outside the delivered pilot.
- Assistive cloud AI requires separate configuration, entitlement, session consent and an explicit request. It neither decides detections nor changes endpoints. The pilot's local value does not depend on AI.
- Pricing after the free pilot is an owner decision; the repository does not establish a validated paid subscription offer.

## Pilot delivery and validation

The owner builds the two installers with the explicitly provisioned public trust and contact details, delivers the signed pilot key separately and makes checksums available through the trusted distribution channel. Installer Authenticode signing and public release hosting are not supplied by the repository.

Before a customer deployment, record the results for that exact release using the [two-computer checklist](pilot/PILOT-TEST-CHECKLIST.md). Native CI and portable tests provide complementary evidence; neither is a recorded Windows 10/11 customer-network trial. Pilot validation should capture installation effort, useful and confusing findings, report usefulness, support needs and the customer's willingness to continue.

The customer-facing descriptions and IT instructions are in [Polish](pilot/SentinelAI-dla-firm.pl.md) and [English](pilot/SentinelAI-for-business.en.md). [Security boundaries](SECURITY.md) and the linked technical documentation explain how the local installation handles authority and data.
