TASK-007 — Security Rules v1

Objective

Implement the first deterministic SentinelAI security detection rules.

Requirements

Create a reusable rule engine capable of evaluating normalized endpoint state.

Implement at least 10 high-value rules from the supported MVP telemetry.

Prioritize rules such as:

firewall disabled,

BitLocker disabled where applicable,

Defender/AV unhealthy,

RDP exposure/configuration risk,

unexpected local administrator,

missing security update indicators,

risky configuration state.

Each rule must produce structured output:

rule ID,

title,

severity,

reason,

evidence,

endpoint,

timestamp,

recommended action.

Design

Rules must be deterministic and auditable.

Do not use an LLM for detection.

Rules should be individually testable.

Definition of Done

reusable rule interface exists.

at least 10 rules are implemented.

each rule has tests.

triggered rules generate structured alerts.

false/normal conditions are tested.

.agent/STATUS.md is updated.
