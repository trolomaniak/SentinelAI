TASK-005 — Endpoint Inventory

Objective

Collect and report basic endpoint information from the Windows Agent to Core.

Required Data

Collect at minimum:

hostname,

OS name,

OS version,

architecture,

CPU information,

installed RAM,

disk information,

basic security posture status where readily available.

Include:

collection timestamp,

Agent version,

endpoint identifier.

Requirements

Inventory collection must be bounded and lightweight.

Do not perform full disk scans.

Avoid expensive operations.

Handle unavailable Windows APIs gracefully.

Agent sends inventory to Core.

Core persists the most recent inventory.

Privacy

Collect only data required for the MVP.

Do not collect user documents or arbitrary file contents.

Definition of Done

Agent collects inventory on supported Windows environment.

Inventory reaches Core.

Core stores latest state.

malformed inventory is rejected safely.

collection failures do not stop the Agent.

tests exist.

.agent/STATUS.md is updated.
