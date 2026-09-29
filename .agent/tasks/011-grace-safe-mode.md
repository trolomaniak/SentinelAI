TASK-011 — Grace Period and Safe Mode

Objective

Implement SentinelAI licensing state transitions during loss of Internet connectivity.

Required States

Implement:

FULL

GRACE

SAFE_MODE

RECOVERING

REVOKED where supported by the current License API.

Required Behavior

Successful license validation:

FULL

No connection but last successful validation < 7 days:

GRACE

More than 7 days without successful validation:

SAFE_MODE

Successful validation after connectivity returns:

return to FULL.

Safe Mode

The following must continue:

critical telemetry collection,

local detection rules,

critical alerts,

access to recent incidents,

emergency export.

Premium/cloud-dependent features may be disabled.

Security Requirements

Implement reasonable protection against obvious clock rollback using trusted server time and locally persisted state.

Do not create a mechanism that can disable core security monitoring because the vendor service is unavailable.

Definition of Done

state machine is explicit.

transitions are tested.

automated test simulates >7 days without successful validation.

Safe Mode behavior is enforced.

connectivity restoration returns system to FULL after successful validation.

.agent/STATUS.md is updated.

