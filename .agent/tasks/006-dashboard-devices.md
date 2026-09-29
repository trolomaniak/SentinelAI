TASK-006 — Dashboard Device List

Objective

Create the first useful SentinelAI dashboard view showing monitored endpoints.

Requirements

Implement a dashboard page displaying:

endpoint name,

operating system,

health state,

last seen,

Agent version,

basic security posture summary.

Create endpoint details navigation.

Core must expose the required API.

UX Requirements

The dashboard should prioritize clarity over information density.

Clearly distinguish:

healthy,

warning,

offline/unknown.

Avoid presenting raw internal database structures.

Out of Scope

Do not implement:

full incident dashboard,

AI Assistant,

reporting,

MSP multi-tenancy.

Definition of Done

Device list loads from Core.

Health/last-seen values are visible.

endpoint detail page exists.

loading/error/empty states exist.

frontend build passes.

relevant tests pass.

.agent/STATUS.md is updated.
