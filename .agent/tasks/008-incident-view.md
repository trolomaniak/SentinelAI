TASK-008 — Alerts and Incident View

Objective

Provide administrators with a usable view of detected security alerts.

Requirements

Core must support:

storing alerts,

alert severity,

evidence,

status,

timestamps,

endpoint relationship.

Dashboard must provide:

alert list,

filtering by severity/status,

alert details,

evidence display,

recommended remediation,

ability to change alert status.

Use statuses appropriate for an MVP, such as:

Open

Investigating

Resolved

Accepted

UX Requirement

Every alert should answer:

What happened?

Why is it risky?

Which endpoint?

What evidence supports it?

What should the administrator do?

Definition of Done

alerts persist in Core.

dashboard shows alert list.

details page shows evidence.

administrator can update status.

API tests exist.

frontend tests/build pass.

.agent/STATUS.md is updated.
