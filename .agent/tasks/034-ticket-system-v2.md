TASK-034 — Ticket System v2

Objective

Create a first-class internal ticket/work-item system for security problems.

Ticket Model

Support:

- Ticket ID,
- title,
- description,
- priority P1-P4,
- status,
- reporter,
- assignee,
- linked endpoint,
- linked alerts,
- linked Risk records,
- created/updated/due timestamps,
- tags,
- comments,
- complete change history.

Initial statuses should include a documented workflow such as:

Open → In Progress → Waiting → Resolved → Closed

Requirements

Ticket state must be separate from alert detection state.

Resolving a ticket must not automatically mark a security alert Resolved unless an explicit authorized action performs that transition.

Definition of Done

- Tickets can be created, assigned, edited and closed.
- Alerts/Risks can be linked without duplication.
- Ticket history is persisted and visible.
- Desktop provides list/detail/filter/search views.
- Authorization hooks are prepared for RBAC tasks.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
