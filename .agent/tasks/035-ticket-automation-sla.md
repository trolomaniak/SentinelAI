TASK-035 — Ticket Automation and SLA

Objective

Add controlled automation and service-level tracking to the ticket system.

Requirements

Support configurable policies for:

- automatic ticket creation from eligible alerts,
- minimum severity,
- deduplication/linking,
- default assignment/team,
- SLA response target,
- SLA resolution target,
- overdue status,
- escalation,
- reopen/link behavior when a related risk reappears.

Notifications

Desktop should expose:

- My Tickets,
- Unassigned,
- Overdue,
- SLA at risk,
- newly assigned/high-priority notifications.

Safety

Automation must be deterministic and explain why a ticket was created or escalated.

Avoid ticket storms from repeated identical observations.

Definition of Done

- Synthetic repeated alerts do not create uncontrolled duplicate tickets.
- SLA timers survive restart.
- Escalation/audit history is persisted.
- Manual override remains possible for authorized users.
- Tests cover time boundaries and deduplication.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
