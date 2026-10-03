TASK-020 — Desktop Alerts and Incident Workspace

Objective

Provide the complete existing alert and tracked-incident workflow in the native Desktop application.

Requirements

Desktop must support:

- alert list,
- endpoint filtering,
- severity filtering,
- status filtering,
- alert detail,
- rule ID and title,
- reason,
- typed evidence,
- recommended action,
- first/latest observation,
- status history,
- Open / Investigating / Accepted / Resolved transitions.

Preserve current alert lifecycle semantics.

Constraints

Changing status is an administrator/operator decision and must not modify endpoint configuration.

Normal or unknown telemetry must not silently resolve tracked alerts.

Security

Status writes must continue using optimistic/version checks where already required.

Never render untrusted strings as executable content.

Definition of Done

- Existing alert/incident workflows are usable entirely from Desktop.
- Status changes persist and history is visible.
- Stale conflicting writes are handled safely.
- New positive observations can reopen resolved alerts according to existing policy.
- Relevant tests cover UI state and Core integration behavior.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
