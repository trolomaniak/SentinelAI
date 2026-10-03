TASK-039 — Fully Customisable RBAC

Objective

Allow administrators to create custom roles with granular control over SentinelAI capabilities.

Requirements

Provide a permission catalog covering relevant actions, for example:

- Devices.Read,
- Alerts.Read,
- Alerts.ChangeStatus,
- Risk.Read,
- Risk.Manage,
- Tickets.Read,
- Tickets.Create,
- Tickets.Assign,
- Reports.Generate,
- Reports.Export,
- AI.Use,
- Users.Manage,
- Roles.Manage,
- Policy.Manage,
- Licensing.Manage,
- Updates.Manage,
- Audit.Read.

Support custom role create/edit/delete and user-role assignment.

Where scope is introduced, support explicit endpoint/group scope rather than implicit hostname patterns.

Safety

Prevent accidental removal of all principals capable of managing roles/users.

Authorization must be fail-closed.

Definition of Done

- Custom roles can be built from explicit permissions.
- Permission changes take effect predictably.
- Every permission-changing action is audited.
- Last-admin/lockout protections exist.
- Server-side authorization tests cover custom combinations.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
