TASK-038 — Built-in RBAC: User, IT and Admin

Objective

Introduce server-enforced role-based access control with three built-in roles.

Built-in Roles

User

Primarily limited visibility to explicitly assigned information/functions.

IT

Operational access to devices, alerts, risk and tickets as defined by the permission matrix.

Admin

Administrative access including users, roles, policy, licensing, updates and organization settings.

Requirements

Define granular permissions first; roles are bundles of those permissions.

Core must enforce authorization.

Desktop visibility is convenience only and must never be the security boundary.

All denied actions must fail safely through the API.

Definition of Done

- Permission matrix is documented.
- User, IT and Admin built-in roles exist.
- Core endpoints enforce permissions.
- Desktop hides/disables unavailable features but still handles server denial.
- Existing administrator migrates to Admin.
- Authorization tests cover every protected capability category.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
