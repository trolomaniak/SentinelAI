TASK-036 — Multi-User Identity

Objective

Replace the single-administrator assumption with secure local multi-user identity management.

Requirements

Support:

- multiple local user accounts,
- enabled/disabled state,
- display name,
- secure password storage using Core,
- password change,
- administrator-initiated reset workflow,
- password policy,
- lockout/rate limiting,
- last successful login metadata,
- forced password change where appropriate.

Migration

Existing administrator must migrate safely into the new identity model without loss of access.

Security

Do not expose password hashes.

Do not create default shared passwords.

Prevent deletion/disablement states that leave the system without a recoverable administrator path.

Definition of Done

- Multiple users can authenticate independently.
- Disabled/locked accounts cannot sign in.
- Existing administrator remains valid after migration.
- Identity changes are audited.
- Tests cover migration and lockout edge cases.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
