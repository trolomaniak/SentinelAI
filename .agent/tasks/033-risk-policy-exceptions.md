TASK-033 — Risk Policy and Exceptions

Objective

Allow controlled organization-specific tuning of Risk policy without making it easy to hide security findings.

Requirements

Provide administrator-managed settings for supported policy fields such as:

- asset criticality,
- exposure,
- approved confidence overrides,
- scoring weights within validated bounds,
- correlation policy within validated bounds,
- documented exceptions,
- compensating controls.

Governance

Every policy or exception change must record:

- actor,
- time,
- old value,
- new value,
- rationale where appropriate.

Safety

Prevent invalid configurations.

Protect against removing the last meaningful risk signal through accidental global zeroing.

Exceptions must be visible in UI and reports.

Definition of Done

- Policy can be managed from Desktop by authorized roles.
- Core remains authoritative.
- All changes are validated and audited.
- Existing deterministic scoring tests remain valid or are explicitly versioned.
- Reports expose policy assumptions/exceptions.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
