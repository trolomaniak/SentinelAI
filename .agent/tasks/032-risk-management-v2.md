TASK-032 — Risk Management v2

Objective

Add a formal operational Risk Register on top of technical SentinelAI findings.

Risk Record

Support:

- unique Risk ID,
- title and description,
- linked endpoint/assets,
- linked alerts/tickets,
- owner,
- likelihood,
- impact,
- inherent risk,
- existing controls,
- residual risk,
- treatment strategy,
- target date,
- review date,
- status,
- notes/history.

Treatment strategies:

- Avoid,
- Mitigate,
- Transfer,
- Accept.

Requirements

Technical endpoint score and managed business Risk must remain distinguishable.

Accepted Risk must require explicit ownership and rationale.

Expired acceptance/review dates must become visible.

Definition of Done

- Administrators can create/update/review Risk records.
- Risk records link to existing alerts/endpoints.
- History is auditable.
- Accepted risks do not silently change deterministic detection.
- Desktop provides Risk Register views and filtering.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
