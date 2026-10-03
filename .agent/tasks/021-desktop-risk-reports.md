TASK-021 — Desktop Risk and Reports

Objective

Move Risk and reporting workflows into the native Desktop application.

Requirements

Risk UI must display:

- organization score,
- ranked endpoints,
- endpoint score,
- raw score,
- saturation,
- severity contribution,
- confidence weight,
- asset criticality,
- declared exposure,
- age multiplier,
- remediation/status effect,
- correlation bonus,
- coverage/freshness information.

Reports must be generated through the existing Core reporting implementation and be accessible from Desktop.

Constraints

Do not replace deterministic RiskScorer calculations with AI.

Do not invent historical risk trends in this task.

Definition of Done

- Organization and endpoint Risk views work natively.
- Explanations expose contributing factors rather than only a number.
- Report date selection/generation/download is available from Desktop.
- Existing deterministic scoring output matches prior API behavior.
- Existing report privacy and Safe Mode guarantees remain intact.
- Tests cover risk presentation and report workflow.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
