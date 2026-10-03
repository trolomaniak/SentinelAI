TASK-022 — Desktop AI, Licensing and Settings

Objective

Move the remaining operator-facing AI, licensing and essential settings workflows into Desktop.

Requirements

Desktop must expose:

- current FULL / GRACE / SAFE_MODE / RECOVERING licensing state,
- license renewal status and manual renewal action,
- permitted optional features,
- selected-alert `Explain with AI`,
- explicit AI availability/failure state,
- relevant local application settings.

AI behavior must remain assistive only.

Security

Do not expose activation credentials, signed lease bodies, gateway credentials or provider keys.

Desktop must not select arbitrary AI gateway or license destinations.

Safe Mode must preserve local monitoring and local alert/risk workflows.

Definition of Done

- License state is visible from Desktop.
- Manual renewal can be requested safely.
- AI explanation can be requested from a supported alert.
- AI outage does not block local security functions.
- No secret material appears in Desktop output/logs.
- Tests cover disabled/unavailable/Safe Mode behavior.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
