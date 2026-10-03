TASK-025 — Setup Upgrade, Repair and Uninstall

Objective

Make the single installer safe for the complete application lifecycle.

Requirements

Support:

- fresh install,
- repair,
- upgrade,
- uninstall,
- detection of an existing installation,
- version comparison,
- transactional replacement of code,
- rollback when health verification fails.

Integrate the existing signed update and transactional updater foundation instead of creating an unrelated updater path.

Data

Normal upgrade and repair must preserve:

- Core SQLite,
- installation identity,
- endpoint enrollment,
- Agent DPAPI state,
- protected configuration,
- license state.

Uninstall must not silently delete security history or configuration.

Definition of Done

- Upgrade from an older supported build succeeds.
- Failed upgrade rolls back to a working version.
- Repair restores damaged program files without resetting identity.
- Uninstall removes owned services/code predictably.
- Data removal is explicit rather than accidental.
- Installation lifecycle tests run on Windows.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
