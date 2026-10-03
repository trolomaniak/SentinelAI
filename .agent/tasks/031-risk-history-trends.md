TASK-031 — Risk History and Trends

Objective

Persist enough historical scoring information to show real Risk trends without reconstructing or fabricating past values.

Requirements

Persist bounded snapshots/events sufficient for:

- endpoint Risk history,
- organization Risk history,
- score changes over time,
- raw/capped score,
- policy/version used,
- principal factors causing a change.

Desktop

Provide selectable trend ranges such as:

- 24 hours,
- 7 days,
- 30 days,
- 90 days,

when stored data exists.

Data Policy

Define retention and bounded storage.

Do not rewrite historical scores when the current scoring policy changes; preserve the policy/version context.

Definition of Done

- Risk history survives restart.
- Trend charts use persisted historical values.
- Reports can distinguish current Risk from historical Risk.
- Retention limits are documented and tested.
- No historical score is inferred from missing history.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
