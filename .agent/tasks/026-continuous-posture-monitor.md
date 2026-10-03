TASK-026 — Continuous Posture Monitor

Objective

Detect changes to security posture promptly instead of relying only on the six-hour inventory refresh.

Requirements

Implement event-driven or appropriately bounded monitoring for configuration fields used by current deterministic rules.

When a relevant posture setting changes:

- collect the affected bounded state,
- produce a new trusted observation,
- send it to Core promptly,
- evaluate rules,
- update tracked alerts and Risk on the next read.

Keep periodic inventory as a reconciliation/fallback mechanism.

Performance

Avoid busy polling.

Coalesce duplicate rapid changes.

Bound CPU, memory, disk and network usage.

Reliability

Temporary Core unavailability must not crash the Agent.

Queue/retry behavior must be bounded and documented.

Definition of Done

- A supported security-setting change is reflected in SentinelAI within seconds/minutes, not hours.
- Duplicate bursts do not create unbounded work.
- Existing six-hour inventory remains as reconciliation.
- Restart/outage behavior is tested.
- Current deterministic rules keep their existing meaning.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
