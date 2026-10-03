TASK-041 — Production Entitlements and Product Hardening

Objective

Move development licensing assumptions toward a production-ready commercial product boundary.

Requirements

Replace or extend development static entitlement provisioning with a production-capable entitlement source/process.

Support:

- plan,
- endpoint limit,
- optional feature grants,
- renewal,
- key rotation,
- clear expired/offline behavior,
- administrative visibility.

Preserve the established principle:

vendor outage, invalid cloud response or expired optional entitlement must not disable the local security baseline.

Hardening

Review production defaults for:

- configuration,
- logging,
- telemetry,
- privacy,
- release channels,
- feature gating,
- error disclosure.

Definition of Done

- Production entitlement lifecycle is documented and implemented for a controlled environment.
- Endpoint/feature enforcement is tested.
- Local monitoring remains available in Safe Mode.
- No production private key enters Core/Agent/Desktop artifacts.
- Development and production trust are clearly separated.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
