TASK-019 — Desktop Devices and Endpoint Details

Objective

Replace the browser Devices experience with a native Desktop implementation.

Requirements

Desktop must display:

- enrolled endpoints,
- hostname,
- operating system and release/build information,
- Agent version,
- heartbeat health,
- last inventory time,
- configured firewall posture,
- endpoint detail information already exposed by Core.

Preserve existing health semantics and explicit Unknown states.

UX

Provide sortable/filterable device presentation suitable for larger fleets.

The UI must clearly distinguish connectivity health from security posture.

Security

Do not expose enrollment credentials, password hashes, raw secret configuration or private SQLite records.

Definition of Done

- Desktop lists enrolled endpoints from Core.
- Endpoint detail opens without a browser.
- Healthy/warning/offline/unknown states match Core semantics.
- Missing inventory remains explicit rather than inferred.
- UI handles loading, no-data and Core-unavailable states.
- Relevant automated tests pass.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
