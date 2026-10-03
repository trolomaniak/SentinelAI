TASK-017 — Core Windows Service

Objective

Make SentinelAI Core operate as a managed Windows background service so protection does not depend on an open console or desktop window.

Requirements

Core must:

- support Windows Service hosting,
- start automatically according to an explicit installer-managed policy,
- preserve existing console/development hosting,
- use the existing protected configuration and data locations,
- stop gracefully,
- recover predictably after service failure,
- expose health required by installation and update verification.

Closing `SentinelAI.exe` must not stop Core.

Constraints

Do not change Agent enrollment semantics or local security rules.

Do not move secrets into service command-line arguments.

Do not weaken the existing loopback/HTTPS security requirements.

Security

Use an explicitly selected limited service identity where practical.

Document service-account privileges, filesystem ACL requirements and recovery behavior.

Definition of Done

- Core can be installed and started as a Windows Service.
- Core survives desktop application exit.
- Existing SQLite state and administrator identity persist across service restarts.
- Service stop/start/restart behavior is tested.
- Console development mode remains supported.
- No credentials appear in service arguments or logs.
- `.agent/STATUS.md` and architecture documentation are updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
