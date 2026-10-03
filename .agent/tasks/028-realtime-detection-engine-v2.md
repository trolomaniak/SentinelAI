TASK-028 — Real-Time Detection Engine v2

Objective

Add deterministic runtime detections based on continuous security observations.

Initial Detection Areas

Implement a carefully scoped first set such as:

- repeated failed logons,
- suspicious or abnormal RDP/logon conditions supported by collected evidence,
- Windows Defender detections,
- suspicious PowerShell execution patterns using bounded structured evidence,
- creation of persistence-relevant services or scheduled tasks,
- unexpected disabling of monitored protections.

Requirements

Every rule must have:

- stable rule ID,
- explicit prerequisites,
- severity,
- typed evidence,
- reason,
- recommended investigation/remediation,
- unit tests,
- documented false-positive considerations.

Constraints

AI must not decide whether the rule fires.

Do not market these detections as proof of compromise.

Definition of Done

- Runtime rules consume TASK-027 observations.
- Findings enter the existing alert lifecycle.
- Risk can consume the new supported groups/policy.
- Rules are deterministic and individually tested.
- Missing telemetry does not imply safety.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
