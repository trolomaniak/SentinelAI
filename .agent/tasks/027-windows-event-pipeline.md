TASK-027 — Continuous Windows Event Pipeline

Objective

Add a bounded continuous Windows security event collection pipeline.

Initial Sources

Subscribe only to explicitly selected useful channels such as:

- Windows Security,
- System,
- Microsoft-Windows-PowerShell/Operational,
- Microsoft-Windows-Windows Defender/Operational,

where permissions and platform support allow.

Requirements

Normalize selected events into typed internal observations.

Provide:

- checkpoints/bookmarks,
- bounded local buffering,
- backpressure,
- duplicate handling,
- restart recovery,
- event-size limits,
- explicit source/version metadata.

Security and Privacy

Do not ingest all logs indiscriminately.

Do not collect arbitrary message text when stable structured fields are sufficient.

Never collect stored credentials.

Document which event IDs/fields are collected and why.

Definition of Done

- Selected Windows event streams are consumed continuously.
- Restart does not cause uncontrolled duplicate processing.
- Core outage is handled with bounded buffering.
- Resource usage remains controlled.
- Tests use synthetic events and do not contain real customer telemetry.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
