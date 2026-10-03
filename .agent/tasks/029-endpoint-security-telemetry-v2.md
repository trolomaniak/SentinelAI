TASK-029 — Endpoint Security Telemetry v2

Objective

Collect additional bounded endpoint security state needed for meaningful posture management.

Initial Telemetry

Add explicit observations for:

- BitLocker state,
- Windows Defender / registered antivirus health where supported,
- local administrator membership,
- Windows Update configuration/status,
- pending reboot indicators,
- important security service state,
- installed software inventory needed by vulnerability management.

Requirements

Represent unavailable or unsupported values as Unknown.

Do not infer security from absence of data.

Collect only fields required by documented features.

Security and Privacy

Do not collect passwords, recovery keys, browser history or arbitrary user files.

Local administrator data must be minimized and justified.

Definition of Done

- New telemetry is versioned in contracts.
- Agent collection is bounded and tested.
- Core persists the newest accepted observations safely.
- Desktop exposes supported posture with explicit Unknown states.
- New deterministic rules are added only where evidence is sufficient.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
