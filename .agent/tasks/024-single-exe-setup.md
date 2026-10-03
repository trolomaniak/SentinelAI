TASK-024 — Single EXE Setup

Objective

Create one installer executable that installs a complete SentinelAI Windows deployment.

Artifact

Target artifact:

`SentinelAI-Setup.exe`

Requirements

One setup executable must install and configure:

- SentinelAI Desktop,
- SentinelAI Core,
- SentinelAI Agent,
- SentinelAI Updater,
- required local configuration,
- Windows services,
- Start Menu shortcuts,
- protected Program Files / ProgramData layout.

Setup must provide clear elevation and installation progress.

It must support initial local deployment without requiring the operator to manually unpack ZIP files.

Security

Validate installation paths.

Preserve existing signed-package trust boundaries.

Do not embed production private signing keys or customer credentials.

Do not disable Windows security controls to make installation succeed.

Definition of Done

- Fresh supported Windows machine can install SentinelAI from one setup EXE.
- Core and Agent services start successfully.
- Desktop opens and can complete/authenticate setup.
- Correct ACLs are applied.
- No manual ZIP extraction is required.
- Native Windows acceptance test covers the complete path.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
