TASK-016 — Native Desktop Foundation

Objective

Create the native Windows desktop application that becomes the primary SentinelAI user interface.

Architecture

Create a new `SentinelAI.Desktop` project targeting .NET 10 and Windows x64.

Use WPF with an MVVM-oriented structure. The application must be a real native desktop program and must not embed the existing dashboard through WebView, Chromium, or an external browser.

Requirements

Provide:

- a native application shell,
- navigation structure,
- application title and version display,
- reusable view/view-model/service boundaries,
- responsive DPI-aware Windows layout,
- a consistent theme foundation suitable for later dark/light modes,
- startup and graceful shutdown handling,
- a local Core client abstraction for future tasks.

Do not migrate all existing dashboard screens in this task.

Security

Desktop must not store administrator passwords.

Do not embed Core, Agent, licensing, AI, update or production credentials in the executable.

No remote HTTP destinations may be selectable by untrusted UI input.

Definition of Done

- `SentinelAI.Desktop` builds as a Windows x64 executable.
- The executable opens a native Windows application without launching a browser.
- Navigation shell and placeholder pages work.
- DPI/scaling behavior is tested where practical.
- Desktop-specific tests exist for testable non-visual logic.
- Existing Core/Agent behavior remains unchanged.
- `.agent/STATUS.md` and architectural decisions are updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
