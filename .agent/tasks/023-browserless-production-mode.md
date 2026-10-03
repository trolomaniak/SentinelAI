TASK-023 — Browserless Production Mode

Objective

Make native Desktop the supported production user interface and remove browser dependence from normal operation.

Requirements

Provide:

- Desktop startup entry point,
- optional tray integration,
- `Open SentinelAI` action,
- service status indication,
- safe notification hooks for important local events,
- application activation when already running,
- configurable Desktop auto-start independent from Core/Agent auto-start.

The browser dashboard may remain as a development/diagnostic compatibility surface only if explicitly documented.

Constraints

Core and Agent protection must continue when Desktop is closed.

Do not make UI availability a dependency for monitoring.

Definition of Done

- Normal supported workflow requires no browser.
- Desktop can be closed without stopping Core or Agent.
- Reopening Desktop reconnects to the running local system.
- Duplicate UI processes are handled predictably.
- Browser dependencies are removed from production documentation.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
