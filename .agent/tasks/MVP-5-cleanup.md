MVP-5 — Remove Leftovers After the Single Setup

Objective

The pilot ships one central `SentinelAI-Setup.exe` and one `SentinelAI-Agent-Setup.exe`. Remove what only served earlier delivery paths (owner decision of 2026-10-26).

Requirements

- Remove the browser dashboard: the `dashboard/` application, Core's static file serving, its Node.js build and tests, and its documentation. Native Desktop is the only interface.
- Remove the manual pilot installation: `docs/PILOT.md`, the manual entry and verification scripts and their tests, the single-file pilot bundle mode and the documents it copied.
- Remove the separate Agent and Desktop packages: their publish scripts and CI artifacts. CI may still publish them internally for tests.
- Remove the empty `.agent/PLANS.md`.
- Keep every `.gitkeep`, the installer modules Setup loads, and the scripts CI tests use.

Definition of Done

- Build and tests pass with 0 warnings; Windows CI is green.
- No document or script refers to removed files.
- `.agent/STATUS.md` and `.agent/DECISIONS.md` are updated.
