TASK-018 — Desktop Bootstrap and Authentication

Objective

Move initial administrator setup and normal sign-in into the native desktop application.

Requirements

Desktop must support:

- first-run detection,
- initial administrator creation when Core has no administrator,
- normal sign-in,
- sign-out,
- expired-session handling,
- explicit authentication errors,
- reconnect behavior after Core restart.

Authentication must reuse Core's authoritative authentication boundary rather than duplicating password verification in Desktop.

Security

Passwords must not be written to disk, logs, crash reports or process arguments.

Bearer/session material must remain protected and short lived.

Remote plaintext authentication remains forbidden.

Definition of Done

- Fresh installation can complete administrator bootstrap from Desktop.
- Existing installation can sign in from Desktop.
- Sign-out invalidates the local Desktop session.
- Core restart/session expiry returns Desktop to a safe signed-out state.
- Invalid credentials remain indistinguishable where appropriate.
- Automated tests cover bootstrap/authentication state transitions.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
