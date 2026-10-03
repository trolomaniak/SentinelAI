TASK-037 — MFA and Session Security

Objective

Strengthen local user authentication and session control.

Requirements

Add optional/administratively enforceable TOTP MFA.

Support:

- TOTP enrollment,
- protected secret storage,
- verification,
- one-time recovery codes,
- recovery-code rotation,
- session listing,
- session revocation,
- revoke-all-sessions,
- re-authentication for selected sensitive administration actions.

Security

TOTP secrets and recovery codes must never be logged or returned after appropriate enrollment boundaries.

Recovery codes must be stored using secure one-way verification.

Rate-limit verification attempts.

Definition of Done

- MFA-enabled user requires valid second factor.
- Recovery code works once.
- Session revocation takes effect.
- Sensitive administrative operations can require recent authentication.
- Tests cover replay, expiry and lockout/rate limits.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
