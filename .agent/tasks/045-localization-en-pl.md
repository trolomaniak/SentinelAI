TASK-045 — Full English and Polish Localization

Objective

Make the complete release candidate available in English and Polish.

Supported Languages

- English (`en`)
- Polish (`pl`)

Requirements

Move all user-facing strings into a localization system, including:

- Desktop,
- Setup/installer,
- tray/notifications,
- authentication,
- Devices,
- Alerts,
- Risk,
- Risk Register,
- Tickets,
- Users/Roles/RBAC,
- Reports,
- licensing/Safe Mode,
- AI labels/messages,
- updater,
- validation and error messages,
- relevant end-user documentation.

Provide an in-application language selector.

Persist the selected language appropriately.

English must remain the invariant fallback for missing resources.

Quality

Avoid machine-generated placeholder wording in the final resource set.

Test layout expansion and Polish diacritics.

Ensure security identifiers, rule IDs, CVEs and machine-readable values are not translated.

Definition of Done

- Complete supported UI can be used in English.
- Complete supported UI can be used in Polish.
- Language can be changed without reinstalling.
- No intended user-facing hard-coded English remains outside approved technical identifiers.
- Installer/setup and generated user-facing reports use the selected/specified language where designed.
- Localization tests detect missing resource keys.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
