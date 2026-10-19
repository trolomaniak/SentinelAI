MVP-3 — Pilot License Key

Objective

Give each pilot company a free, time-limited license with no endpoint limit, verified offline, with no license server. When it expires, SentinelAI keeps protecting the company, asks it to get in touch and offers uninstallation.

Current state

- Licensing today is the opt-in seven-day signed lease from `cloud/license-api`. Core verifies leases in `core/LicenseStateService.cs` and `core/LicenseStateMachine.cs`, with rollback-resistant effective time in `core/LicenseClock.cs`.
- Licensing gates only optional signed features. Local monitoring works in every state (`docs/LICENSING.md`).
- Desktop shows license status in Settings (`desktop/SentinelAI.Desktop.Foundation/LicenseViewModel.cs`).

Requirements

The pilot key:

- A compact signed text with these fields:
  - format version;
  - key ID;
  - customer label (the company name, at most 64 characters);
  - issue date and expiry date (UTC);
  - plan `pilot`.
- It has no endpoint limit, and it is not bound to an installation, so it can be sent before Setup runs.
- It is signed with ECDSA P-256 using the existing signing and verification helpers in `shared/crypto`.

The issuer tool, `tools/pilot-license`:

- `keygen --directory <new directory> --key-id <id>`:
  - creates the key pair with owner-only permissions;
  - refuses an existing directory;
  - prints paths only, like `tools/update-dev`.
- `issue --private-key <path> --key-id <id> --customer "<name>" --days <1-365> [--start <yyyy-mm-dd>]` prints the key. Typical durations are 30, 60 and 90 days.

Trust:

- Pilot public keys are supplied to the Setup bundle at build time, by key ID, and are separate from update and lease keys.
- Tests use generated development keys only.
- The owner generates the production pilot key on their own computer.
- No private key enters the repository or any Core, Agent, Desktop or Setup artifact.

Entry:

- A fresh central Setup asks for the pilot key and verifies it before installing.
- Desktop Settings → License shows the customer, the expiry date and the days left, and accepts a new key to extend or replace the current one.
- The Agent installer needs no key.

Core:

- Verifies the key offline when it is entered and whenever status is read.
- Stores it additively in the existing license state.
- Uses the existing effective time, so turning the clock back cannot extend a pilot.

States:

- **Pilot active:** until expiry. Seven days before expiry, Desktop shows "Pilot ends in N days — contact us".
- **Pilot ended:** after expiry, decided by the owner on 2026-10-19:
  - All local monitoring, detection, alerts, incidents, risk and reports continue.
  - Desktop shows a persistent notice that the pilot has ended, with a request to get in touch and the configured contact details.
  - At the bottom of the notice, an "Uninstall SentinelAI" action starts the existing Setup uninstall flow, with retained data by default and removal only after the exact DELETE confirmation.
  - The notice can be hidden for the current session only.

Contact details (company name, e-mail, phone, website) are build-time settings of the Setup bundle. No personal contact data is committed to the repository; tests use placeholders.

The existing lease licensing and `cloud/license-api` stay unchanged and opt-in. The pilot key grants no cloud AI permission.

Constraints

- Never disable or degrade the local security baseline because of license state.
- No license server, network call or telemetry for pilot licensing.
- Signature, format and clock checks fail closed to "no valid pilot key", never to "pilot active".

Definition of Done

- Format tests cover the following:
  - round-trip;
  - tampering, an unknown key ID and a wrong signature;
  - expired and not-yet-valid keys;
  - the length limits.
- Core state tests with a controlled clock cover active, warning, ended, extension by a newer key and clock rollback.
- Desktop tests cover the warning and ended notices and the uninstall action, in the portable view-model tests and the native WPF tests.
- Native Setup acceptance enters a development pilot key.
- The issuer tool tests check permissions, refusal to overwrite and output.
- `docs/LICENSING.md` and `docs/MVP.md` describe the pilot key, and `.agent/STATUS.md` is updated.

Development sequence

MVP-1 → MVP-2 → MVP-3 → MVP-4, before TASK-030. One scoped branch and one Pull Request; do not merge to main.
