MVP-6 — Detection on Every Windows, With the Permissions It Needs

Objective

Every implemented detection works on Windows in any language, and the installed Agent can read every event its rules need (owner decision of 2026-10-26).

Requirements

- Detections must not depend on the Windows display language. Today 7045 service type and start type and 7040 start type are matched as English text, so SA-EVT-PERSIST-002 and SA-EVT-PROT-002 never fire on Polish Windows. Use language-independent values.
- Setup grants the Agent service, and only it (by its service SID), read access to the Windows Security log, and enables the audit subcategories the rules need that Windows does not enable by default (Other Object Access Events for 4698). Uninstall restores the previous state.
- Both the central installation and Agent Setup do this; repair and upgrade keep it.
- Never weaken any other control; never widen access beyond reading the Security log.

Definition of Done

- Portable tests with synthetic localized events; native Windows acceptance shows Security collecting and a 4698 detection.
- Customer and IT documents state what Setup changes and no longer list these limitations.
- `.agent/STATUS.md` and `.agent/DECISIONS.md` are updated.
