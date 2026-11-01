# Languages

SentinelAI is available in English and Polish. Each installation has one language: it is chosen in Setup and an
administrator can change it in Desktop → **Settings → Language**. Desktop shows itself in it for every administrator,
and Core writes the texts it creates in it.

## How the language is chosen

- **Core** keeps the installation language. Setup writes the choice as `SentinelAI:Language` (`en` or `pl`) in Core's
  configuration; an administrator's choice in Desktop is stored in Core's database and outlasts it. Any other
  configured value stops Core from starting.
- **Desktop** asks Core for the language when it starts (`GET /api/language`, anonymous, because the sign-in screen
  is already shown in it). While Core does not answer it uses the last language this Windows user saw, and otherwise
  Polish when Windows is shown in Polish and English otherwise. Desktop chooses its language once at start: after a
  change in Settings, close and reopen it.
- **Changing it**: `PUT /api/admin/settings/language` with `{"language":"pl"}` (administrators only).

## How texts are translated

English is the source of every text. `shared/localization/pl.json` maps each exact English text to its Polish
translation. A text without a translation stays in English, so a changed English text never shows an outdated
translation.

- Code uses `T("English text")` and, for texts with values, `F("{0} of {1} computers", a, b)`; numbers keep the invariant
  format. Views use `{loc:T 'English text'}`.
- Texts Core produces and Desktop shows (alert titles, reasons and recommended actions, Risk explanations, remediation
  from the vulnerability data) are translated by their exact English text. Texts Core composes with values, such as
  the coverage caution, are written by Core in the installation language.
- The catalog loader refuses duplicate keys, empty translations and translations that change a `{0}` placeholder.
- Tests fail when a Desktop text, a view text or a rule's title, reason or recommended action has no Polish
  translation.

## Adding or changing a text

1. Write the English text in code with `T`/`F`, or in a view with `{loc:T '…'}`.
2. Add the exact English text and its Polish translation to `shared/localization/pl.json` (keys sorted).
3. Run the Desktop and Rules tests: they list any text still without a translation.

## Coverage

Desktop (every page, notifications and tray texts), alert texts of every rule, Risk explanations and Core's coverage
caution are translated. Setup, Agent Setup and the HTML report follow in the next parts of the Polish version. Names of
products and Windows components, rule IDs, CVE numbers and other identifiers are not translated.
