# Languages

SentinelAI is available in English and Polish. Each installation has one language: it is chosen in Setup and an
administrator can change it in Desktop → **Settings → Language**. Desktop shows itself in it for every administrator,
and Core writes the texts it creates in it.

## How the language is chosen

- **Setup** shows a **Język / Language** choice at the top of its window. It starts in Windows' language (Polish when
  Windows is shown in Polish, English otherwise); repair, upgrade and uninstall start in the language of the installed
  SentinelAI. Choosing another language redraws the window at once. After a fresh installation in Polish, Setup signs in
  once as the administrator it has just created and saves the language in Core (`PUT /api/admin/settings/language`).
  When Core does not accept it, the installation still succeeds and its final message says to choose the language in
  Desktop → Settings → Language. Repair and upgrade keep the installation's language.
- **Agent Setup** has the same choice for its own window only. It starts in Windows' language; the Agent itself shows
  no texts. Quiet installs (`/quiet`) report exit codes only.
- **Core** keeps the installation language in its database. Its configuration value `SentinelAI:Language` (`en` or
  `pl`, default `en`) is the language of an installation until a language is saved; any other value stops Core from
  starting.
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
- Tests fail when a Desktop, Setup or Agent Setup text, a view text or a rule's title, reason or recommended action has
  no Polish translation.

## Adding or changing a text

1. Write the English text in code with `T`/`F`, or in a view with `{loc:T '…'}`.
2. Add the exact English text and its Polish translation to `shared/localization/pl.json` (keys sorted).
3. Run the Desktop and Rules tests: they list any text still without a translation (the Desktop tests also read the
   Setup and Agent Setup sources).

## Coverage

Desktop (every page, notifications and tray texts), Setup and Agent Setup (window texts, progress, results and errors),
alert texts of every rule, Risk explanations and Core's coverage caution are translated. The HTML report follows in the
next part of the Polish version. Names of products and Windows components (including SentinelAI Setup, Agent Setup,
Core, Desktop and Updater), rule IDs, CVE numbers, support codes, command-line options and other identifiers are not
translated. The word `DELETE` that confirms data removal in Setup stays as it is in both languages.
