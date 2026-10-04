# Local security report

TASK-013 adds administrator-generated standalone HTML security reports. Core reads its existing SQLite data and runs the existing deterministic risk policy locally. Generation does not call cloud AI, a model provider or the License API and remains available in Safe Mode. There is no new database table, report scheduler or external dependency.

## Generate a report

Sign in through Desktop or the dashboard, open **Reports**, select the start and end dates, then generate the HTML file. Desktop's **Generate report** holds Core's exact attachment in owned memory and displays period/filename/size/status. **Save HTML** opens the native destination picker and saves only after explicit confirmation, without an embedded preview or automatic opening. Date edits, leaving Reports, sign-out and closing erase retained bytes and cancel pending work; already saved exports remain. The default is the previous complete calendar month in UTC. Open the saved file yourself without a network connection. Browser printing also supports saving the HTML as PDF; Core does not add a PDF rendering service. See [native report operation, bounds and verification](DESKTOP-RISK-REPORTS.md).

The administrator API is `GET /api/admin/reports/security?from=2026-09-01&to=2026-09-30`. It requires the existing administrator bearer token and HTTPS outside loopback, returns `text/html` as an attachment and uses `Cache-Control: no-store`. Tokens are sent in the authorization header only, never in the download URL or file.

Desktop requires strict UTF-8 and Core's attachment, `no-store`, `nosniff` and exact restrictive CSP headers, with a 30-second complete-response deadline and an 8 MiB byte limit. The native saver uses a date-derived suggestion, rejects final link/directory destinations, stages bytes in the confirmed destination directory and moves them into place; it never trusts a server-supplied save path. This changes only the report delivery workflow, preserving Core's privacy projection and local/Safe Mode generation.

Only `from` and `to` are accepted, once each. Both must be exact `yyyy-MM-dd` dates. Dates are inclusive UTC calendar days: the example includes September 1 at midnight and excludes October 1 at midnight. The range must be ordered and contain at most 366 days. Invalid parameters return `400`.

## What the report describes

The report separates the selected period from the current state because the database retains the newest inventory and heartbeat, and one tracked alert per endpoint/rule with its latest positive evidence.

- Period incident activity includes a retained first observation, retained latest observation, or stored status transition within the selected range. These are distinct tracked incidents, not a count of every positive observation. Intermediate positive observations are not retained, so activity cannot be reconstructed completely.
- Newly tracked incidents are counted by their first observation. A later observation does not erase that original date.
- Resolved incidents are distinct alerts with a recorded transition to Resolved during the period. Repeated resolutions do not duplicate the incident count. A later reopening is disclosed; a resolution is an administrator decision and does not prove remediation on the endpoint.
- Period severity, status and evidence describe the latest retained alert, with observation dates shown. Titles, reasons and recommendations use the current supported local rule templates rather than stored freeform text. Older evidence and severity snapshots are unavailable.
- Organization risk, endpoint health, inventory coverage and unresolved posture findings describe the current enrolled fleet at the report's evaluation time. They are not historical values at the end of the reporting period. Existing organization risk semantics remain: the highest endpoint score, where higher values prioritize recorded risks.
- Historical score trend is explicitly unavailable because Core has no persisted score history. No historical scores or fleet membership are inferred.

Management summary and prioritized actions are followed by technical incident evidence. Missing inventory, unknown signals, stale observations and policy assumptions remain visible. A zero score or absence of tracked incidents does not establish endpoint safety. Recommendations come from deterministic local findings and never perform endpoint changes.

## Consistency, privacy and limits

Generation uses one consistent SQLite read transaction and one UTC evaluation time. Stable sorting and invariant formatting make the HTML deterministic for the same stored data, scoring policy and evaluation time, without AI.

The report projects selected endpoint identifiers and configuration evidence. It does not export raw inventory, passwords, hashes, enrollment or gateway credentials, license material, model-provider configuration, or status-history administrator identities. Security evidence is restricted to known Boolean and bounded integer fields. All dynamic HTML is encoded, and the document has no scripts or external resources; restrictive CSP is included in both the response and saved document.

Local generation admits at most 1,000 enrolled endpoints and 13,000 tracked alerts. Larger datasets or an HTML attachment exceeding 8 MiB return `422` instead of presenting incomplete aggregate totals. Detailed lists may show the first 200 items in a stable order with omitted totals disclosed; summary counts include all admitted records.
