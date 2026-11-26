# Expanded pilot 06 — Software catalog

Provide a searchable native catalog of machine-wide Windows software across the fleet, with reported versions, affected endpoints and retained observations of changes.

- Use the existing software section of endpoint telemetry. Group products by normalized name and publisher. Preserve exact version and architecture observations, including unknown values, and keep inventory identity separate from CVE matching.
- Expose the latest positive observations from active endpoints. Show software collection coverage and stale data so an empty search can be interpreted correctly. Surface existing stored telemetry when upgrading or restoring a pre-catalog backup.
- Record changes to observed variant sets only between consecutive software reports that were collected without truncation or skips. Treat the first report as a baseline. Older or duplicate reports and incomplete scans cannot create changes. Preserve explicit before and after versions with the collection times and bounded retention.
- Provide local administrator read APIs and a Polish and English Desktop workspace with product search, endpoint and version detail, separate fleet change history, product filtering and paging. Sign-out and navigation clear protected results.
- Exercise actual telemetry ingestion, upgrade and restart, retention, endpoint removal, query limits, authorization, localization and native layout. Record verification in STATUS.
