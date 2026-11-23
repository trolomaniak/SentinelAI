# Monitoring coverage

Open **Monitoring coverage** in Desktop to check which enrolled computers are reporting and which data sources need attention. Choose a computer to see its latest source states and retained continuity notices. **Coverage issues only** finds computers with missing or old data, reduced source availability, heartbeat warnings or retained gaps. Counts and filters apply to the whole active enrollment list. Removed computers are excluded.

| Source | How Core assesses freshness |
| --- | --- |
| Heartbeat | Age since Core received the heartbeat. Healthy through two minutes, warning through five minutes, offline after five minutes. |
| Inventory | Age of the report's collection timestamp. The installed Risk inventory threshold, normally 12 hours, applies. Inventory has no recorded Core receipt time. |
| Endpoint telemetry | Age of the collection timestamp, with a three-hour threshold. The view also shows when Core received the latest report. |
| Windows event channels | Age since Core received each channel status, with a two-hour threshold. The last log read time is the Agent's timestamp. |

The threshold includes its exact boundary. Future timestamps are shown separately, because their age cannot be established. A heartbeat refreshes connection health only. Each data source has its own reporting cadence. The offline threshold in Notifications is a separate policy.

The latest source state and its freshness are separate. An old report can show that the source was collecting, but a new report is needed to confirm current availability. A collected section can contain individual values the Agent could not establish. Telemetry shows BitLocker, antivirus, Defender Antivirus, local administrators, Windows Update policy and results, pending reboot, services and software separately. The Windows event section covers Security, System, PowerShell and Microsoft Defender.

## Continuity notices

Core retains recent gaps measured from its own receipt time, normally up to 30 days and at most 1,000 notices per endpoint. Gaps can describe overwritten records, a reset log, records dropped or rejected, or coverage starting or restarting at a checkpoint. A first coverage boundary appears in the history without counting as an operational gap. A restart remains visible as a gap. The device summary flags operational gaps within the retained window. The first acknowledged checkpoint is a starting point, and counters are cumulative since their displayed start date. Record ranges cannot establish the exact duration of missing monitoring. An empty gap history or a currently collecting channel does not establish that the computer is safe.

## Administrator API

The read-only routes use the existing administrator session, actual loopback access and `Cache-Control: no-store`. The Agent-only LAN listener denies them. Responses project source metadata and continuity records from the existing database. Agent collection, permissions and schedules are unchanged.

| Request | Result |
| --- | --- |
| `GET /api/admin/monitoring-coverage?offset=0&limit=50&issuesOnly=false` | Active endpoint summaries, total and filtered counts |
| `GET /api/admin/monitoring-coverage/{endpointId}` | Source detail for one active endpoint |
| `GET /api/admin/monitoring-coverage/{endpointId}/gaps?offset=0&limit=50` | Retained continuity notices for that endpoint |

Each page contains at most 100 items. Missing and removed endpoints return `404`. Each response uses one database snapshot and one evaluation time.
