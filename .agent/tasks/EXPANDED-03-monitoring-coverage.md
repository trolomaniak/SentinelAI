# Expanded pilot 03 — Monitoring coverage

Give administrators one native English and Polish view of which devices and sources report usable data, how old the reports are and what continuity gaps Core retained. Use existing Agent data and SQLite state.

- Build a read-only, bounded administrator API for active endpoints, source detail and recent continuity notices. Filter device and gap pages before applying offsets. Read each response from one SQLite snapshot. Require the existing local administrator session, deny the Agent-only listener and use no-store responses.
- Show heartbeat health separately from inventory, telemetry and event source availability. Preserve the source's last reported state and distinguish current, missing, stale and future timestamps. Use existing 2/5 minute heartbeat, configured inventory, 3-hour telemetry and 2-hour event receipt thresholds.
- Cover all nine telemetry subsections and the four configured Windows event channels. Separate Defender Antivirus status from its event channel. Include event receipt and read time, checkpoint, counter period and reported gap counters when available. Use receipt-time retention for the gap list and distinguish first coverage from a coverage restart.
- Add a native workspace with paged device list, issue filter, source details and paged continuity history. Explain that gaps describe record ranges and do not establish exact outage duration. Use the current session boundary and common accessible page heading.
- Keep locale, scan cadence, permissions, alerting, existing projections and Agent collection behavior intact. Use synthetic tests for freshness boundaries and source states, filter/retention paging, API permission checks, session changes and the native minimum viewport.
