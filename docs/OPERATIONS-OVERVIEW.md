# Operations Overview

Open **Overview** in Desktop to see what needs attention across the installation. The page reads the latest state when opened. Use **Refresh** to update it while you work. Each section links to the workspace where you can investigate or make a decision.

| Section | What it shows |
| --- | --- |
| Priority alerts | Open or investigating critical and high alerts for active enrolled computers. Critical alerts come first, followed by the most recently observed alerts at each severity. |
| Monitoring coverage | Total active enrollments and how many have at least one issue under the same rules used by Monitoring coverage. |
| Unread notifications | The number retained in the local center and the newest unread entries. |
| Risks needing attention | Risks with an overdue review, expired acceptance or passed treatment target under the same rules used by Risk Register. |
| Recent alert changes | The latest status history entries in the past 24 hours, including alert creation, reopening and administrator decisions. History can refer to a now removed device. |
| Last successful backup | The time Core recorded its most recent successful backup, when available. The timestamp does not indicate that an exported copy exists. |

Each list shows up to five entries. Totals cover all matching entries. An empty section means no matching entries at the displayed evaluation time. Unavailable data is shown as an error. Detailed workspaces contain their own filters, current data and decision controls.

The local administrator API `GET /api/admin/overview` returns the bounded projection from one SQLite read transaction. It requires an administrator session over loopback and uses `Cache-Control: no-store`. The Agent listener denies access. The page uses Core's existing state and does not ask Agents to collect or send new data.
