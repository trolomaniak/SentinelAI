# Expanded pilot 04 — Operations Overview

Make the existing native Overview a local administrator's work queue. Replace the static guide with a live, bounded summary in English and Polish. Keep its existing accessible heading and workspace shortcuts.

- Show total active registered devices and the number with monitoring issues, active high and critical alerts awaiting a decision, unread retained notifications and Risk Register entries requiring attention. Use the same coverage and risk deadline rules as their source views.
- Show at most five examples per category, with deterministic ordering. Put critical alerts ahead of high alerts. Show recent alert status changes over the last 24 hours, including new and reopened alerts. Distinguish absent items from a failed read. Show the newest successful backup timestamp when available.
- Read one evaluated SQLite snapshot using existing state. No persisted dashboard state, new Agent collection, evidence projection or outbound service calls. Restrict the bounded read-only response to the local administrator and disable caching.
- Link each group to its existing workspace. Preserve session isolation on navigation and logout. Use the two supported languages and the minimum native viewport. Keep filters and source workspaces authoritative for detailed decisions.
- Test actual authorized API behavior, count/list consistency and ordering, time boundaries, bounded fields and rows, safe views of empty and failed reads, canceled/stale Desktop requests, and native layout and navigation. Record local and CI results.
