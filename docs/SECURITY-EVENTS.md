# Continuous Windows security event collection

The Agent continuously reads a fixed, compiled allowlist of Windows security events from four event log channels and delivers minimized, typed observations to Core through an authenticated batch route. A channel's position advances only after Core acknowledges a batch, so during an outage the Windows log itself is the bounded buffer. Records that could not be observed (overwritten, cleared, dropped or older than the start of coverage) are reported to Core as explicit gaps. Core deduplicates and retains observations, gaps and per-channel status, and exposes status (never content) to administrators. Observations are stored, not evaluated: detection rules, alerts and scoring based on them are TASK-028, and no Desktop view, report, rule or AI context uses them.

## What is collected

Exactly 16 selections of 12 kinds, compiled into the Agent (`SecurityEventCatalog.Production`) and the shared contract (`SecurityEventContract.Catalog`). Configuration cannot widen them, and Core ignores any other channel, provider, event ID and kind combination. A test fails if this table and the catalog diverge.

Fields are read only by name through property selectors (`Event/EventData/Data[@Name='<field>']`, or the UserData path noted for 104). Windows evaluates the provider, event ID and, for 4104, level filters; the conditions on event data are evaluated in the Agent.

| Channel | Provider | Event ID | Kind | Collected when | Typed fields sent |
| --- | --- | --- | --- | --- | --- |
| Security | Microsoft-Windows-Security-Auditing | 4624 | logonSucceeded | `LogonType` is 2 (interactive), 10 (remote interactive) or 11 (cached interactive) | `LogonType`, `TargetUserSid`, `IpAddress`, `ElevatedToken` (`%%1842` true, `%%1843` false) |
| Security | Microsoft-Windows-Security-Auditing | 4625 | logonFailed | always | `LogonType` (0–15), `TargetUserSid`, `IpAddress`, `Status`, `SubStatus` (NTSTATUS as unsigned 32-bit) |
| Security | Microsoft-Windows-Security-Auditing | 4698 | scheduledTaskCreated | always | `TaskName`, `SubjectUserSid` |
| Security | Microsoft-Windows-Eventlog | 1102 | logCleared | always | `ClearedChannel` = `Security` (a constant; nothing is rendered) |
| System | Service Control Manager | 7045 | serviceInstalled | always | `ServiceName`; `ImageFileName` and `ImageLocation` derived from `ImagePath`; `ServiceType`; `StartType`; `AccountKind` derived from `AccountName` |
| System | Service Control Manager | 7040 | protectionServiceStartTypeChanged | `param4` is a protection service: `WinDefend`, `WdNisSvc`, `Sense`, `MpsSvc`, `BFE`, `EventLog`, `wscsvc` or `SecurityHealthService` (any casing) | `ServiceName` (canonical casing), `NewStartType` from `param3` |
| System | Microsoft-Windows-Eventlog | 104 | logCleared | always | `ClearedChannel` from `Event/UserData/LogFileCleared/Channel` |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell | 4104 | scriptBlockFlagged | Level 3 (Windows' own warning flag for a suspicious script block) and `MessageNumber` 1 | `ScriptBlockId`, `PartCount` from `MessageTotal` |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1116 | malwareDetected | always | `DetectionId`, `ThreatId`, `ThreatName`, `SeverityId`, `CategoryId` |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1117 | malwareActionTaken | always | As 1116, plus `ActionId` |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1118 | malwareActionFailed | always | As 1117, plus `ErrorCode` |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1119 | malwareActionFailed | always | As 1117, plus `ErrorCode` |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 5001 | protectionDisabled | always | None; the event ID identifies the disabled protection |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 5010 | protectionDisabled | always | None |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 5012 | protectionDisabled | always | None |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 5007 | defenderSettingChanged | always | `SettingArea` and `Change` derived from `Old Value` and `New Value` |

Every observation also carries `Channel` and `Provider` (the catalog's canonical names, never text from the record), `EventId`, `EventVersion`, `Level`, the Windows `RecordId`, `TimeCreatedUtc` (the original event time in UTC at full precision, never receipt time) and `Kind`. Every batch carries the format `sentinelai-security-events-v1`, the Agent version, the Agent's send time and the time its counters started.

Values are minimized before they leave the Agent:

- **Identities are SIDs only.** `S-1-0-0` (no identity) becomes null. SIDs must use ASCII digits; IP addresses are canonical (IPv4-mapped addresses become IPv4 and IPv6 scope IDs are removed).
- **Free text is derived, never copied.** `ImagePath` becomes only the executable or driver file name (`ImageFileName`) and a location class (`ImageLocation`: `windows`, `programFiles`, `programData`, `userProfile`, `temp`, `network` or `other`; null for other environment-variable or relative forms). `AccountName` becomes `AccountKind` (`localSystem`, `localService`, `networkService`, `virtualAccount` for `NT SERVICE\…`, otherwise `otherAccount`). Defender 5007 values become `SettingArea` (`exclusionPath`, `exclusionProcess`, `exclusionExtension`, `exclusionIpAddress`, `realTimeProtection`, `tamperProtection` or `other`) and `Change` (`added`, `removed` or `modified`).
- **Closed vocabularies.** `ServiceType` is `userModeService`, `kernelDriver` or `fileSystemDriver`; start types are `boot`, `system`, `auto`, `demand` or `disabled`, from English SCM text or the numeric value 0–4.
- **Bounded text.** `ServiceName`, `TaskName`, `ThreatName` and `ClearedChannel` are at most 256 characters, and `ImageFileName` at most 128. They are trimmed, and none may contain control, format (bidirectional) or unpaired surrogate characters. Strings longer than 1,024 characters never cross the Windows adapter.
- **A bad field value never suppresses an event.** An empty or `-` value is absent (null). A present value that fails conversion or validation becomes null and is counted in `fieldsDiscarded`, and the observation is still sent. If rendering the fields fails, all of them become null and the occurrence is still reported. The exception is the data condition of 4624, 4104 and 7040: a record whose condition value renders but cannot be read is not selected and is counted in `fieldsDiscarded`, while a record whose condition cannot be rendered at all might be selected, so it is counted in `droppedUnparsed` and sent as a `dropped` gap.

## Never collected

| Excluded | Why |
| --- | --- |
| Message text (`FormatDescription`), event XML (`ToXml`), positional `Properties`, display names | Arbitrary, localized or positional text. A test scans the Agent's event code to make sure these APIs are never called. |
| Account, domain and workstation names: `TargetUserName`, `TargetDomainName`, `SubjectUserName`, `SubjectDomainName`, `WorkstationName` | 4625 user names often contain passwords typed into the user field, and workstation names are supplied by the remote party. SIDs are sufficient. |
| Other 4624/4625 fields: `LogonProcessName`, `AuthenticationPackageName`, `LmPackageName`, `KeyLength`, `ProcessId`, `ProcessName`, `IpPort`, `LogonGuid`, `TargetLogonId`, `TargetLinkedLogonId`, `ImpersonationLevel`, `RestrictedAdminMode`, `VirtualAccount`, `TargetOutbound*`, `FailureReason`, `Subject*` | Not needed for TASK-028; local paths or localized tokens. |
| 4104 `ScriptBlockText` and `Path`; events 4103, 4105 and 4106 | Script content can contain secrets. These fields are never in a selector. |
| 7045 raw `ImagePath` (directories and arguments) and raw `AccountName` | Arguments can carry secrets, and paths and accounts can name users. They are held only briefly in memory for derivation and are never logged, stored or sent. |
| 4698 `TaskContent`, `ClientProcess*` and `FQDN` | Task XML contains command lines and principals. |
| 104 `SubjectUserName`, `SubjectDomainName` and `BackupPath`; 1102 `Subject*` | Names and paths. Who cleared a log is investigated locally. |
| 7040 `param1` and `param2`; 7040 for any service that is not a protection service | Localized display names; noise that would disclose software usage. |
| Defender `Path`, `Process Name`, `Detection User`, `Remediation User`, `FWLink`, other `*Name`/`*Description` fields, product, engine and signature versions, raw 5007 values | Paths, users and URL tokens, localized text, health data (TASK-029) and exclusion paths. |
| Credential-related events: 4648, 5376–5382, 4692–4695 | SentinelAI never collects stored credentials. |
| Bookmark XML | Generated from a catalog channel name and a record number; never stored or read from disk. |

**Credentials.** No credential-bearing event IDs are selected, and the known places where secrets get typed or embedded are excluded by construction: failed-logon user names, service command-line arguments, PowerShell script text, scheduled task XML and Defender setting values. Tests plant secret markers in these fields of synthetic events and check that they never appear in observations or logs; elevated Windows acceptance does the same with a real test service's arguments against Core's database, the Agent's files and the logs.

**Not in this catalog.** Other channels (Application, Sysmon, `PowerShellCore/Operational`, `TaskScheduler/Operational`) and events such as 4719, 5013, 4688, 4697, 4720/4732, 7036 and 4103. They are candidates for later, additive kinds.

**Logs.** Agent logs can reach the Windows Application log, which interactive users can read. Event code therefore never logs field values, SIDs, addresses, names, observation JSON, bookmark XML or exception messages; failures are logged by exception type and HResult only. Core logs the endpoint ID with a status code or count only and never logs request bodies or parser messages.

## Channel access and LocalService

The installed Agent runs as `NT AUTHORITY\LocalService`. TASK-027 changes no ACL, channel security descriptor (SDDL), group, privilege, service account, audit policy or channel enablement.

| Channel | Installed LocalService Agent |
| --- | --- |
| Security | **`accessDenied`.** LocalService has no read access to the Security channel, so 4624, 4625, 4698 and 1102 are not collected on a default installation. The Agent retries every minute. |
| System | Collected. |
| PowerShell/Operational | Collected where the channel is readable by the service account; otherwise its state is reported. |
| Defender/Operational | Collected where the channel exists and is readable; `notFound` where Microsoft Defender's channel is absent. |

A process whose token can already read Security, such as an Agent run from an elevated console, collects the documented minimal fields from it.

Granting the installed Agent read access to Security changes a security boundary and requires the owner's approval. It has not been done. The options, narrowest first:

1. Give the Agent service its own SID (`sc sidtype SentinelAIAgent unrestricted`) and add a read-only entry `(A;;0x1;;;<NT SERVICE\SentinelAIAgent SID>)` to the Security channel access, owned and restored exactly by Setup.
2. Add the service SID to the Event Log Readers group.
3. Add LocalService (`S-1-5-19`) to Event Log Readers, which grants every LocalService process read access, or change the Agent's service account, which orphans its DPAPI-protected enrollment state.

Approval also covers the data: Security-derived SIDs (4624, 4625 and 4698), remote IP addresses (4624 and 4625) and log clears (1102) would then be stored in Core, available to SentinelAI administrators who need not be Windows administrators on the endpoint.

The pipeline picks up a grant without a code or configuration change. At its next one-minute retry the channel becomes `collecting` and coverage starts at the log's newest record with a `coverageStarted` gap (normally cause `noCheckpoint`, with `coverageRestart` false). Events written before the grant are not backfilled.

Other degraded states follow the same rule. A missing channel is `notFound`, any other failure (including a read timeout) is `error` with its HResult in `lastErrorCode`, and each is retried every minute. A channel disabled in Windows is reported as `disabled` and is still read. One channel's failure never affects the other channels, heartbeats, inventory or posture monitoring.

## How events reach Core

1. **Dormant until linked.** The pipeline does nothing (no reads, no checkpoint file, no traffic) until the Agent is enrolled and Core has acknowledged its latest heartbeat. On a platform without the Windows event log it logs that collection is unavailable and stays idle.
2. **Poll.** Every `Agent:EventPollInterval` (5 seconds by default) it makes one metadata call per channel for the oldest and newest record numbers, starting from a different channel on each poll for fairness. A channel with no new records costs nothing more.
3. **Server filter plus anchor membership.** A channel with new records is read by one `EventLogReader` query generated from the catalog. Windows applies the provider, event ID and level filters, and the query also selects up to two records by number: the newest record seen by the metadata call and, when the channel's position is still in the log, the position itself (the anchor). For System at position 1234 with newest record 5678:

   ```text
   *[System[(Provider[@Name='Service Control Manager'] and (EventID=7040 or EventID=7045)) or (Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104) or EventRecordID=1234 or EventRecordID=5678]]
   ```

   The reader is positioned with `Seek(bookmark, 0)` on the anchor, which is in the result set by construction. The bookmark is generated from the channel name and record number. If the seek fails, the query is reopened with an `EventRecordID>=<position>` filter and no bookmark; this fallback is correct but slower and is counted in `seekFallbacks`. Without an anchor (position 0, or a position no longer in the log) the query is read from the oldest record without a seek. Only catalog records plus at most two numbered records cross from the event log service.
4. **Anchor verification.** On every pass that reads from a position still inside the log, the first record at or above the position must be the position's record with the stored creation time (exact ticks). This detects a log that was cleared and has grown past the position again; see [gaps and coverage](#gaps-and-coverage).
5. **Selection.** For each returned record, the Agent finds its catalog selection, evaluates any data condition (4624 `LogonType`, 4104 `MessageNumber`, 7040 `param4`), renders only the named fields and normalizes them.
6. **One batch.** Observations and gaps go into at most one prepared batch: at most 256 observations, 192 KiB of serialized observations and 32 gaps. The status of all four channels is added when it is sent. A record that does not fit is not consumed; it is read again for the next batch, and the Agent polls again as soon as the full batch is acknowledged.
7. **Delivery.** The batch is posted to `POST /api/agent/security-events` with the Agent credential, one request at a time and at least 2 seconds apart by default.
8. **Acknowledgement-only positions.** A channel's position is the record it has scanned through, plus that record's creation time. It advances only when Core returns success, and the checkpoint is then saved immediately. A pass that found nothing to collect (only other events, or catalog events whose data condition does not match) advances at once without a request, because it skipped nothing collectable, and is saved lazily.

Status travels with every batch. When nothing is prepared, a status-only request is sent at the next delivery slot: for the first report, when a channel changes state or gains or loses an acknowledged position, at most every 5 minutes when counters or record numbers changed, and every 60 minutes otherwise as a liveness report.

## Checkpoints, restart and duplicates

Positions are kept in `<Agent:DataDirectory>/event-checkpoints` (installed: `%ProgramData%\SentinelAI\Agent\event-checkpoints`), at most 4,096 bytes of UTF-8 JSON. It holds only the format, the endpoint ID and, per channel, a record number and creation time in ticks (null when there is none):

```json
{"format":"sentinelai-event-checkpoints-v1","endpointId":"00000000-0000-0000-0000-000000000001","channels":[{"channel":"System","recordId":123456,"anchorUtcTicks":639000000001234567}]}
```

- **Writes.** The file is replaced atomically: a uniquely named `.event-checkpoints.<guid>.tmp` is created, flushed to disk and renamed over it. Links are refused, and up to 16 orphaned temporary files are removed at load. It is written right after an acknowledgement that moved a position, at most every 5 minutes for positions advanced past records with nothing to collect, and at graceful stop when something changed. An idle Agent never rewrites it.
- **Loading** is strict (size, UTF-8, depth, duplicate and unknown properties, catalog channels, non-negative record numbers) and never stops the host.
- **Updates** refuse packages containing `event-checkpoints` or `.event-checkpoints.*` files, so a code update cannot replace positions.

| Situation | Result |
| --- | --- |
| First start, or a channel without an entry | `coverageStarted`/`noCheckpoint` at the log's newest record; history before it is never delivered. |
| Graceful restart | Collection resumes. Events written while the Agent was stopped are delivered, as far as the channel still holds them. Nothing is resent unless a request was in flight at stop (at most one batch, which Core deduplicates). |
| Crash | At most one batch (the one in flight, or the one acknowledged just before the crash) is resent and counted by Core as duplicates. Gaps not yet acknowledged are detected again with the same first record. |
| Overwritten while stopped | An exact `overwritten` gap. |
| Cleared while stopped | A `logReset` gap; the new generation is read from its oldest record, with an `overwritten` gap for any of its first records that were already lost. |
| Checkpoint file deleted | `coverageStarted`/`noCheckpoint`; Core sets `coverageRestart` because it had already covered the channel. |
| Checkpoint file corrupt or a link | `coverageStarted`/`checkpointInvalid` on every channel, a warning and `coverageRestart` where Core had coverage. |
| Checkpoint file temporarily unreadable (another process holds it exclusively, or an IO or access error) | Collection waits and the load is retried on each of the next steps (six attempts, about 30 seconds at the default poll interval) with a warning per attempt; only then does coverage restart as `checkpointInvalid`. The file is read with shared access, so another process merely reading it (a scanner or a backup) never blocks the load. |
| Checkpoint of another endpoint ID | `coverageStarted`/`endpointChanged` on every channel, so one enrollment's positions never replay into another. |

**Duplicates.** Retries resend identical observations and gaps; only status and the send time are refreshed. Core stores each observation once per endpoint, channel, record number and event time, so replays are counted as `duplicates`, and record numbers that restart after a clear never collide with earlier records. Gap rows are unique per endpoint, channel, reason and first record, and a resent gap merges its last record (the maximum is kept). If the Agent's 10-second request timeout expires after Core committed a batch, the resend is absorbed the same way.

## Outage, buffering and overflow

- **No spool.** Exactly one prepared batch is held in memory, and no event payload is written to disk. Each Windows channel is the durable, size-bounded buffer; its capacity is reported as `logMaximumBytes`, and the lag is `newestRecordId − checkpointRecordId`.
- **Backpressure.** While a batch waits for Core, the Agent makes no metadata call, query or read. During an outage it makes no event log calls after preparing one batch.
- **Transient failures.** A transport failure, a timeout or any status other than those below (including 401, 403, 408, 429 and 5xx) keeps the batch and retries after 5, 10, 20, 40, 60, 60 … seconds, using the existing `Agent:RetryDelay` and `Agent:MaxRetryDelay`. The first failure is logged, then at most one warning every 10 minutes; recovery is logged with the attempt count.
- **Incompatible Core.** 400, 404, 405, 413 or 415 (an older Core without the route, a format mismatch or a contract bug) holds the batch without dropping anything and retries every 15 minutes, with one warning per transition. A batch that fails the Agent's own validation is held the same way and logged once as an error.
- **Link lost.** While heartbeats are not acknowledged, no batch is sent. Reading continues only until one batch is prepared. When the link returns, delivery is attempted immediately with the backoff reset.
- **Overflow.** The Agent never drops events to make room and never blocks Windows logging. The only loss is Windows overwriting records that were not read, after an outage longer than the channel's retention or a sustained selected-event rate above the delivery capacity. It is reported as an exact `overwritten` gap, and `skippedRecords` counts every record number in the range, an upper bound on lost observations because most records are usually not in the catalog.
- **Stop.** The heartbeat worker stops first. The pipeline then cancels any event log read and any request in flight, and saves changed positions within 5 seconds.

## Gaps and coverage

| Reason | Range | Meaning |
| --- | --- | --- |
| `overwritten` | `firstRecordId`–`lastRecordId` | Records after the position were overwritten by Windows before they were read. |
| `logReset` | From `firstRecordId` (position + 1), open-ended | The log was cleared or reset: it shrank below the position, became empty, or the record at the position is missing or has a different creation time. Unread records of the old generation from `firstRecordId` on are lost. |
| `coverageStarted` | From `firstRecordId` (newest record + 1), open-ended | Collection started at the log's newest record. Earlier records were not collected. `cause` is `noCheckpoint`, `checkpointInvalid` or `endpointChanged`. |
| `dropped` | One record | A catalog record that could not be sent: it had no creation time or could not be normalized. A record over 4 KiB serialized would also be dropped; the largest valid observation measures 2,823 bytes. A record without a record number cannot carry a gap and is only counted in `droppedUnparsed`. |
| `rejected` | One record | Recorded by Core for an observation item it rejected as invalid. A `rejected` gap sent by an Agent is ignored. |

Gaps are computed from the acknowledged scanned-through position, not from the last selected event, so non-catalog records never cause false gaps. Each gap is logged as a warning with the channel, reason, cause and record range.

- **Reset, same pass.** When a reset is detected and the log has records again, the new generation is read in the same pass, so its position never rests at 0 while records exist. If the new generation's oldest record is above 1, records 1 to oldest − 1 were overwritten before they could be read, and an `overwritten` gap for that range is sent together with the `logReset` gap. A reset is committed only together with at least one consumed record of its new generation: if that pass ends before reading one (the scan budget, a full batch or a read failure), its gaps are withdrawn and the old position stays, so the next pass detects the same reset again, including after a further clear.
- **Failed anchor check.** If the anchor is missing, the query is reopened without the bookmark once. If the anchor is still missing or has a different time, the channel is described again before deciding: an empty log is a `logReset` with position 0; a log that should contain the position but does not (shrunk, or the position is inside the log with another record or none) is a `logReset` followed by the new generation; an oldest record above position + 1 is an `overwritten` gap; and an oldest record equal to position + 1 means that only the anchor itself was overwritten and nothing was lost.
- **Overwrite marker.** When an `overwritten` gap is recorded before any newer record is scanned (for example when the poll's scan budget is used up), the position becomes oldest − 1 with no time. If a later metadata call shows that record number inside the log again, the log must have been reset; the seek then finds a record with a time, or none, and reports it.
- **Untimed anchors.** A record without a creation time can become the position (for example a dropped record, or a newest record without a time at coverage start), so no time is stored. It is still verified by seeking on it: a record without a time at that number confirms the generation, a record with a time is a reset, and a missing record is resolved as for a failed anchor check.
- **Gap budget.** A batch carries at most 32 gaps. Coverage, reset and overwrite gaps are always recorded. A `dropped` gap is added only while room remains after reserving two continuity gaps for every channel not yet read in the same poll; otherwise the record is left for the next batch.
- **Crash consistency.** Gaps travel inside the batch whose positions they explain, and positions advance only on acknowledgement. After a crash or failed delivery the same gap is detected again with the same first record, and Core merges it.
- **Coverage restart.** Core sets `coveredSinceUtc` for a channel from the first status that carries an acknowledged position and never clears it. A later `coverageStarted` gap on a channel with `coveredSinceUtc` is stored with `coverageRestart` true, so a deleted, corrupt or replaced checkpoint is visible. A first start or a newly readable channel has `coverageRestart` false.

**Rule for TASK-028.** Missing telemetry is never evidence of safety. A channel that is not `collecting`, or a time window that contains a gap or a coverage restart for the channel, is Unknown. Event order uses `TimeCreatedUtc`; alert lifecycle ordering must clamp it to Core's receipt time.

## Resource bounds

| Resource | Agent | Core |
| --- | --- | --- |
| CPU | **Idle:** one metadata call per channel every 5 seconds, with the channel size and enablement cached for 5 minutes; an unavailable channel is touched once a minute. **New records:** one query, one seek and reads in batches of 64; only catalog records plus at most two numbered records are returned, and fields are rendered only for catalog records. **Backlog:** at most 1,024 records per channel and 2,048 per poll, re-polled after 1 second. **Pending batch:** no event log calls. | At most 60 requests per minute per remote IP. Each request: one credential check before the body is read, at most 256 KiB buffered, and one SQLite transaction with at most 256 observation inserts, 32 gap upserts plus one `rejected` gap row per invalid observation, 4 status upserts, a per-endpoint cap and an age sweep of at most 500 observations and 100 gaps. |
| Memory | One prepared batch (at most 256 observations, 192 KiB serialized and 32 gaps), four channel states, one cached property selector per catalog field list and one current record (plus the reader's internal batch of 64). | At most 256 KiB of buffer per request. |
| Disk | One file of at most 4 KiB: up to 30 writes per minute under sustained backlog (one per acknowledgement), at most 12 per hour for positions advanced past records with nothing to collect, none when idle. | At most 10,000 observations and 1,000 gap rows per endpoint, 30 days by receipt, and at most four status rows per endpoint. |
| Network | At most 30 requests per minute, each under the 256 KiB request limit (the worst case measures 207,253 bytes). Idle status reports at most every 5 minutes when counters change, plus one per hour. Transient retries back off from 5 seconds to 1 minute; an incompatible Core is retried every 15 minutes. | — |
| Logs | Channel state changes (one line per change of state or error code, judged at the end of each pass), gaps, delivery failures (throttled) and recovery; never field values. | Endpoint ID plus status code or counts. |

Capacity: during backlog the Agent scans up to 1,024 query-returned records per second per channel (2,048 in total), and it delivers at most 256 observations per 2 seconds, which is 128 observations per second or 7,680 per minute per endpoint. Sustained rates above these build a backlog until Windows overwrites unread records, which is reported as `overwritten` gaps.

## Configuration

Ordinary host configuration may tune collection; a value outside these bounds fails Agent startup:

| Key | Default | Allowed |
| --- | --- | --- |
| `Agent:EventPollInterval` | `00:00:05` | 100 ms – 5 minutes |

The other event intervals are derived from this poll interval (P):

| Timing | Formula | Default |
| --- | --- | --- |
| Backlog re-poll | min(1 second, P) | 1 second |
| Delivery spacing | min(2 seconds, 4P) | 2 seconds |
| Unavailable or failed channel retry | 12P | 1 minute |
| Incompatible Core retry | min(15 minutes, 180P) | 15 minutes |
| Status report after counter changes | min(5 minutes, 60P) | 5 minutes |
| Status liveness report | min(60 minutes, 720P) | 60 minutes |
| Saving positions advanced past records with nothing to collect | min(5 minutes, 60P) | 5 minutes |
| Channel size and enablement refresh | min(5 minutes, 60P) | 5 minutes |

Transient delivery retries use the existing `Agent:RetryDelay` (5 seconds) doubling to `Agent:MaxRetryDelay` (1 minute). Fixed in code: the 10-second request timeout and the separate 10-second bound on reading Core's result body (a peer that stalls after a 2xx cannot hold the loop; the batch counts as accepted), the scan caps, the batch and request limits, the checkpoint limits and Core retention. The catalog, channels and fields are compiled, so configuration can never widen collection.

`Agent:EventPollInterval` is not part of the pilot/Setup `--config` allowlist, so installed services use the defaults, and there is no installed-endpoint switch to disable or tune collection. There is no license check: collection and ingest continue in Safe Mode.

## Core storage and retention

`POST /api/agent/security-events` accepts a JSON batch from an enrolled Agent:

| Status | Meaning |
| --- | --- |
| `200` | The batch was committed: every item was stored, was already present, was ignored as unknown or was rejected as invalid. The body is `{accepted, duplicates, ignored, rejected}`. |
| `400` | Malformed JSON, a strictness violation (duplicate property, null for a non-nullable member, missing required member, number sent as a string, depth over 8) or an invalid envelope (for example the format, an item count over its limit, two statuses for one channel or a time that is not UTC). |
| `401` | Missing or invalid Agent credential, checked before any body byte is read, or a body endpoint ID that differs from the credential's. |
| `403` | Remote request without HTTPS. |
| `413` | `Content-Length` or the streamed body exceeds 256 KiB. |
| `415` | Not JSON. |
| `429` | More than 60 requests in a minute from one remote IP address. |

Unknown JSON members are skipped so later Agents stay compatible. There is no comparison with Core's clock: send and event times are stored as reported. Each item is validated on its own. An unknown item (another catalog tuple, status channel or state, or gap reason) is ignored; an invalid item is rejected, and an invalid observation with a known channel and record number is recorded as a `rejected` gap row. In the result, `accepted` and `duplicates` count observations only (newly stored versus already present), while `ignored` and `rejected` count items of every kind (observations, gaps and statuses). Valid gaps and statuses are stored but not counted.

Each batch is one immediate SQLite transaction: gaps first (so a coverage restart is judged against coverage before this batch), then observations, then statuses, then retention. Core stores its own re-serialization of each validated typed record, with the batch format and receipt time; raw request text and unknown members are never stored. A status from a new Agent process (a different `countersSinceUtc`) always replaces the stored one; within one process, an older attempt never overwrites a newer one.

Retention is measured by Core's receipt time, so an endpoint's clock cannot defeat it:

- At most 10,000 observations per endpoint (the most recently stored are kept), applied whenever a batch adds observations.
- At most 1,000 gap rows per endpoint, applied whenever a batch writes gaps.
- 30 days: every ingest also deletes up to 500 observations and 100 gap rows received more than 30 days earlier, across all endpoints, and Core startup deletes up to 5,000 of each.
- Status rows are not pruned (at most four per endpoint, without personal data).

Retention is fixed for installed Core. No API returns observation content; the only read surface is the status route below.

## Operator runbook: reading event-source status

`GET /api/admin/devices/{endpointId}/event-sources` requires the existing administrator bearer token and HTTPS outside loopback, and uses `Cache-Control: no-store`. It returns `401` without a valid token, `403` for remote HTTP and `404` for an unknown device. The response contains states, counters, record numbers and gap metadata only, never observation content, SIDs or names. Property names are camelCase:

| Property | Meaning |
| --- | --- |
| `endpointId` | The device. |
| `sources[]` | The latest accepted status of each reported channel, ordered by channel name. |
| `channel`, `state` | `collecting`, `disabled`, `accessDenied`, `notFound` or `error`. |
| `lastErrorCode` | The HResult behind an `accessDenied`, `notFound` or `error` state, as a signed 32-bit number (no message text); null while the channel is readable. |
| `oldestRecordId`, `newestRecordId` | The channel's record range at the Agent's last metadata call. |
| `checkpointRecordId` | The acknowledged position; null until coverage is acknowledged. |
| `logMaximumBytes`, `lastReadUtc` | Channel size (the buffer capacity) and the Agent time of the last successful metadata call. |
| `scanned`, `observed`, `delivered`, `droppedUnparsed`, `droppedOversize`, `fieldsDiscarded`, `gaps`, `skippedRecords`, `seekFallbacks` | Counters since `countersSinceUtc`. |
| `reportedUtc` | When Core received this status. |
| `agentSentUtc`, `countersSinceUtc`, `agentVersion` | The Agent's send time, the start of its counters (each Agent start resets them) and its version. |
| `coveredSinceUtc` | When Core first received an acknowledged position for the channel; never cleared. |
| `storedObservations` | Observations Core currently holds for the channel, after retention. |
| `recentGaps[]` | The 50 newest gap rows: `channel`, `reason`, `cause`, `firstRecordId`, `lastRecordId`, `detectedUtc` (Agent clock), `receivedUtc` and `coverageRestart` (a JSON boolean). |

Reading it:

- **Healthy:** `state` is `collecting`, `checkpointRecordId` is set and `reportedUtc` is recent. On the installed Agent, Security is expected to be `accessDenied`.
- **Stale:** `reportedUtc` older than 2 hours. A working Agent reports at least once an hour, so a stale status means that the Agent is stopped or not linked, Core is unreachable, delivery is held as incompatible, or event collection is stalled on the event log service. Heartbeats run independently, so the device's heartbeat time tells these cases apart.
- **Skew:** `reportedUtc − agentSentUtc`. A large value points to an Agent clock offset; event times use the Agent's clock, and Core does not reject them.
- **Lossy:** an `overwritten`, `logReset`, `dropped` or `rejected` gap row for the channel, or a `coverageStarted` row with `coverageRestart` true. A channel's first `coverageStarted` row (`coverageRestart` false) only marks where collection began. `skippedRecords` bounds the records lost to overwrites.
- **Lag:** `newestRecordId − checkpointRecordId`, together with `logMaximumBytes`, shows how close a backlog is to being overwritten.
- **Errors:** `error` with `lastErrorCode`, for example `-2147023436` (`0x800705B4`, Win32 error 1460) for a read timeout; the channel is retried every minute. A growing `seekFallbacks` means the bookmark seek is not being used; collection stays correct but costs more.

## Limits

- Collection is polled. A new event normally reaches Core within one poll interval plus the delivery spacing and request (up to about 7 seconds by default); a backlog or a failed delivery delays it further.
- Channel retention bounds outage recovery: records overwritten before delivery resumes are lost and reported as `overwritten` gaps.
- A backlog is scanned at up to 1,024 records per second per channel, and at most 128 observations per second are delivered per endpoint. Storms above that, such as many network (type 3) logons rejected by the 4624 condition on a busy server with a Security grant, build a backlog that can end in `overwritten` gaps.
- Windows audit policy decides whether 4624, 4625 and 4698 are logged at all. SentinelAI does not change audit policy.
- Localized SCM text for 7045 `ServiceType`/`StartType` and 7040 `param3` maps to null (Unknown) on non-English systems; numeric start types still map.
- Failed logons for accounts that do not exist carry no SID (`S-1-0-0` becomes null), because names are never collected; TASK-028 has to group them by source address and status.
- `ClearedChannel` of a 104 event is null on a Windows build where its UserData path does not render; the event is still collected.
- Schedules (polling, delivery, status and channel retries) follow the Agent's wall clock. When the clock steps back (a time correction or a manual change), every schedule moves back by the same amount, so collection resumes within one poll interval instead of waiting out the step.
- An acknowledged position of 0 (the log was empty when coverage started, or a reset emptied it) has no anchor record. Records written and then cleared between two polls of that empty log cannot be detected, and no gap is reported for them. Windows itself records the clear as System 104 or Security 1102, which is collected where the channel is readable.
- A log cleared and refilled to exactly its previous newest record is detected only when the next record arrives; no record is lost.
- Any LocalService process can edit the Agent's data directory. Moving a position backwards only replays (deduplicated), and deleting or corrupting the checkpoint is visible as a coverage restart, but moving a position forwards within the log silently skips records. This is the existing shared-LocalService limitation described in the [pilot guide](PILOT.md#install-and-enroll-agent).
- Local administrators and channel writers can forge or clear events. Observations are evidence, not proof; clears surface as `logCleared` (when read before loss) and as gaps.
- Event times are stored as reported, with no future or past bound. TASK-028 must order alert lifecycle by event time clamped to Core's receipt time.
- PowerShell 7 (`PowerShellCore/Operational`) is not collected, and 4104 is collected only at warning level, where Windows flags a suspicious script block.
- There is no installed-endpoint switch or tuning for event collection; installed Agents always collect the fixed catalog.
- The installed Agent does not collect Security until a read grant is approved.
- There is no watchdog thread. A hung event log service call stalls only this pipeline, and heartbeats continue; reads time out after 10 seconds, and the stall is visible as stale status.
- Endpoints behind one NAT share Core's per-IP request window; a `429` is retried with backoff.

## Validation

- **Deterministic (all platforms).** The real pipeline runs against an in-memory synthetic event log with a manual clock and scripted or in-memory Core semantics. The tests cover the option bounds and derived timings; catalog and contract conformance, the generated queries and this document's table and exclusions; normalization of every kind with excluded-field markers; image path derivation; the validator; the size proof (largest observation 2,823 bytes, worst-case request 207,253 bytes); checkpoint file hardening; dormancy, first start, steady delivery and idle cost; batch and gap caps; backpressure and the retry schedule; incompatible holds; continuity (overwrites, resets, clears while stopped, a clear after a reset, a reset whose new generation cannot be read in its pass followed by a second clear, new generations with overwritten starts, untimed records, unrenderable data conditions, seek fallbacks, races and crash consistency); availability and containment, including one log line for a channel that keeps failing after it is described; a backwards clock step; status cadence; scan caps and fairness; corrupt, foreign and temporarily held checkpoints; log privacy; uploader classification, including a result body that stalls after a 2xx; and link signalling. A randomized invariant run (3 seeds × 1,500 operations of appends, overwrites, clears, failures, lost acknowledgements, restarts and crash rollbacks) checks that every selected record reaches the in-memory Core exactly once or is covered by a reported gap. A source scan forbids message rendering, XML and log-clearing APIs.
- **Integration.** A real Agent host and a real Core with a synthetic event source cover first start, continuous delivery and latency, graceful restart without resend, crash replay absorbed as duplicates, an outage with bounded memory followed by overflow and drain, lost acknowledgements, degraded channels and a later grant, an unenrolled Agent and a deleted checkpoint becoming a visible coverage restart.
- **Core.** Ingest of every kind, replay and record-number reuse, unknown and invalid items, the status guard and coverage restart, gap merging, retention, the ordering and strictness matrix (including proof that unauthenticated bodies are refused without being read), the rate limit, the status route's exact shape and concurrent ingest. License tests cover ingest in Safe Mode, and update tests cover the checkpoint denylist.
- **Windows CI (default run, read-only).** Provider manifests must contain every catalog event and named field with a supported type (an absent Defender provider is a notice), every production query must parse on each channel the account can open (Security `accessDenied` and an absent Defender channel are notices), and the adapter's metadata, channel refusal and value conversion are checked. No event content is read.
- **Elevated Windows acceptance** (`--native-event-acceptance`) uses the production adapter with Core: a never-started test service installation must reach Core, the seek design is proven on a test-only classic log (including overwrite, clear and the resulting System 104), a restart must not resend, and secret markers must be absent from Core's database, Agent files and logs.
- **Setup acceptance** checks that the installed LocalService Agent reports System `collecting` and Security `accessDenied`, delivers a test service installation and keeps a valid checkpoint, and prints the observed state of every channel.
