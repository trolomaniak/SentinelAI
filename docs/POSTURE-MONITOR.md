# Continuous posture monitoring

The Agent detects changes to the Windows settings used by the [deterministic rules](../rules/README.md) within seconds, instead of waiting for the six-hour inventory refresh. A detected change is delivered to Core as a fresh, authenticated full inventory through the existing `/api/agent/inventory` route. Core is unchanged: it stores the newest report, evaluates the same rules, updates tracked alerts in the same transaction and computes Risk on the next read.

## What is monitored

Exactly the registry keys read by `WindowsSecurityConfigurationCollector` (`ConfigurationKeyPaths`), all under `HKLM` in the 64-bit view. A test fails if the watched list and the collector's reads diverge.

| Rules | Keys (policy first, then local) |
| --- | --- |
| SA-FW-001/002/003 | `SOFTWARE\Policies\Microsoft\WindowsFirewall\{Domain,Standard,Public}Profile`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{Domain,Standard,Public}Profile` |
| SA-UAC-001/002 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` |
| SA-RDP-001/002/003 | `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, `SYSTEM\CurrentControlSet\Control\Terminal Server`, `...\Terminal Server\WinStations\RDP-Tcp` |
| SA-SMB-001 | `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` |
| SA-SMB-002 | `SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation`, `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` |
| SA-LOGON-001 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` |
| SA-LSA-001 | `SYSTEM\CurrentControlSet\Control\Lsa` |
| SA-UPDATE-001 | `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` |

Rule meaning, evidence and severity do not change. Notifications carry no data: every check re-reads the same bounded allowlist with the same parser as inventory.

## How a change reaches Core

1. **Notification.** Each existing key is watched with a one-shot, thread-agnostic `RegNotifyChangeKeyValue` registration for value and subkey changes. An absent key (for example an unconfigured policy) is covered by watching its nearest existing ancestor subtree, so creating it is noticed; a hive root or top-level key is never watched. Registrations are replaced before every read, and callbacks from replaced registrations are ignored.
2. **Coalescing.** A notification only sets one signal slot. The monitor waits until no further notification arrives for the settle delay (default 2 seconds), at most five settle delays under a continuous storm, then re-arms and reads once.
3. **Comparison.** The read is compared with the posture Core last acknowledged. Equal posture, including a change reverted before delivery, requests nothing. A difference becomes one pending delivery.
4. **Delivery.** If the last heartbeat was acknowledged and the Agent is enrolled, the heartbeat worker wakes immediately, sends a heartbeat and then a freshly collected full inventory. Change-triggered uploads are spaced at least 30 seconds apart by default; a change inside that window waits for it and replaces any earlier pending change.
5. **Verification fallback.** Every five minutes, the monitor re-arms and re-reads even without notifications. This covers missed notifications, deleted/recreated keys, keys the service account cannot watch and hosts without registry notifications.

With defaults, a supported setting change normally reaches Core in about two to three seconds. Automated tests measured roughly 140–200 ms end to end (measured by polling Core) with a 100 ms settle delay and a five-minute heartbeat interval.

## Reconciliation

The six-hour full inventory remains unchanged and independent: change-triggered uploads neither replace nor postpone it. The first upload after start is a reconciliation, so a change made while the Agent was stopped is reported after restart. A failed reconciliation upload still retries after five minutes.

## Queue, retry and outage behavior

- **No queue.** There is one in-memory pending flag; observations are not queued or persisted, and nothing is written to disk. Core keeps only the newest report, so the latest posture is what matters.
- **Core unavailable.** Heartbeats keep their existing retry backoff (5 seconds doubling to 1 minute by default) and the posture monitor does not shorten it. No inventory upload is attempted until a heartbeat is acknowledged; then one fresh inventory with the latest posture is sent. Intermediate changes during the outage collapse into that one upload. Transport and HTTP failures are logged and never stop the Agent.
- **Upload rejected.** If a heartbeat succeeds but the inventory upload fails, the next upload attempt waits five minutes (the existing inventory retry delay). The change stays pending in its single slot.
- **Restart.** A pending delivery is not persisted. Startup reconciliation collects and sends the current posture instead.
- **Monitoring failure.** Notification-registration or read failures are logged; the monitor retries after the verification interval, and inventory reconciliation is unaffected.

## Resource bounds

| Resource | Bound |
| --- | --- |
| CPU | At most one allowlist read (22 registry values) and re-registration of at most 16 watches per settle period; about one per 10 seconds under a continuous notification storm; one every five minutes otherwise. No polling loop. |
| Memory | At most 16 registry watches (key handle, event and thread-pool wait each), one signal slot and three posture records. |
| Disk | None. |
| Network | At most one change-triggered inventory (Core accepts at most 16 KiB) plus its heartbeat per delivery interval (30 seconds by default), only when posture differs from Core's acknowledged posture. Core's existing per-client inventory rate limit still applies. |

## Configuration

Ordinary host configuration may tune monitoring; values outside these bounds fail Agent startup:

| Key | Default | Allowed |
| --- | --- | --- |
| `Agent:PostureSettleDelay` | `00:00:02` | 100 ms – 1 minute |
| `Agent:PostureDeliveryInterval` | `00:00:30` | 1 second – 1 hour |
| `Agent:PostureCheckInterval` | `00:05:00` | 1 second – 6 hours |

These keys are not part of the pilot/Setup `--config` allowlist, so installed services use the defaults.

## Limits

- Posture is current state, not an event history. A change that is reverted within the settle/spacing window, or during a Core outage, is not reported individually. Windows security events are collected separately; see [continuous security event collection](SECURITY-EVENTS.md).
- Detection covers the registry values above. Settings enforced only through mechanisms that do not update them are not observed, consistent with the rule catalog.
- The Agent runs as `NT AUTHORITY\LocalService`. A key it cannot read was already reported as Unknown; one it cannot watch is covered only by the five-minute verification.
- Group Policy refresh or other writes in watched keys cause cheap re-reads; nothing is uploaded unless the monitored posture changed.
- A privileged local account can stop the Agent or tamper with the registry; that remains outside the Agent's trust boundary.

## Validation

- Portable tests (all platforms) cover configuration bounds, watch-list/collector equivalence, coalescing of 1,000-notification bursts into one read, bounded reads under a continuous storm, revert/duplicate suppression, single-slot spacing and five-minute retry, periodic fallback and contained failures. With a real Core, they also cover delivery in seconds with a five-minute heartbeat, current findings, tracked alerts and Risk, duplicate bursts with zero extra uploads, preserved alert meaning after restoration, a Core outage with bounded retries and one latest upload, inventory rejection without retry storms, and restart reconciliation without persisted queue state.
- On Windows CI, the same suite uses actual registry notifications on a private `HKCU` copy of the monitored keys, including creation of an absent policy key, to deliver a change to Core.
- The elevated `package-agent-windows` step runs `--native-posture-acceptance` with the production Agent composition and default intervals. It changes the real `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` value, which Windows applies only at boot. It then requires SA-LSA-001 in Core within 30 seconds, allowing a heartbeat retry, and restores the original value. The first CI run measured 2.2 seconds.
