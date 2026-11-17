# Security notifications

The native **Notifications** page provides a durable local center, read markers, grouped occurrence counts, delivery history and explicit policy settings. It works while Desktop is closed because Core records and processes notifications. External channels are disabled by default; the local center does not require them. Monitoring and delivery run independently, so a slow external recipient does not pause local heartbeat evaluation.

## What creates a notification

- A newly observed critical alert, a resolved alert observed again at critical severity, or an existing alert escalating to critical. Repeated critical observations do not repeatedly notify. Alert and notification changes commit together.
- An enrolled endpoint crossing the configured heartbeat absence threshold, then receiving a fresh heartbeat. The default threshold is fifteen minutes; the supported range is 5–120 minutes. The initial existing endpoint state is baselined without an upgrade notification flood. Removed endpoints are excluded.

Related transitions for the same endpoint and alert or monitoring condition are grouped within a fixed window (default five minutes, configurable 1–60). The center updates immediately; external delivery waits until that window ends. Retries retain the first attempted payload and notification identifier. Delivery does not continuously postpone itself when observations keep arriving.

Core must be running and reachable to process these notifications. An offline endpoint means missing recent heartbeats, not proof that it is switched off or compromised. These notifications do not cover all source-quality gaps; the next expanded-pilot stage addresses monitoring coverage. Core cannot send a notification while its own computer or network is unavailable.

## Optional external channels

Configure and explicitly enable either channel in Notifications. No external test message is sent automatically.

| Channel | Supported configuration |
| --- | --- |
| Webhook | One public HTTPS destination on port 443; optional signing secret of 16–512 UTF-8 bytes |
| E-mail | One SMTP server on port 587 with STARTTLS and authenticated PLAIN or LOGIN, one sender and one recipient |

SMTP passwords are 8–512 UTF-8 bytes. The integration does not provide OAuth, implicit TLS on port 465, anonymous relaying, custom mail templates, attachments, proxy configuration or private/intranet destinations. A provider that disables password authentication requires another supported integration or a compatible relay.

DNS results are checked for public routability on every new connection; any nonpublic answer rejects the entire result. Connections use a checked IP without a second DNS resolution. TLS still validates the original hostname and normal certificate trust. Webhooks do not follow redirects or use a proxy. Protocol responses and processing time are bounded. There is no arbitrary callback command or header setting.

The outbound content contains only the notification identifier, event kind, endpoint/alert identifiers, rule identifier, severity, occurrence count and timestamps, with format `sentinelai-notification-v1`. It excludes hostnames, user accounts, raw event data, finding prose and evidence. E-mail contains the same JSON as a base64-encoded MIME text body. A successful result means the webhook returned 2xx or the SMTP server accepted the message; it does not prove a human read it or that it reached an inbox.

Webhook requests use `Idempotency-Key: <notification UUID>`. If a signing secret is configured, `X-SentinelAI-Signature: sha256=<lowercase hex HMAC-SHA256>` authenticates the exact UTF-8 request body. Recipients should verify the signature before processing and deduplicate the notification UUID. The complete webhook URL may contain a private token: it is protected as a credential and is never returned by policy reads. Only its origin and presence flags are shown.

## Credentials, policy and delivery state

Windows machine DPAPI protects the stored webhook URL, webhook signing secret and SMTP password inside the installer-protected Core database. They are write-only settings. Blank replacement fields retain the current protected value; explicit clear actions remove it. The page never fills a password field with saved material. Other policy fields, including the SMTP account and sender/recipient addresses, remain administrator-visible configuration.

Policy saves require the current version. Conflicting saves must refresh first. A policy change cancels pending work under the old revision and asks an in-progress attempt to stop; it cannot retract data already accepted by a remote server. Saving new channel settings does not replay historical notifications.

The durable outbox attempts delivery at most five times, with bounded backoff. Failed completion persistence or a process interruption is recovered through a persisted lease and attempt fencing. A network failure can occur after the recipient accepted a message, so delivery is **at least once**, with possible duplicates. Acknowledgement is not an exactly-once guarantee. The local center and delivery history survive restart.

Notifications and their delivery records have a 30-day retention target and a 10,000-notification capacity. The oldest groups and their deliveries are removed at that capacity, including unsent work; this feature is not an indefinite audit archive. Read markers currently apply to the installation's shared administrator center.

## Backup recovery

Restoring or migrating an archive disables both external channels, removes their protected credentials and cancels queued deliveries before starting recovered Core. The monitoring baseline is rebuilt without replaying old transitions. Reconfigure and explicitly enable channels after successful recovery. Older backups without notification tables remain supported. Rolling back an unsuccessful restore returns the original live database.

## Administrator API

All routes require the existing administrator session, actual loopback access and `Cache-Control: no-store`. The Agent-only LAN listener denies these routes.

| Route | Purpose |
| --- | --- |
| `GET /api/admin/notifications?offset=0&limit=50&unreadOnly=false` | Bounded notification page and unread count |
| `PUT /api/admin/notifications/{id}/read` | Idempotently mark one existing notification as read |
| `GET /api/admin/notifications/deliveries?offset=0&limit=50` | Delivery history; optional `notificationId` filter |
| `GET /api/admin/notifications/policy` | Current version and sanitized settings |
| `PUT /api/admin/notifications/policy` | Explicit versioned settings and write-only credential replacements |

Pages contain at most 100 items. Policy bodies are capped at 16 KiB and reject missing required settings, duplicate properties and unknown properties. Production credentials and actual external deliveries are not used in tests.
