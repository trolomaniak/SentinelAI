# Expanded pilot 02 — Security notifications

Owner-approved sequence: docs/EXPANDED-PILOT.pl.md. Based on backup/recovery PR #56 after all twelve CI jobs passed on dfc1c3d; do not merge or release either feature automatically.

## Scope

- Durable local notification center for new/reopened/escalated critical alerts and endpoint monitoring lost/recovered transitions. Repeated observations do not create storms; fixed grouping window and durable transition state survive restart.
- Bounded paging, unread/read state, delivery history and explicit versioned policy. No historical alert flood on upgrade. Default external channels disabled; the local center works independently.
- Optional one HTTPS webhook and one SMTP STARTTLS channel. Explicit administrator configuration; write-only Windows-protected credentials; minimal structured payload without evidence, usernames, host names or arbitrary finding text. No implicit external test delivery.
- Public-routable destinations only, per-connection DNS validation and pinning, no proxies/redirects, strict TLS validation, bounded protocol responses, timeouts, cancellation and retries. Arbitrary headers, templates, executable callbacks and attachments are out of scope.
- Transactional outbox, bounded retry/backoff, stable idempotency key, honest at-least-once semantics. Policy changes cancel stale queued work; recovery disables external sending and cancels pending deliveries, so old snapshots cannot silently resend old notifications or revive secrets.
- Native English/Polish Desktop page with notification list/read state, delivery results and settings. Password fields are short-lived, not view-model properties; settings responses never return secrets.

## Acceptance

Synthetic tests cover committed/rolled-back critical transitions, deduplication/grouping, offline/recovery boundaries, restart, paging, retention, auth/LAN boundaries, policy concurrency, write-only secrets, safe outbound addresses/DNS pinning, malformed/oversized protocol replies, retries, cancellation and recovery suppression. No real recipient or third-party endpoint is contacted in tests. Relevant build/regression and native Windows CI pass. Update STATUS and documentation with actual evidence.
