# Core hosting and desktop lifetime

Core is the existing .NET 10 ASP.NET Core host with SQLite persistence. Console/development hosting remains available. On Windows, the official WindowsServices host integration connects Core to SCM as `SentinelAICore`; it uses the executable's directory for content and requires the explicit, bounded, nonsecret `--config` file. Service mode refuses bootstrap credentials and first-run administrator creation. The console launcher or Desktop's Core-owned local setup command initializes the administrator before service registration.

The installer manages delayed automatic startup and a fixed limited virtual account, `NT SERVICE\SentinelAICore`. Code remains under protected Program Files and the existing pilot configuration/database remain under ProgramData. The service has read/execute access to code, read access to configuration and ownership receipts, and narrowly scoped runtime-data write access. Agent's LocalService identity, DPAPI state and enrollment rules are unchanged. A separate protected Core service receipt binds the SCM registration to the pilot installation; unknown registrations are refused.

Core and the WPF desktop are separate processes. Opening or closing the desktop does not control the Core service. Core's existing `/api/health` response is available after hosted persistence initialization, and service installation/start verifies both SCM state and the configured loopback health listener. Graceful service stop uses the host cancellation lifecycle with a 15-second shutdown budget. SCM crash/failure recovery uses bounded restart delays; ordinary operator stop does not request recovery.

The supported installer configuration remains loopback HTTP, with the existing HTTPS requirements preserved for other console deployments. No schema migration, administrator replacement, remote listener, certificate provisioning, secret-bearing service command or transactional upgrade integration is added. See [Core service operation and validation](CORE-SERVICE.md) and [pilot package trust](PILOT.md).

# Desktop authentication

The WPF shell uses a portable authentication state model and Core's existing login/session authority. Bearers remain private in memory, refresh tokens are discarded, and passwords are never model-bound or persisted. Sign-out invalidates pending completions; expiry, `401`, restart or connection loss closes the local session. Workspace navigation is gated behind authentication.

First-run detection and creation use one-shot commands in the trusted installed Core executable against the existing protected configuration. Creation accepts bounded credentials through private redirected stdin, uses the same hasher/atomic SQLite transaction, and cannot replace an administrator. The helper starts no HTTP listener. UAC is confined to a separate initial-setup window when required; normal sign-in remains unelevated and does not require access to SQLite or protected setup files.

SCM's administrator-controlled registration identifies the managed Core process. The native authentication transport verifies ownership of the actual connected TCP tuple before HTTP can write secrets, closing the port-occupation race of a simple pre-request listener check. Console fallback retains existing operator filesystem trust. Service identity/ACL/bootstrap policy remain unchanged, and remote plaintext login is rejected before credential body binding. See [desktop authentication](DESKTOP-AUTH.md).

# Native Desktop devices

Devices uses read-only administrator API calls through the same private authentication client and connected-peer-verified transport. No bearer is exposed to views/view models, and Desktop never reads SQLite or enrollment credentials. Core remains authoritative for healthy/warning/offline/unknown; configured security posture and inventory observation times are displayed separately.

Core's list response adds an optional inventory timestamp derived from the existing stored report. This avoids one detail request per fleet row, with no schema migration or change to existing fields. Desktop validates bounded public DTOs, filters/sorts the complete accepted list, and presents 100-row pages in a recycling native DataGrid. Detail shows only the public typed inventory fields already exposed by Core. Cancellation/generation checks reject obsolete results; sign-out clears all device state. See [native device operation](DESKTOP-DEVICES.md).

# Native Desktop alerts and incidents

Alerts uses the same private authenticated, connected-peer-verified transport for Core's public paged list/detail and versioned status API. An additive optional endpoint filter applies with severity/status before server paging and count, preserving existing defaults and response contracts. The native workspace renders bounded literal typed evidence and the latest retained history with its total disclosed.

Only the administrator's explicit save changes status, using the version reviewed in detail. Conflicts reload current state and require a fresh decision; uncertain write outcomes require a detail refresh before another save, with no automatic write retry. Core owns all persistent lifecycle/history and newer-positive reopening policy; no endpoint configuration changes are performed. Session cancellation and generations prevent obsolete completions from restoring workspace data. See [native incident operation](DESKTOP-ALERTS.md).
