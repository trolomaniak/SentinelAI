# Native Devices and endpoint details

After signing in, open **Devices** to read enrolled endpoints from Core. The native list shows hostname, full operating system/release/build string, Agent version, heartbeat connectivity, last heartbeat, last inventory time and configured firewall summary. Select a row and **Open endpoint**, or double-click it, to open native details. **Back to devices** returns to the list without launching a browser.

Search matches hostname, endpoint ID, operating system or Agent version. The connectivity filter retains Core's Healthy, Warning, Offline and Unknown states. Choose a sort column/direction to sort the whole accepted fleet before paging; pages contain at most 100 rows and the native grid recycles visible rows. **Refresh** requests current Core data. Filtering an empty fleet and filtering an existing fleet to no matches have distinct messages.

Core alone classifies heartbeat health: at most two minutes is Healthy, over two through five minutes is Warning, over five minutes is Offline, and no heartbeat is Unknown. Desktop displays Core's returned value without recalculating thresholds or inferring connectivity from firewall settings. Inventory may be old even when heartbeat connectivity is healthy. Timestamps are explicitly UTC; an unavailable list inventory timestamp is **Unknown / not reported**. The optional timestamp is additive, so older Core responses do not cause Desktop to infer inventory absence.

Details show endpoint identity, connectivity, operating system name/release/build, Agent version, inventory time, architecture, CPU, RAM, disks and the public configured firewall/security observations already exposed by Core. A missing inventory is explicit; unavailable fields and nullable configuration observations remain Unknown. Configured firewall settings do not establish effective packet enforcement, Internet reachability or overall endpoint safety.

The list and details handle loading, no data, no matches, missing endpoint and Core-unavailable/untrusted/invalid-response states. Data is cleared on sign-out, expiry and window close; obsolete requests cannot repopulate it or invalidate a newer session. Reconnect follows the existing explicit [sign-in flow](DESKTOP-AUTH.md).

## Boundaries and limits

Desktop calls only the existing read-only administrator device routes through the same private, short-lived session and verified local Core transport. It never reads SQLite, enrollment credentials, password hashes or raw configuration. There is no device edit, enrollment action, remediation, new dependency, schema migration or later native screen.

List requests have a ten-second complete-response deadline, an 8 MiB JSON bound and a 10,000-endpoint limit. Details have the same deadline, a 256 KiB bound and at most 64 disk records. Oversized responses are rejected with an explicit message; the fleet is never silently truncated. Core's existing list API returns the full fleet, so server-side paging/background refresh is not introduced here.

## Verification

Run `./scripts/build.sh` and `./scripts/test.sh` for the complete portable regression suite. The Windows WPF runner covers actual bindings, gated device reads, native list/details, filters, sorting, paging, row virtualization, supported window sizes and sign-out clearing.

On the fresh elevated interactive Windows test machine described in [authentication acceptance](DESKTOP-AUTH.md), add `-VerifyDevices` to `tests/desktop/Authentication.Acceptance.ps1`. Its native extension enrolls two synthetic endpoints through the real Core API: one with heartbeat/inventory and a disabled firewall profile, and one without any heartbeat/inventory. It verifies the published Desktop's actual list, filtering, native details, release/build/time/hardware, separate health/posture and explicit Unknown/no-inventory states. Synthetic credentials remain in fixture memory; existing test installations are never adopted and protected test state is retained.
