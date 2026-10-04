# Native Alerts and tracked incidents

After signing in, open **Alerts**. Select an endpoint, severity and review status, then **Apply filters**. Core applies the filters before returning the page and total; pages contain 50 alerts in Core's existing latest-observation order. **Refresh** reloads the current endpoint choices and first page. An empty result is explicit and does not establish endpoint safety or telemetry completeness.

Select a row and **Open alert**, or double-click it, to review the tracked incident without a browser. Detail shows endpoint and alert identity, rule ID/title, severity, reason, recommended action, typed evidence, first/latest observation, retained creation/update/status-change times and the reviewed version. Evidence values and all other strings are native literal text; no HTML, scripts or executable markup is rendered.

History shows the latest 100 retained status transitions, their UTC times and operator/system actor, with the full retained count disclosed. Creation, administrator decisions and automatic reopening remain distinct. Core retains the latest positive evidence; this view does not reconstruct intermediate observations or older evidence snapshots.

Choose **Open**, **Investigating**, **Accepted** or **Resolved**, then **Save status** to record an administrator decision. This changes only the tracked incident in Core and never endpoint configuration. The write includes the exact version you reviewed. A conflicting `409` reloads the current detail and explains that your change was not saved; review the new evidence/status and make a fresh decision. Desktop never automatically reapplies the rejected write.

If a write's response cannot be confirmed, its outcome may already be persisted. Desktop requires **Refresh latest** before another decision; it does not automatically retry the write. Confirmed saves return Core's authoritative detail/history and refresh the current filtered page. A failed list refresh does not undo or hide a confirmed status decision.

Core's lifecycle policy is unchanged: strictly newer positive evidence updates the incident and can reopen **Resolved** to **Open**. **Investigating** and **Accepted** remain those operator decisions when a positive finding repeats. Equal/older observations, normal telemetry and Unknown observations do not change the retained lifecycle. **Resolved** records a review decision and does not prove remediation.

## Boundaries

Alerts reuse Desktop's private short-lived session and actual connected-peer-verified local Core transport. Views never receive a bearer or read SQLite. Server writes remain authenticated and optimistic; no enrollment, endpoint mutation, remediation, export, cloud AI or later native screen is introduced here.

Requests have a ten-second complete-response deadline. Alert pages are bounded to 1 MiB and details to 256 KiB, including at most 100 history entries and 64 primitive evidence entries. Invalid, private/unknown response properties and oversized responses are rejected explicitly. Endpoint choices use the existing bounded public Devices API. Sign-out, expiry and close clear alert state and cancel pending operations; obsolete completions cannot restore data or invalidate a newer session. Successful periodic session validation preserves the selected page/detail.

## Verification

Run `./scripts/build.sh` and `./scripts/test.sh` for portable regression checks. Core integration tests exercise persistent lifecycle/history, concurrent version conflicts, newer-positive reopening, normal/Unknown behavior and combined endpoint/severity/status paging. Desktop transport and state tests cover validated public DTOs, typed literal values, session isolation, conflict readback and indeterminate writes. Windows WPF tests verify actual bindings, filtering/paging/detail/status controls, history/evidence, supported layouts and state clearing.

On the fresh elevated interactive Windows machine described in [authentication acceptance](DESKTOP-AUTH.md), add `-VerifyAlerts` to `tests/desktop/Authentication.Acceptance.ps1`. Its native extension exercises the published Desktop with a real signed installed Core: an isolated synthetic endpoint/rule, combined filters, typed evidence, saved status/history, a concurrent authenticated client's conflicting write, retained Accepted status, manual resolution, newer-positive reopening and persisted detail/history after a new Desktop session. Credentials remain in fixture memory and existing installations are never adopted.
