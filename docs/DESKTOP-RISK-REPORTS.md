# Native Desktop Risk and Reports

Sign in through [Desktop authentication](DESKTOP-AUTH.md), then open **Risk** or **Reports**. Both use Core's existing administrator APIs through the same private session and verified local connection. The browser dashboard remains available.

## Review Risk

**Risk** shows Core's organization score, explanation, inventory/signal coverage, alert status counts, effective policy and evaluation time. The organization score is the highest endpoint score, not an average of the visible page. The ranked native list uses Core's order and 50-row server pages. **Next**, **Previous** and **Refresh** request Core pages; Desktop does not calculate or sort scores.

Select a row and **Open endpoint risk**, or double-click it. Endpoint detail exposes score, full decimal raw score, saturation, asset criticality and declared exposure with their sources/multipliers, correlation groups/base bonus/final bonus, inventory coverage/freshness and evaluation time. Expand a recorded finding to read its literal title/reason and every contributing factor: severity points, confidence weight/source, observation age/band/multiplier, future-time clamp, remaining-risk/status reduction, points before the status effect, final contribution, current-snapshot confirmation and correlation eligibility.

**Refresh endpoint** reads a new Core evaluation. The ranked list and endpoint detail retain their own evaluation times; a detail refresh does not rewrite the earlier ranked list. Successful periodic session validation preserves an open page/detail. An absent endpoint, missing inventory, no contributions and unavailable Core have explicit states.

Scores prioritize reported configuration findings. A zero rounded score may retain positive raw points, reflect confidence discounts/resolved findings or have missing observations; it never establishes effective protection or telemetry completeness. **Accepted** and **Investigating** remain risk-bearing under the existing policy. Criticality/exposure are declarations or labeled policy defaults, not inferred from hostname/firewall/RDP. Inventory freshness (default 12 hours) and scoring age windows (default seven/30 days) are separate. See [deterministic scoring semantics](../scoring/README.md).

## Generate and save a report

**Reports** defaults to the previous complete UTC calendar month. Choose ordered inclusive UTC dates, at most 366 days, with the end before `9999-12-31`, then select **Generate report**. Core produces the existing standalone HTML attachment; Desktop shows only its period, suggested filename, byte size and operation status. It never embeds, interprets or automatically opens the HTML.

Select **Save HTML** to open the native destination picker. The suggested name derives from the selected dates, not a server-supplied path. Confirm a `.html` destination and any replacement. Saving preserves Core's exact bytes, stages a temporary file in the selected directory, then moves it into the destination. A new file that appears during a non-overwrite save is preserved; final link/directory destinations are rejected. Cancelling the picker retains the generated report for another explicit save.

Editing either date, leaving Reports, signing out, losing the session or closing Desktop cancels pending work and disposes/erases retained report bytes. Stale downloads cannot become a new session's report; temporary save buffers are erased and unfinished temporary files are removed where possible. Files already explicitly saved remain the operator's exported documents. Open a saved HTML file yourself for offline viewing or browser printing/PDF.

Core's privacy projection, capacity checks and Safe Mode behavior are unchanged. Generation calls neither AI nor the License API and needs no premium entitlement. Selected-period incident activity is distinct from current risk/health/coverage. No historical score trend, historical fleet snapshot or intermediate positive-observation history is invented. The report excludes raw inventory, credentials, license material and status-history administrator identities; its evidence is allowlisted and dynamic HTML is encoded. See [report semantics and privacy](REPORTING.md).

## Transport and memory bounds

Passwords/bearers stay behind the existing authentication owner; views never receive a token or access SQLite. Requests use the fixed local origin and verified connected Core peer, with redirects, proxies, cookies and ambient authentication disabled. Risk strings render as native literal text. No new package, Core calculation, scoring policy, database history, AI operation or endpoint mutation is introduced.

| Operation | Complete-response deadline | Accepted body and data limits |
| --- | --- | --- |
| Risk page | 10 seconds | 2 MiB JSON; transport limit at most 200 rows, native pages exactly 50 |
| Endpoint Risk | 10 seconds | 1 MiB JSON; at most 64 contributions/public alerts and 64 correlation groups |
| Risk policy dictionaries | Within the Risk deadline/body bound | At most 1,024 entries per accepted dictionary; bounded keys/values and validated policy labels/numbers |
| Report generation/download | 30 seconds | Nonempty, strictly valid UTF-8 HTML, at most 8 MiB |

Report responses must have Core's `text/html; charset=utf-8`, attachment disposition, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and exact restrictive Content Security Policy. Desktop does not use a response filename or inspect the attachment as a DOM; Core remains the authority for report HTML and its embedded CSP/privacy projection. Malformed, oversized, unavailable and untrusted responses produce safe errors without displaying server bodies. Cancellation and generation checks discard obsolete responses before data publication or session-expiry notification.

## Verification

From the repository root:

```sh
./scripts/build.sh
./scripts/test.sh
```

On Windows x64 with the .NET 10 SDK:

```powershell
dotnet run --project tests/SentinelAI.Desktop.Windows.Tests/SentinelAI.Desktop.Windows.Tests.csproj --configuration Release --runtime win-x64
bash ./scripts/publish-desktop-windows.sh
```

Portable tests cover Core field/decimal preservation, all contributing factors, ranked server paging, bounds, strict attachment metadata/UTF-8, opaque byte preservation, explicit file saving, cancellation/clearing and stale-session races. Existing Core/scoring/report regressions cover deterministic output, report privacy and Safe Mode independence. Native WPF tests cover actual Risk/Reports bindings, factors, pagination, layouts, report actions and retained/cleared session state.

The local full build/test run and Debug Windows WPF cross-build passed with zero .NET warnings/errors. These results establish portable/backend regression coverage and compilation, not execution of WPF on Windows.

The Core-service Windows CI also runs `tests/desktop/Authentication.Acceptance.ps1 -VerifyDevices -VerifyAlerts -VerifyRiskReports` against the signed installed Core and published Desktop. Its isolated synthetic Risk/Reports fixture compares native ranking, scores and factors with real Core responses, generates in Safe Mode, saves through the actual Windows destination picker, verifies identical retained-document exports and checks privacy/session clearing. Cross-builds and portable tests cannot establish actual Windows acceptance; exact implementation/CI evidence is recorded in [development status](../.agent/STATUS.md).
