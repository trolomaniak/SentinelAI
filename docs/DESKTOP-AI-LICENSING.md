# Native AI, licensing and local settings

Settings reads Core's public FULL, GRACE, SAFE_MODE or RECOVERING state after sign-in. It shows permitted optional features, local capabilities, signed validation/expiry times and Core's effective UTC/rollback information. Desktop never recalculates lease deadlines. RECOVERING retains Core's underlying permissions; expired signed timestamps can remain visible in Safe Mode. Missing status is explicitly unknown.

Use **Renew license** for one manual attempt against Core's existing configured issuer. A response reporting GRACE or SAFE_MODE is a completed attempt without restoring FULL. Unconfigured, rate-limited and unavailable requests have fixed safe messages. A lost or malformed renewal response has an unknown result: use **Refresh license** to reconcile before requesting another attempt. Desktop never replays renewal, changes the issuer, displays lease bodies or reads activation credentials. Core's existing automatic renewal behavior remains independent.

Settings also shows the fixed local Core address, Desktop version, connection status and memory-only session policy. **Check Core connection** runs the existing bounded health check. Protected AI/license configuration stays with Core; Settings has no credential, gateway, issuer or destination editor.

Cloud AI requests are off by default. Enable **Allow cloud AI requests for this session**, open a supported stored alert under Alerts and choose **Explain with AI**. Enabling the setting or selecting an alert sends nothing automatically. The action additionally requires a current public premium capability and exact `cloud_ai` permission; Core enforces the current signed entitlement and supported minimized evidence again. Safe Mode withholds AI while local monitoring, alert decisions, Risk and Reports remain available.

The explicit request sends only the alert ID to Core. Existing Core minimization excludes arbitrary text, hostnames, identifiers, actors and raw logs from gateway context. Desktop receives the existing structured explanation, impact, investigation/remediation suggestions, qualitative confidence and uncertainty. All text is literal under **AI assistive analysis**, with administrator review required; there are no execution controls or automatic endpoint changes. No provider key or gateway credential reaches Desktop.

AI outage, unsupported evidence, expired permission, throttling and malformed responses are explicit safe states. Restore availability and explicitly request again; there is no automatic paid retry. Leaving Alerts, changing the selected alert/version or disabling consent cancels pending work and clears analysis. Navigation preserves the local session preference; sign-out, session expiry and close clear both analysis and consent. Obsolete replies cannot restore content or sign out a newer session. Analysis and preferences are not persisted or intentionally logged.

The same private authentication owner and connected-peer-verified transport serve all native pages. JSON is closed-schema and bounded: license status allows 16 KiB, 64 unique feature names up to 64 ASCII letters/digits/underscore/hyphen; AI reuses the existing strict 32 KiB first-party contract. Whole-operation deadlines include trust, headers and body: 10 seconds for licensing reads, 65 seconds for manual renewal and AI (Core permits a 60-second downstream timeout). Failure bodies and exception text are never rendered or logged.

Verification uses `scripts/build.sh`, `scripts/test.sh` and actual Windows WPF tests:

```powershell
dotnet run --project tests/SentinelAI.Desktop.Windows.Tests/SentinelAI.Desktop.Windows.Tests.csproj --configuration Release --runtime win-x64
```

Core-service CI runs `tests/desktop/Authentication.Acceptance.ps1 -VerifyDevices -VerifyAlerts -VerifyRiskReports -VerifyAiLicenseSettings` against signed installed Core and published Desktop. The final fixture verifies real Safe Mode/public state, unconfigured manual renewal, session consent, the supported-alert AI gate and continued local pages. Actual WPF tests cover licensed success, literal output, outages, all modes, layouts and session races with synthetic services; existing Core/gateway integration tests cover minimized real request boundaries without production keys. Exact results are recorded in [development status](../.agent/STATUS.md).
