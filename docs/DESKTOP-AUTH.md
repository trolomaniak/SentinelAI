# Desktop administrator setup and sign-in

The native desktop creates the first local administrator and signs in through Core. Core remains the authority for account creation, password hashing and verification. The desktop never opens SQLite or stores credentials. The browser dashboard remains available; Devices provides a native list and endpoint details; the other workspace pages remain placeholders.

## Fresh installation

Install the signed Core files and protected configuration using the [pilot workflow](PILOT.md), then open the published `SentinelAI.Desktop.exe`. The desktop uses the existing default installation: `%ProgramFiles%\SentinelAI\Core`, `%ProgramData%\SentinelAI\Core` and `http://127.0.0.1:5000`.

Initial setup needs the installing operator's existing filesystem authority. When required, **Open initial setup as administrator** opens a separate UAC-approved native setup window. Enter a username and a password of at least 12 characters there. No password crosses the UAC process boundary or appears in process arguments.

The trusted installed Core executable receives bounded setup input through a private redirected standard-input pipe. It uses the existing password hasher and immediate SQLite transaction, creates one administrator only, then exits. A second creation attempt cannot replace or reset the existing administrator. Its read-only state command distinguishes missing administrator state from inaccessible or corrupt storage; an unavailable HTTP listener never establishes that first-run setup is required.

After setup, register/start Core through the existing [Core service installer](CORE-SERVICE.md), then sign in from the normal desktop window. Desktop setup does not install, start or stop the service. The original console launcher remains available for development and the pilot workflow. Service mode continues to refuse administrator bootstrap and requires an initialized administrator.

## Existing installation and sessions

Sign in with the existing Core administrator. Desktop uses Core's existing `/api/auth/login` and authenticated `/api/admin/me` routes. Unknown usernames and wrong passwords produce the same generic error. Throttling and unavailable/untrusted Core produce explicit safe errors without echoing server bodies or credentials.

The fixed local destination accepts no UI-selected host or path. Redirects, proxies, cookies and ambient authentication are disabled. For managed Core, administrator-controlled SCM registration identifies the expected virtual account, executable and live PID. Before HTTP can transmit a password or bearer, the connected TCP peer's exact server-side connection tuple must belong to that Core process. This prevents an unrelated process occupying port 5000 from receiving credentials. Console fallback additionally requires the operator's existing trusted installation access and exact executable/configuration command.

Passwords enter a native `PasswordBox`, are cleared on submission, and pass only through short-lived buffers erased after use. There is no password binding, credential file, argument, logging or crash-report collection. Bearers stay private in memory for at most Core's 15-minute session lifetime; refresh tokens are discarded. **Sign out** erases the local session, clears inputs and invalidates pending operations. It does not revoke other Core sessions.

The desktop revalidates an active session every five seconds. Local expiry, Core `401`, Core restart or connection loss returns it to a safe signed-out state. Reconnection requires explicit sign-in; it never replays a saved password. Closing either desktop window clears its own state and leaves Core running. Core rejects remote plaintext login before reading credentials; normal HTTPS authentication remains supported by Core.

## Verification

`./scripts/build.sh` and `./scripts/test.sh` include Core setup/authentication and portable session-state tests. The Windows WPF runner also checks password clearing, gated navigation, bootstrap, invalid credentials, sign-out and expiry.

On a fresh elevated interactive Windows x64 test machine without the default Core installation/service, run:

```powershell
.\tests\desktop\Authentication.Acceptance.ps1 -BundleDirectory 'C:\SentinelAI-Pilot' `
  -PublicKeyPath 'C:\SentinelAI-Trust\dev-pilot.public.pem' -KeyId dev-pilot `
  -Environment development -Channel pilot `
  -ExecutablePath .\artifacts\desktop\win-x64\SentinelAI.Desktop.exe
```

The acceptance fixture stages generated public inputs into fresh protected directories, installs signed Core files, creates the administrator through the actual published desktop, registers the existing managed service, and verifies real sign-in, generic invalid credentials, sign-out, foreign-listener rejection, restart/reconnect and independent Core lifetime. It retains protected test state and removes only its installer-owned service. Private signing keys and synthetic password values never become source/release assets. Record native CI results in [development status](../.agent/STATUS.md) before declaring verification complete.

The native fixture runs under the elevated installing operator. The interactive UAC prompt and the setup window opened from an unelevated Desktop require a separate manual Windows check; CI does not automatically approve that prompt.
