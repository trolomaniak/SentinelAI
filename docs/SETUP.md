# Single executable Windows setup

`SentinelAI-Setup.exe` installs and maintains the central SentinelAI installation of a company: Desktop, Core, Agent, the public-only Updater, protected configuration, both Windows services and an all-users Start Menu shortcut. By default Core also serves the Agents on the other computers of the local network (see [central computer and the local network](#central-computer-and-the-local-network)); a clearly labelled option keeps the installation local to one computer. It supports fresh installation, repair, upgrade, explicit recovery and uninstall for the owned default installation. Supported targets are Windows 10 22H2 x64 and Windows 11 x64; Windows Server 2022, which CI uses, keeps working. No SDK, separate .NET installation, browser or manual ZIP extraction is needed on the target. Windows PowerShell 5.1 is part of the supported operating system.

The artifact is a development/pilot installer built from source. Obtain the complete executable through a trusted delivery channel. Development manifest signatures authenticate Core/Agent packages; they are not an Authenticode signature for the setup executable. Production signing, release publication and trust distribution require separate operator provisioning.

## Install

1. Open the trusted `SentinelAI-Setup.exe` and approve Windows administrator elevation. Canceling the UAC prompt prevents setup from starting. Credentials are entered only after elevation.
2. Wait for Setup to verify its payload and inspect the local installation. On a fresh machine, choose the first local Core administrator username and a matching password of 12–1024 characters. **Allow Agents on other computers in this local network to connect** is selected by default; clear it to keep the installation local to this computer only. Select **Install SentinelAI**.
3. Follow the installation progress. Setup verifies its embedded resources and signed packages, creates Core's local-network certificate (unless local-only was chosen), installs Core, creates the administrator through Core's existing private setup command, starts Core, adds the Windows Firewall rule for the local network, obtains a one-use enrollment token through a connection verified as belonging to Core, and installs/enrolls Agent. It then installs Desktop/Updater and the shortcut.
4. After completion, use **Open Desktop** or **Start → SentinelAI**. Sign in explicitly with the administrator account you created. If a normal interactive Explorer shell is unavailable, Setup shows the Start Menu instruction rather than launching an elevated Desktop.
5. In native **Devices**, verify the enrolled endpoint and fresh heartbeat/inventory observation times. Closing Desktop leaves Core and Agent running.
6. In native **Settings**, **Local network** shows the computer's local-network IPv4 addresses, the HTTPS port and the SHA-256 fingerprint of Core's certificate, the values Agents on other computers use.

Fresh installation never adopts an existing or partial installation. If it fails before complete ownership is recorded, close Setup and inspect the retained state; unverified component directories, services or Start Menu entries are refused. Setup does not reset administrators or migrate accounts/data. Partial installation is not reported as success.

## Repair, upgrade and uninstall

Close Desktop before maintenance. Open a trusted Setup executable and approve elevation. Setup verifies fixed paths, ownership receipts, protected configuration, ACLs and service registrations before offering an operation. Credentials are requested only for a fresh installation; maintenance preserves the existing administrator and endpoint enrollment.

| Detected installation | Available operations |
| --- | --- |
| Owned installation; Setup version equals installed version | **Repair** or **Uninstall**. Repair restores authenticated program files at the installed version. |
| Owned installation; Setup version is newer | **Upgrade** or **Uninstall**. |
| Owned installation; Setup version is older | **Uninstall** only; code cannot be downgraded. |
| Protected data retained after an owned uninstall | Repair at the retained version or upgrade to a newer version restores code/services using the existing configuration and enrollment; uninstall can explicitly remove retained data. |
| Interrupted transaction | **Recover installation** restores an incomplete replacement or finishes reconciliation of an already healthy committed deployment. Close and reopen Setup after recovery. |
| Ownership cannot be verified | No operation is available; inspect the installation separately. |

Maintenance requires the installed key ID, public trust root, environment and channel to match the Setup package. A candidate cannot replace its own trust authority. Keep the same separately stored development key when building supported replacement versions.

Choose the available operation and select **Continue**. Repair and upgrade preserve Core SQLite/security history, administrator and installation identity, endpoint enrollment, Agent DPAPI state, protected configuration, license state and Core's local-network certificate and key, which every Agent pins. Repair and upgrade also restore the owned firewall rule if it was removed or changed. Setup does not create another administrator, re-enroll Agent or sign in to Desktop automatically. An installation keeps its role: an installation that was local-only, including one from before the central role existed, stays local-only.

Uninstall removes the owned services, the owned firewall rule, the complete program-code directory and owned Start Menu shortcut. **Keep security history and protected configuration** defaults to checked. Keeping data also keeps Core's certificate and key, so a restored installation is trusted by the same Agents. To remove the protected installation data too, select **Uninstall**, clear that checkbox and type the exact word **DELETE** in the confirmation field; this also deletes Core's certificate and its private key. Keeping data is distinct from a fresh installation: a later matching Setup recognizes the retained ownership and restores the same identity. Per-user Desktop preferences and the separately retained native bootstrap workspaces are outside this installation-data removal.

## Transaction and recovery

The publisher signs a single `sentinelai-deployment-win-x64` package containing Core, Agent, Desktop, Updater and their runtimes. Setup uses the existing [transactional updater](UPDATES.md#installation-and-rollback-api) to replace the whole protected code directory together. It verifies the signature, pinned installed trust, environment/channel, version floor, complete ZIP hash and bounded safe archive before stopping services. Equal-version repair uses an explicit authenticated repair policy; ordinary upgrade still requires a strictly newer version.

The shared updater retains the previous code and a durable journal, while Setup retains a protected receipt snapshot. Services keep their accounts and fixed configuration/data paths. Core health and Agent service/enrollment checks gate commit. For an installed deployment, failure or cancellation restores the previous code and checks its health with a separate bounded recovery token. Restoration after a retained-data uninstall starts from absent code/services rather than a previous running build. Persistent data is outside the replaceable code directory and is not rolled back or migrated.

If rollback cannot finish, Setup reports failure and retains recovery material. A later Setup shows **Recover installation**; recovery is an explicit action, followed by closing/reopening Setup before another operation. Setup never reports failed recovery as success or silently deletes history. Foreign paths, links, changed ownership/trust or unsupported partial state require separate administrator inspection. The journal supports process-interruption recovery; it does not guarantee recovery from every storage or power-loss failure.

## Installed layout and authority

| Location | Contents and access |
| --- | --- |
| `%ProgramFiles%\SentinelAI\Desktop` | Native workspace and self-contained runtime; Users read/execute, administrator/System write. |
| `%ProgramFiles%\SentinelAI\Core` | Signed Core package and runtime; limited Core service read/execute, installer-controlled code. |
| `%ProgramFiles%\SentinelAI\Agent` | Signed Agent package and runtime; LocalService read/execute, installer-controlled code. |
| `%ProgramFiles%\SentinelAI\Updater` | Public-only verification client and runtime; protected installer-controlled code. |
| `%ProgramData%\SentinelAI\Core` | Existing private SQLite/configuration/ownership layout; Core can update SQLite while protected configuration/receipts remain immutable to it. |
| `%ProgramData%\SentinelAI\Agent` | Existing LocalService inventory/enrollment state and security event positions; credential protected with that account's DPAPI. |
| `%ProgramData%\SentinelAI\Setup` | Pinned public trust key, ownership receipt, retained-installation marker and temporary maintenance receipt snapshot; no administrator password, bearer or enrollment token. |
| `%ProgramData%\SentinelAI-Setup` | Protected private payload workspaces and the exclusive setup-operation lock; no persistent application state. |
| Common Start Menu `SentinelAI\SentinelAI.lnk` | Exact installed Desktop target, no credential or startup arguments. |
| `LocalMachine\My`, certificate **SentinelAI Core local network** | Core's own local-network TLS certificate (public). Its non-exportable machine key is usable only by Core's service account (read), SYSTEM and Administrators. Central role only. |
| Windows Firewall rule `SentinelAI-Core-LocalNetwork` | Inbound TCP 5443 for `SentinelAI.Core.exe` from LocalSubnet on the Domain and Private profiles. Central role only. |

Core uses `NT SERVICE\SentinelAICore`, delayed automatic startup and its existing recovery policy. Agent uses automatic `NT AUTHORITY\LocalService`. Core listens at `http://127.0.0.1:5000` for the local Desktop and Agent and, in the central role, at HTTPS port 5443 on every interface for Agents on the local network. Setup does not provision cloud credentials, licensing entitlements or automatic updates. Desktop preferences and AI consent retain their default-off behavior.

Under LocalService, the Agent collects the selected System, PowerShell and Defender events where those channels are readable and reports the Security channel as access denied; Setup grants no additional event log access (see [security event collection](SECURITY-EVENTS.md#channel-access-and-localservice)).

## Central computer and the local network

The pilot runs one central installation per company on an always-on Windows computer; every other computer runs only the Agent and reports to it over the local network ([pilot MVP](MVP.md)). Agent installers and enrollment codes for those computers follow in MVP-2.

- **Listener.** Core keeps the loopback HTTP listener `http://127.0.0.1:5000` for the local Desktop and Agent and adds one HTTPS listener on the fixed port **5443** on every interface. That listener serves only the Agent routes: enrollment, heartbeat, inventory (including posture changes), security events and endpoint telemetry (`POST /api/agent/*`). Administrator, authentication, health, dashboard and Desktop routes answer `404` there, also with a valid administrator bearer. Desktop stays on the central computer.
- **TLS policy** (owner decision of 2026-10-19). Core enables TLS 1.2 and TLS 1.3 on that listener, so TLS 1.3 is negotiated whenever both computers support it and TLS 1.2 only when one side is Windows 10, whose SChannel has no TLS 1.3. Windows has no per-application cipher suite policy, so Core reads each connection's negotiated protocol and cipher suite (`ITlsHandshakeFeature`) and aborts it before any HTTP request unless it is TLS 1.3 with AES-GCM or TLS 1.2 with ECDHE key exchange and AES-GCM. TLS 1.1 and lower are never enabled.
- **Certificate.** Setup creates one certificate for Core at installation: ECDSA P-256, self-signed, valid for 10 years, subject and DNS names the computer's DNS name and FQDN, server authentication only, not a certificate authority. It is stored in `LocalMachine\My` with a non-exportable CNG machine key whose protected access list is set when the key is created: SYSTEM and Administrators full control, `NT SERVICE\SentinelAICore` read (enough to use it for TLS). The key never appears in logs, process arguments, environment variables, Setup output or the repository; only its public SHA-256 fingerprint travels from the Setup host to the installer and into Core's protected configuration. Nothing is added to any trusted root or certificate authority store.
- **Pin trust** (owner decision of 2026-10-19). An Agent configured with `Agent:CoreCertificateSha256` trusts Core when, and only when, the exact SHA-256 of Core's raw certificate matches that pin; chain and name errors are accepted only together with a matching pin, and a wrong pin ends the connection during the TLS handshake, before any enrollment token or credential is sent. Without a pin the existing full chain and name validation (and TLS 1.3 only) is unchanged. A remote Core URL always requires HTTPS and a pin.
- **Windows Firewall.** Setup adds one owned inbound rule, `SentinelAI-Core-LocalNetwork`: TCP 5443, program `SentinelAI.Core.exe`, remote address `LocalSubnet`, profiles Domain and Private only, never Public, no edge traversal. Windows applies no rule of the Private/Domain profiles while the network is classified as **Public** (the Windows default for a new network): set the company network to **Private** in Windows Settings, or Agents cannot connect.
- **Desktop.** Settings → **Local network** shows the computer name, its IPv4 addresses, the port and the certificate fingerprint, read from Core's administrator route `GET /api/admin/local-network` (loopback only). An administrator compares that fingerprint with the pin configured on an Agent; MVP-2's enrollment codes embed the same values.
- **Lifecycle.** Upgrade, repair, recovery and uninstall with retained data keep the certificate and key; repair and upgrade recreate a missing or changed firewall rule; uninstall removes the rule; confirmed data removal also deletes the certificate and key. A fresh installation refuses a computer that already has the owned rule, as it refuses any other existing installation state.
- **Missing certificate.** If the configured certificate is no longer in `LocalMachine\My`, Core keeps serving the local Desktop and Agent on loopback, logs that the local-network listener is disabled and Settings shows it as not listening. Setup's health checks then do not require the local-network listener. Agents pin the certificate, so it cannot be replaced without re-enrolling them.
- **Local only.** Clearing the option creates no certificate, no firewall rule and no local-network listener; Core then listens only at `http://127.0.0.1:5000`, as before MVP-1.

## Bootstrap and package trust

The outer executable is a native Windows bootstrap. Before loading .NET, it validates the embedded file table, sizes and SHA-256 hashes and extracts a complete private WPF host into an atomically protected, unique `%ProgramData%\SentinelAI-SetupHost` directory. It rejects unsafe paths, links, untrusted owners/write permissions and existing extraction targets. Runtime files are held read-only during supervised execution; after the bounded bootstrap deadline, protected ACLs still apply. Its child environment removes inherited code-loading overrides and uses private protected temporary storage, while preserving execution/application-control policies, proxy configuration and unrelated credentials.

This avoids relying on .NET's reusable single-file extraction cache for elevated setup. Setup's Core/Agent packages and Updater are published as ordinary self-contained directories, so service runtime libraries remain in protected installation code. The original manual pilot publisher retains its single-file default.

The private WPF host verifies the complete embedded payload before extraction. Its build-provisioned public key is a separate trusted resource and is staged outside the package bundle; a key selected from a delivered ZIP cannot become its own authority. Fresh installation verifies signed Core/Agent packages; maintenance authenticates the signed whole-deployment package against the existing installed trust root. Bootstrap, Desktop and Updater files are also authenticated by the executable's embedded resource hashes.

Setup reuses the existing installer implementations for path validation, ACLs, package verification, SCM ownership and enrollment. Their authenticated embedded PowerShell code is loaded as in-memory modules through the stock protected Windows PowerShell executable. No `ExecutionPolicy Bypass`, execution-policy change, security-control disablement or PowerShell SDK dependency is introduced. Enforced application control or constrained language can refuse setup; Setup reports failure without weakening those controls.

Administrator credentials stay in the setup process and Core's private initialization input. Agent receives only a bounded, one-use token issued over the existing Desktop connection-ownership checks. Credentials never become process arguments, environment variables, logs or permanent configuration. There is no automatic administrator sign-in.

## Build the development artifact

Publishing requires Windows x64, the .NET 10 SDK, PowerShell 5.1 or 7, and Visual Studio C++ build tools with the Windows SDK (`cl`/`rc`). These are build prerequisites only. Private development signing keys must be outside every repository ancestor and are never embedded or committed.

```powershell
$setupBuild = Join-Path $env:TEMP ('SentinelAI-Setup-Build-' + [Guid]::NewGuid().ToString('N'))
dotnet run --project tools/update-dev --configuration Release -- keygen --directory "$setupBuild\keys" --key-id dev-local-setup
.\scripts\publish-setup-windows.ps1 -Version 1.0.0 `
    -DevelopmentPrivateKey "$setupBuild\keys\dev-local-setup.private.pem" `
    -PublicKeyPath "$setupBuild\keys\dev-local-setup.public.pem" `
    -KeyId dev-local-setup
```

The default fresh output is `artifacts/setup/win-x64/1.0.0/SentinelAI-Setup.exe`. Publishing refuses an existing output, verifies that the independently supplied public key authenticates the Core/Agent and whole-deployment packages, and requires exactly one final executable. Private keys and intermediate artifacts are excluded. Versions are canonical `major.minor.patch`, each component 0–65535; fresh artifacts must be newer than `0.0.0`. Build the next version with the same key, key ID and channel for maintenance of that installed deployment. Keep the private development key separately; transfer only the completed Setup executable through the trusted channel.

## Validation

`./scripts/build.sh` and `./scripts/test.sh` include portable metadata/archive/credential-flow/protocol, version/action/explicit-removal/cancellation and shared signed-transaction tests, plus PowerShell setup workflow checks when `pwsh` is present. Native publishing requires the Windows build tools above.

```powershell
.\tests\setup\Windows.Acceptance.ps1 `
    -ExecutablePath .\artifacts\setup\win-x64\1.0.0\SentinelAI-Setup.exe
```

The native acceptance also verifies the central role on the runner: Core's certificate in `LocalMachine\My` with its key ACL and no trusted-store copy, the exported pin, the firewall rule's program, port, LocalSubnet and Domain/Private profiles, and that the listener is owned by the Core service. A Windows TLS 1.2 client is admitted (ECDHE with AES-GCM); administrator, authentication, health and dashboard routes answer `404` on the local-network listener; a client with a different pin cannot complete TLS. The installed Agent, started as a second endpoint with the runner's own non-loopback IPv4 address, is refused under a wrong pin without spending its one-use token, then enrolls with the exact pin and delivers heartbeat, inventory, telemetry and security events through the listener. The lifecycle acceptance checks that the certificate, pin and listener survive upgrade, health rollback, repair and retained-data restoration, that repair restores a deleted firewall rule, that uninstall removes it and that confirmed data removal deletes the certificate and its key.

TASK-024's recorded native acceptance passed the actual outer EXE, protected child runtime, rejection of caller-controlled runtime/temp caches, complete services/ACLs, one-use enrollment, LocalService DPAPI isolation/restart, fresh endpoint telemetry and Desktop authentication/independent lifetime. TASK-025's complete Windows lifecycle acceptance also passed in both push and PR CI: real upgrade, signed unhealthy candidate rollback, damaged-file repair, owned uninstall, identity-preserving retained-data restoration and explicit confirmed removal. Exact verified results and commits are recorded in [development status](../.agent/STATUS.md).

The lifecycle fixture runs on a fresh isolated Windows machine with three actual published executables sharing one temporary development trust root: initial `1.0.0`, healthy `1.1.0` and a signed `1.2.0` Core service fixture that runs without passing HTTP health. It exercises upgrade, real health-failure rollback, damaged-file repair, retained-data uninstall, restoration with the same identity/enrollment and confirmed removal through native controls:

```powershell
.\tests\setup\Lifecycle.Acceptance.ps1 `
    -InitialExecutablePath .\artifacts\setup\win-x64\1.0.0\SentinelAI-Setup.exe `
    -UpgradeExecutablePath .\artifacts\setup\win-x64\1.1.0\SentinelAI-Setup.exe `
    -UnhealthyExecutablePath .\artifacts\setup\win-x64\1.2.0\SentinelAI-Setup.exe
```

CI already has administrator authority. Interactive UAC consent/cancellation from a standard user and physical display scaling remain manual Windows checks; CI does not approve the secure-desktop prompt. The protected native bootstrap workspace is retained after exit for diagnosis and contains no operator credentials. Repeated setup attempts consume disk space until an administrator separately inspects/removes only those completed, owned runtime workspaces.

### Manual check on Windows 10 22H2

CI runs Windows Server only, so the central role on Windows 10, whose SChannel has no TLS 1.3, and Agents on other computers are checked by hand on two computers in one local network, with synthetic data only:

1. On a Windows 10 22H2 x64 computer that will be the central computer, set the network to **Private** (Settings → Network & Internet → Properties). Run `SentinelAI-Setup.exe` with **Allow Agents on other computers in this local network to connect** selected. Installation must finish without errors.
2. In an administrator PowerShell: `Get-NetFirewallRule -Name SentinelAI-Core-LocalNetwork | Format-List Enabled, Direction, Action, Profile` must show `True`, `Inbound`, `Allow`, `Domain, Private`; `Get-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name SentinelAI-Core-LocalNetwork)` must show `RemoteAddress : LocalSubnet`. `Get-NetTCPConnection -LocalPort 5443 -State Listen` must show a listener owned by the `SentinelAICore` process. `Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | Where-Object FriendlyName -eq 'SentinelAI Core local network'` must return nothing.
3. Open Desktop → **Settings** → **Local network** and note an address, the port `5443` and the fingerprint. Compare the fingerprint with `Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'SentinelAI Core local network' | ForEach-Object { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData)).Replace('-','') }`.
4. On the central computer, issue a one-use enrollment token in PowerShell (MVP-2 adds enrollment codes in Desktop): `$s = Invoke-RestMethod -Method Post http://127.0.0.1:5000/api/auth/login -ContentType application/json -Body (@{ username = '<administrator>'; password = Read-Host } | ConvertTo-Json)`, then `(Invoke-RestMethod -Method Post http://127.0.0.1:5000/api/admin/enrollment-tokens -Headers @{ Authorization = 'Bearer ' + $s.accessToken }).token`.
5. On a second computer (Windows 11 x64, then Windows 10 22H2 x64) in the same subnet, copy the published `SentinelAI.Agent.exe` and run it in a console with the environment variables `Agent__CoreUrl=https://<address>:5443`, `Agent__CoreCertificateSha256=<fingerprint>`, `Agent__DataDirectory=<empty folder>` and `Agent__EnrollmentToken=<token>`. Within a minute the computer appears in Desktop **Devices** with a fresh heartbeat and inventory. First run it once with one changed character in the fingerprint: it must log transport failures and never appear in Devices, and the same token must still enroll afterwards with the exact fingerprint.
   From the second computer, `curl.exe -k -i --tlsv1.2 https://<address>:5443/api/health` and `curl.exe -k -i --tlsv1.2 https://<address>:5443/` must answer `404` (`-k` only skips curl's own certificate check for this probe). `curl.exe -k -i --tlsv1.3 --tls-max 1.3 https://<address>:5443/api/health` must fail when either computer is Windows 10 and answer `404` when both are Windows 11, which shows TLS 1.3 is used whenever both sides support it.
6. Switch the central computer's network to **Public**: the Agent's connections must fail; switch back to **Private**: they recover. From a computer outside the local subnet (for example through a VPN or a routed network), connections must fail.
7. Run Setup again on the central computer and choose **Repair**: the fingerprint in Settings is unchanged and the Agent keeps reporting. Choose **Uninstall** with data kept: the firewall rule is gone and the certificate remains; repair restores both the rule and reporting. **Uninstall** with confirmed data removal deletes the certificate (step 3's command returns nothing).
8. Record the Windows build, the negotiated protocol (TLS 1.2 or 1.3) and the results in the release notes of the pilot build.

The [manual pilot guide](PILOT.md), [Core service guide](CORE-SERVICE.md) and [Desktop authentication guide](DESKTOP-AUTH.md) remain available for development and diagnostic workflows.
