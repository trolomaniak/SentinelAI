# Single executable Windows setup

`SentinelAI-Setup.exe` installs and maintains a co-located SentinelAI deployment: Desktop, Core, Agent, the public-only Updater, protected configuration, both Windows services and an all-users Start Menu shortcut. It supports fresh installation, repair, upgrade, explicit recovery and uninstall for the owned default installation. The supported pilot target is Windows 11 x64. No SDK, separate .NET installation, browser or manual ZIP extraction is needed on the target. Windows PowerShell 5.1 is part of the supported operating system.

The artifact is a development/pilot installer built from source. Obtain the complete executable through a trusted delivery channel. Development manifest signatures authenticate Core/Agent packages; they are not an Authenticode signature for the setup executable. Production signing, release publication and trust distribution require separate operator provisioning.

## Install

1. Open the trusted `SentinelAI-Setup.exe` and approve Windows administrator elevation. Canceling the UAC prompt prevents setup from starting. Credentials are entered only after elevation.
2. Wait for Setup to verify its payload and inspect the local installation. On a fresh machine, choose the first local Core administrator username and a matching password of 12–1024 characters. Select **Install SentinelAI**.
3. Follow the installation progress. Setup verifies its embedded resources and signed packages, installs Core, creates the administrator through Core's existing private setup command, starts Core, obtains a one-use enrollment token through a connection verified as belonging to Core, and installs/enrolls Agent. It then installs Desktop/Updater and the shortcut.
4. After completion, use **Open Desktop** or **Start → SentinelAI**. Sign in explicitly with the administrator account you created. If a normal interactive Explorer shell is unavailable, Setup shows the Start Menu instruction rather than launching an elevated Desktop.
5. In native **Devices**, verify the enrolled endpoint and fresh heartbeat/inventory observation times. Closing Desktop leaves Core and Agent running.

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

Choose the available operation and select **Continue**. Repair and upgrade preserve Core SQLite/security history, administrator and installation identity, endpoint enrollment, Agent DPAPI state, protected configuration and license state. Setup does not create another administrator, re-enroll Agent or sign in to Desktop automatically.

Uninstall removes the owned services, complete program-code directory and owned Start Menu shortcut. **Keep security history and protected configuration** defaults to checked. To remove the protected installation data too, select **Uninstall**, clear that checkbox and type the exact word **DELETE** in the confirmation field. Keeping data is distinct from a fresh installation: a later matching Setup recognizes the retained ownership and restores the same identity. Per-user Desktop preferences and the separately retained native bootstrap workspaces are outside this installation-data removal.

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
| `%ProgramData%\SentinelAI\Agent` | Existing LocalService inventory/enrollment state; credential protected with that account's DPAPI. |
| `%ProgramData%\SentinelAI\Setup` | Pinned public trust key, ownership receipt, retained-installation marker and temporary maintenance receipt snapshot; no administrator password, bearer or enrollment token. |
| `%ProgramData%\SentinelAI-Setup` | Protected private payload workspaces and the exclusive setup-operation lock; no persistent application state. |
| Common Start Menu `SentinelAI\SentinelAI.lnk` | Exact installed Desktop target, no credential or startup arguments. |

Core uses `NT SERVICE\SentinelAICore`, delayed automatic startup and its existing recovery policy. Agent uses automatic `NT AUTHORITY\LocalService`. Core listens only at `http://127.0.0.1:5000`; Setup does not provision remote listeners, TLS certificates, firewall rules, cloud credentials, licensing entitlements or automatic updates. Desktop preferences and AI consent retain their default-off behavior.

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

TASK-024's recorded native acceptance passed the actual outer EXE, protected child runtime, rejection of caller-controlled runtime/temp caches, complete services/ACLs, one-use enrollment, LocalService DPAPI isolation/restart, fresh endpoint telemetry and Desktop authentication/independent lifetime. TASK-025's Windows lifecycle acceptance is pending; portable tests or cross-compilation alone do not establish it. Exact verified results and commits belong in [development status](../.agent/STATUS.md).

The lifecycle fixture runs on a fresh isolated Windows machine with three actual published executables sharing one temporary development trust root: initial `1.0.0`, healthy `1.1.0` and a signed `1.2.0` Core service fixture that runs without passing HTTP health. It exercises upgrade, real health-failure rollback, damaged-file repair, retained-data uninstall and confirmed removal through native controls:

```powershell
.\tests\setup\Lifecycle.Acceptance.ps1 `
    -InitialExecutablePath .\artifacts\setup\win-x64\1.0.0\SentinelAI-Setup.exe `
    -UpgradeExecutablePath .\artifacts\setup\win-x64\1.1.0\SentinelAI-Setup.exe `
    -UnhealthyExecutablePath .\artifacts\setup\win-x64\1.2.0\SentinelAI-Setup.exe
```

CI already has administrator authority. Interactive UAC consent/cancellation from a standard user and physical display scaling remain manual Windows checks; CI does not approve the secure-desktop prompt. The protected native bootstrap workspace is retained after exit for diagnosis and contains no operator credentials. Repeated setup attempts consume disk space until an administrator separately inspects/removes only those completed, owned runtime workspaces.

The [manual pilot guide](PILOT.md), [Core service guide](CORE-SERVICE.md) and [Desktop authentication guide](DESKTOP-AUTH.md) remain available for development and diagnostic workflows.
