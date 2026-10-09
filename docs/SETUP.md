# Single executable Windows setup

`SentinelAI-Setup.exe` installs a fresh, co-located SentinelAI deployment: Desktop, Core, Agent, the public-only Updater, protected configuration, both Windows services and an all-users Start Menu shortcut. The supported pilot target is Windows 11 x64. No SDK, separate .NET installation, browser or manual ZIP extraction is needed on the target. Windows PowerShell 5.1 is part of the supported operating system.

The artifact is a development/pilot installer built from source. Obtain the complete executable through a trusted delivery channel. Development manifest signatures authenticate Core/Agent packages; they are not an Authenticode signature for the setup executable. Production signing, release publication and trust distribution require separate operator provisioning.

## Install

1. Open the trusted `SentinelAI-Setup.exe` and approve Windows administrator elevation. Canceling the UAC prompt prevents setup from starting. Credentials are entered only after elevation.
2. Choose the first local Core administrator username and a matching password of 12–1024 characters. Select **Install SentinelAI**.
3. Follow the installation progress. Setup verifies its embedded resources and signed packages, installs Core, creates the administrator through Core's existing private setup command, starts Core, obtains a one-use enrollment token through a connection verified as belonging to Core, and installs/enrolls Agent. It then installs Desktop/Updater and the shortcut.
4. After completion, use **Open Desktop** or **Start → SentinelAI**. Sign in explicitly with the administrator account you created. If a normal interactive Explorer shell is unavailable, Setup shows the Start Menu instruction rather than launching an elevated Desktop.
5. In native **Devices**, verify the enrolled endpoint and fresh heartbeat/inventory observation times. Closing Desktop leaves Core and Agent running.

Setup is first-install only. Existing component directories, services, retained state or Start Menu entries are refused. There is no repair, upgrade, administrator reset, account/state migration or destructive rollback. If a step fails, close Setup and inspect the retained installation before taking a separate recovery action; persistent data is never automatically deleted. Partial installation is not reported as success.

## Installed layout and authority

| Location | Contents and access |
| --- | --- |
| `%ProgramFiles%\SentinelAI\Desktop` | Native workspace and self-contained runtime; Users read/execute, administrator/System write. |
| `%ProgramFiles%\SentinelAI\Core` | Signed Core package and runtime; limited Core service read/execute, installer-controlled code. |
| `%ProgramFiles%\SentinelAI\Agent` | Signed Agent package and runtime; LocalService read/execute, installer-controlled code. |
| `%ProgramFiles%\SentinelAI\Updater` | Public-only verification client and runtime; protected installer-controlled code. |
| `%ProgramData%\SentinelAI\Core` | Existing private SQLite/configuration/ownership layout; Core can update SQLite while protected configuration/receipts remain immutable to it. |
| `%ProgramData%\SentinelAI\Agent` | Existing LocalService inventory/enrollment state; credential protected with that account's DPAPI. |
| `%ProgramData%\SentinelAI\Setup` | Public trust key and nonsecret setup ownership receipt; no administrator password, bearer or enrollment token. |
| Common Start Menu `SentinelAI\SentinelAI.lnk` | Exact installed Desktop target, no credential or startup arguments. |

Core uses `NT SERVICE\SentinelAICore`, delayed automatic startup and its existing recovery policy. Agent uses automatic `NT AUTHORITY\LocalService`. Core listens only at `http://127.0.0.1:5000`; Setup does not provision remote listeners, TLS certificates, firewall rules, cloud credentials, licensing entitlements or automatic updates. Desktop preferences and AI consent retain their default-off behavior.

## Bootstrap and package trust

The outer executable is a native Windows bootstrap. Before loading .NET, it validates the embedded file table, sizes and SHA-256 hashes and extracts a complete private WPF host into an atomically protected, unique `%ProgramData%\SentinelAI-SetupHost` directory. It rejects unsafe paths, links, untrusted owners/write permissions and existing extraction targets. Runtime files are held read-only during supervised execution; after the bounded bootstrap deadline, protected ACLs still apply. Its child environment removes inherited code-loading overrides and uses private protected temporary storage, while preserving execution/application-control policies, proxy configuration and unrelated credentials.

This avoids relying on .NET's reusable single-file extraction cache for elevated setup. Setup's Core/Agent packages and Updater are published as ordinary self-contained directories, so service runtime libraries remain in protected installation code. The original manual pilot publisher retains its single-file default.

The private WPF host verifies the complete embedded payload before extraction. Its build-provisioned public key is a separate trusted resource and is staged outside the package bundle; a key selected from a delivered ZIP cannot become its own authority. The existing public Updater verifies Core/Agent manifest signatures, hashes, environment, channel, artifact and version before installation. Bootstrap, Desktop and Updater files are authenticated by the executable's embedded resource hashes.

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

The default fresh output is `artifacts/setup/win-x64/1.0.0/SentinelAI-Setup.exe`. Publishing refuses an existing output, verifies that the independently supplied public key authenticates both signed packages, and requires exactly one final executable. Private keys and intermediate artifacts are excluded. Keep the private development key separately; transfer only the completed Setup executable through the trusted channel.

## Validation

`./scripts/build.sh` and `./scripts/test.sh` include portable metadata/archive/credential-flow/protocol tests and the PowerShell setup workflow checks when `pwsh` is present. Native publishing requires the Windows build tools above.

```powershell
.\tests\setup\Windows.Acceptance.ps1 `
    -ExecutablePath .\artifacts\setup\win-x64\1.0.0\SentinelAI-Setup.exe
```

The dedicated fresh `setup-windows` CI job executes the actual outer EXE and native controls with synthetic credentials. It verifies the protected child runtime, rejection of caller-controlled runtime/temp caches, complete services and ACLs, one-use enrollment, LocalService DPAPI isolation and restart, fresh exact endpoint telemetry, shortcut/native Desktop sign-in, independent service lifetime and refusal of a repeated installation. Native execution results and exact commits are recorded in [development status](../.agent/STATUS.md); cross-compilation alone does not establish acceptance.

CI already has administrator authority. Interactive UAC consent/cancellation from a standard user and physical display scaling remain manual Windows checks; CI does not approve the secure-desktop prompt. The protected native bootstrap workspace is retained after exit for diagnosis and contains no operator credentials. Repeated setup attempts consume disk space until an administrator separately inspects/removes only those completed, owned runtime workspaces.

The [manual pilot guide](PILOT.md), [Core service guide](CORE-SERVICE.md) and [Desktop authentication guide](DESKTOP-AUTH.md) remain available for development and diagnostic workflows.
