# Signed update foundation

TASK-014 provides a public-only verification library, local verification/staging client, development-only signing tool and transactional installation API with rollback. It does not add automatic downloads, a release server, scheduling, or pilot installation/service registration.

## Manifest and explicit trust

An update is a bounded UTF-8 JSON envelope with exactly `format`, `keyId`, `manifest` and `signature`. The format is `sentinelai-update-v1`. The nested manifest contains exactly:

- `version`: canonical numeric `major.minor.patch`, each component 0–65535;
- `artifactId`: the expected artifact identifier;
- `artifactUrl`: an HTTPS URL without credentials, query or fragment;
- `sha256`: 64 lowercase hexadecimal characters for the complete ZIP bytes;
- `sizeBytes`: the exact compressed byte count, greater than zero and at most 512 MiB;
- `channel`: `stable`, `pilot` or `beta`;
- `environment`: `development` or `production`.

The client pins the expected environment, channel, artifact identifier, installed version and named public SPKI P-256 trust anchors. Pilot and Beta are explicit opt-in channels; neither is accepted under Stable policy. Development manifests are rejected under Production policy even if their public key is accidentally supplied there. Keys are provisioned locally, not downloaded from the manifest. Update keys are separate from licensing keys and Agent credentials.

ECDSA P-256/SHA-256 signs the canonical JSON containing the format, key ID and all manifest fields. The signature is a fixed 64-byte IEEE P1363 value encoded as canonical unpadded base64url. There is no algorithm negotiation. Missing/duplicate/unknown fields, malformed types, oversized documents, invalid signatures and policy mismatches fail closed. The maximum manifest size is 8 KiB. Candidate versions must be strictly newer than the configured installed version; an authenticated installed receipt also prevents applying a stale candidate when the caller's version floor is outdated.

Public verification code contains no private-key importer or signer. Production private keys and production signing stay outside this repository and the client. The separate development tool generates disposable development keys outside the checkout, uses only `dev-` key IDs and always signs `environment: development`; it has no production mode. Unix private key files are owner-only; Windows key directories require account-restricted ACLs. Private PEM files are also ignored by Git as a secondary guard.

## Local development workflow

From a Windows PowerShell terminal at the repository root, use a separate directory under local application data. The example uses version `1.1.0` over an explicitly known installed `1.0.0`; choose the actual versions for your installation.

```powershell
$updateWork = Join-Path $env:LOCALAPPDATA 'SentinelAI\UpdateDevelopment'
New-Item -ItemType Directory -Force -Path $updateWork | Out-Null
dotnet run --project tools/update-dev -- keygen --directory "$updateWork\keys" --key-id dev-local

dotnet publish agent/SentinelAI.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:DebugSymbols=false -p:Version=1.1.0 -p:AssemblyVersion=1.1.0.0 -o "$updateWork\agent-code"
Compress-Archive -LiteralPath "$updateWork\agent-code\SentinelAI.Agent.exe" -DestinationPath "$updateWork\agent-1.1.0.zip"

dotnet run --project tools/update-dev -- sign --private-key "$updateWork\keys\dev-local.private.pem" --key-id dev-local --package "$updateWork\agent-1.1.0.zip" --version 1.1.0 --artifact-id sentinelai-agent-win-x64 --artifact-url https://updates.example.invalid/agent-1.1.0.zip --channel pilot --output "$updateWork\agent-1.1.0.manifest.json"

dotnet run --project updater -- verify --manifest "$updateWork\agent-1.1.0.manifest.json" --package "$updateWork\agent-1.1.0.zip" --public-key "$updateWork\keys\dev-local.public.pem" --key-id dev-local --environment development --channel pilot --artifact-id sentinelai-agent-win-x64 --installed-version 1.0.0
```

The example artifact URL is metadata; these commands make no network request. Generate each key pair once; existing keys/manifests/packages are not overwritten. The signing tool does not infer the executable's version, so publish the artifact with the same explicit version that is signed. Legacy installations need an operator-supplied current version floor. The existing Agent's assembly version includes a fourth component; the update policy uses its first three numeric components.

The client `stage` command accepts the same flags as `verify` plus `--output ABSOLUTE_NEW_FILE`. Choose an output directory controlled by the operator, with account-restricted ACLs on Windows. Both commands verify the signature and stream the exact package into a new private copy while checking its signed hash and size. Verification deletes its temporary copy; staging retains the verified ZIP. These commands do not extract code, stop a service or install anything. A staged ZIP is not an authorization bypass: installation verifies it again under the current policy.

TASK-015 adds `prepare`, with the same flags plus `--output ABSOLUTE_NEW_DIRECTORY`, for fresh pilot installation. It uses the authenticated private copy and the existing bounded ZIP extractor, accepts only the expected Core/Agent executable layout and rejects known persistent state and installed-receipt aliases. The parent must already be operator-controlled; existing destinations and links are refused. It leaves only the prepared code tree and performs no service operation or health assertion. The [pilot installer](PILOT.md) provisions Windows ACLs and uses this command before installation. Its bootstrap scripts/verifier must themselves come from a trusted source; a manifest-provided/publicly delivered key is not automatic trust.

## Installation and rollback API

`TransactionalUpdater.InstallAsync` takes the raw signed manifest, local ZIP path, explicit verification policy, existing absolute code-only installation directory, and an `IServiceUpdateLifecycle` adapter. Initial supported artifacts are `sentinelai-agent-win-x64` / `SentinelAI.Agent.exe` and `sentinelai-core-win-x64` / `SentinelAI.Core.exe`. There is no default adapter that assumes a service is healthy. The host must implement stopping, starting and checking the actual updated service, honor cancellation and bound service-control operations. Windows service wiring belongs to the later installer integration.

Persistent Core/Agent data and operator secrets/configuration must remain outside the installation code directory. Keep the service account stable so Windows DPAPI enrollment state remains usable. The default LocalApplicationData state directories already meet this layout. Existing code/state is not migrated by the updater.

Before stopping the service, the installer authenticates the manifest, verifies a private immutable package copy and validates/extracts the archive into a private sibling directory. ZIP limits are 1,024 entries and 512 MiB expanded bytes. Traversal, absolute paths, Windows ADS/device aliases, invalid filenames, duplicate/colliding paths, links/reparse points and missing expected executables are rejected. Known persistent SentinelAI state files are rejected in both the existing code tree and the package. Packages cannot supply an installed receipt. Update directories and their parent must be controlled by the updater/service operator; Unix installation parents writable by group/other accounts are rejected, and Windows requires operator-provisioned restricted ACLs. The mechanism is not protection against a privileged local owner replacing storage.

An exclusive installation lock and durable journal coordinate the transaction. The old code is moved to a backup; staged code replaces it at the same installation path. Only successful service start and health verification commit the signed receipt/version. Installation/start/health failure or cancellation restores the previous directory, restarts the previous service and verifies its health using an independent bounded recovery token.

If rollback itself fails, the result is `RollbackFailed`, and backup/work files plus the journal remain for retry; success is never reported. `RecoverAsync` authenticates pending journal metadata and restores incomplete transactions, including interruption between renames and journal writes. A committed healthy transaction can finish cleanup without undoing its successful update. The journal has fixed, derived sibling paths rather than caller-supplied destinations. Files and journal records are flushed before proceeding; this is process-interruption recovery, not a claim of filesystem durability through every power-loss/storage failure.

## Verification

`./scripts/build.sh` builds the library and both tools; `./scripts/test.sh` also runs `SentinelAI.Updates.Tests`. Tests use generated temporary development keys and synthetic packages, never production credentials. They cover signature/metadata/hash tampering, strict format/trust/channel/version checks, private staging, malformed archives, successful installation, failure/health/cancellation rollback and interruption recovery with scripted service lifecycles. Actual Windows service/ACL integration remains a deployment check; the foundation does not pretend a fake test lifecycle is a real service.
