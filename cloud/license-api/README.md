# Development License API

This separate .NET 10 server issues locally verifiable seven-day signed leases. Core and Agent do not reference the issuer, load its private key, or receive activation credentials. The server uses a static, startup-validated entitlement list for development and tests; billing, public production deployment, periodic renewal, storage of leases, and Safe Mode enforcement are outside TASK-010.

## Generate development material

From the repository root with the published .NET environment configured:

```sh
./scripts/generate-license-development-keys.sh
```

The default output is the ignored `artifacts/license-development-keys` directory. An optional first argument selects a **new** external directory, for example `/tmp/sentinelai-license-development`. Generation fails if the directory already exists; it never overwrites files. The generator writes:

| File | Purpose |
| --- | --- |
| `private.pem` | PKCS#8 ECDSA P-256 signing key; remains on this server only |
| `public.pem` | SPKI public verification key; distribute this to Core |
| `activation-credential.txt` | Random 256-bit activation credential, encoded as 43 base64url characters without padding |
| `activation-credential.sha256` | Hex SHA-256 of the exact credential UTF-8 bytes; configure this digest on the server |

Successful generation prints file paths only. On Unix the output directory is created with mode `0700` and files with mode `0600`. On Windows use a directory whose existing ACL restricts access to the development account. Keep the private key and activation credential out of source control, Core configuration, logs, process arguments, and shared artifacts. Automated tests generate temporary development keys; they never use production keys.

The executable also supports `--generate-development-keys <new-output-directory>` without starting a server or requiring entitlement configuration.

## Configure and start the server

Required configuration lives under `SentinelAI:LicenseApi`. No key or grant is shipped in configuration. The server refuses startup for missing/invalid settings, unknown fields, duplicate organization/installation pairs, invalid entitlement claims, or a private key that is not PKCS#8 P-256.

| Setting | Value |
| --- | --- |
| `KeyId` | ASCII letters, digits, `_`, or `-`; 1–64 characters; must match a public key ID trusted by Core |
| `SigningPrivateKeyPath` | Absolute path to the server-only generated `private.pem` |
| `Entitlements:<index>:OrganizationId` | Nonempty organization GUID |
| `Entitlements:<index>:InstallationId` | Nonempty installation GUID; binds the grant to this Core installation |
| `Entitlements:<index>:ActivationCredentialSha256` | 64 hexadecimal characters from the credential digest file |
| `Entitlements:<index>:Plan` | ASCII label, 1–64 characters |
| `Entitlements:<index>:EndpointLimit` | Integer from 1 to 1,000,000 |
| `Entitlements:<index>:EnabledFeatures:<index>` | Optional list of at most 64 distinct ASCII labels, each 1–64 characters |

For a synthetic local grant, load the digest from its protected file and supply the nonsecret settings through environment variables:

```sh
export SentinelAI__LicenseApi__KeyId=development
export SentinelAI__LicenseApi__SigningPrivateKeyPath="$PWD/artifacts/license-development-keys/private.pem"
export SentinelAI__LicenseApi__Entitlements__0__OrganizationId=00000000-0000-0000-0000-000000000001
export SentinelAI__LicenseApi__Entitlements__0__InstallationId=00000000-0000-0000-0000-000000000002
export SentinelAI__LicenseApi__Entitlements__0__ActivationCredentialSha256="$(cat artifacts/license-development-keys/activation-credential.sha256)"
export SentinelAI__LicenseApi__Entitlements__0__Plan=development
export SentinelAI__LicenseApi__Entitlements__0__EndpointLimit=25
export SentinelAI__LicenseApi__Entitlements__0__EnabledFeatures__0=api
dotnet run --project cloud/license-api/SentinelAI.LicenseApi.csproj --configuration Release --no-launch-profile
```

The default address is `http://127.0.0.1:5100`. Standard ASP.NET Core URL/Kestrel certificate configuration may enable HTTPS. Every request over remote plaintext HTTP is rejected with `403`; local loopback HTTP supports isolated development. There is no forwarded-header trust configuration: TLS must terminate at this host for remote access. All responses use `Cache-Control: no-store`. Issuance has a 4 KiB request-body limit and a limit of 30 requests per minute per remote IP, with no queue.

## Issue a lease

`POST /api/licenses/lease` accepts only `application/json` with exactly these two fields:

```json
{"organizationId":"00000000-0000-0000-0000-000000000001","installationId":"00000000-0000-0000-0000-000000000002"}
```

Send `Authorization: Bearer <activation-credential>` using the protected credential file. The credential is independent of Core administrator and Agent bearer credentials. Unknown/mismatched identities or credentials return `401`. Malformed, duplicate, or additional JSON fields return `400`; a client cannot submit its own plan, endpoint limit, features, or lease duration. Valid claims come solely from the matching configured entitlement.

For example, this local Python request reads the credential without placing it in command arguments or printing it:

```sh
python3 - <<'PY'
import json
from pathlib import Path
from urllib.request import Request, urlopen

credential = Path('artifacts/license-development-keys/activation-credential.txt').read_text()
body = json.dumps({
    'organizationId': '00000000-0000-0000-0000-000000000001',
    'installationId': '00000000-0000-0000-0000-000000000002'
}).encode()
request = Request('http://127.0.0.1:5100/api/licenses/lease', data=body, headers={
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + credential
})
with urlopen(request) as response:
    Path('artifacts/development-lease.json').write_bytes(response.read())
PY
```

The successful response is `{"lease":"<signed compact token>"}`. The token uses ES256 (ECDSA P-256 with SHA-256 and a fixed 64-byte IEEE P1363 signature), an explicit `kid`, and strict shared lease claims. Issue time is the server UTC clock; `full_mode_until` is exactly seven days later. There is no client-controlled lifetime or unsigned entitlement fallback. The shared verifier enforces the configured organization/installation identity and exposes expired status locally; verification does not contact this server.

## Public keys and rotation

Distribute only `public.pem` to Core and associate it with the issuer's `KeyId` in Core's public verification-key configuration. Before switching to a new key ID, add its public key to Core's trusted set while retaining the previous public key for the old lease lifetime. Switch the cloud private key and `KeyId` together, then remove the old Core public key after its leases have expired. A key ID must refer to one key; do not silently replace its material. No rotation management endpoint, private-key export API, or automatic trust discovery is introduced.
