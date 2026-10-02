#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output_directory="${1:-$repo_root/artifacts/license-development-keys}"

# A new directory is required. The program never overwrites a key or prints secret values.
dotnet run --project "$repo_root/cloud/license-api/SentinelAI.LicenseApi.csproj" \
  --configuration Release -- --generate-development-keys "$output_directory"
