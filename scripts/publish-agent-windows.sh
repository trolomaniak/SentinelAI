#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/artifacts/agent/win-x64"

dotnet publish "$repo_root/agent/SentinelAI.Agent.csproj" \
  --configuration Release \
  --runtime win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:DebugType=none \
  -p:DebugSymbols=false \
  --output "$output_dir"

shopt -s nullglob
files=("$output_dir"/*)
if [[ ${#files[@]} -ne 1 || "${files[0]}" != "$output_dir/SentinelAI.Agent.exe" || ! -f "${files[0]}" ]]; then
  printf 'Expected only SentinelAI.Agent.exe in %s\n' "$output_dir" >&2
  exit 1
fi

printf 'Published %s\n' "${files[0]}"
