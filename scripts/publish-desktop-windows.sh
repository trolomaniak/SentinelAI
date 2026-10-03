#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/artifacts/desktop/win-x64"

# WPF uses an ordinary publish directory so its native and managed runtime
# dependencies remain available beside the executable. This is not an installer.
dotnet publish "$repo_root/desktop/SentinelAI.Desktop/SentinelAI.Desktop.csproj" \
  --configuration Release \
  --runtime win-x64 \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:PublishTrimmed=false \
  -p:DebugType=none \
  -p:DebugSymbols=false \
  --output "$output_dir"

for required_file in SentinelAI.Desktop.exe SentinelAI.Desktop.dll \
  SentinelAI.Desktop.deps.json SentinelAI.Desktop.runtimeconfig.json \
  PresentationFramework.dll coreclr.dll; do
  if [[ ! -f "$output_dir/$required_file" ]]; then
    printf 'Desktop publish is missing %s\n' "$required_file" >&2
    exit 1
  fi
done

printf 'Published Windows x64 desktop directory: %s\n' "$output_dir"
