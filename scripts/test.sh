#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet restore "$repo_root/SentinelAI.sln"
dotnet build "$repo_root/SentinelAI.sln" --configuration Release --no-restore

dotnet run --project "$repo_root/tests/SentinelAI.Agent.Tests/SentinelAI.Agent.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Core.Tests/SentinelAI.Core.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Rules.Tests/SentinelAI.Rules.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Scoring.Tests/SentinelAI.Scoring.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Licensing.Tests/SentinelAI.Licensing.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.LicenseApi.Tests/SentinelAI.LicenseApi.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Ai.Tests/SentinelAI.Ai.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Updates.Tests/SentinelAI.Updates.Tests.csproj" --configuration Release --no-build --no-restore

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoLogo -NoProfile -NonInteractive -File "$repo_root/tests/pilot/Workflow.Tests.ps1"
else
  printf 'PowerShell pilot workflow tests require pwsh; Windows acceptance remains a separate explicit check.\n' >&2
fi

cd "$repo_root/dashboard"
npm test
