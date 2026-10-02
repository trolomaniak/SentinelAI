#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet restore "$repo_root/SentinelAI.sln"
dotnet build "$repo_root/SentinelAI.sln" --configuration Release --no-restore

dotnet run --project "$repo_root/tests/SentinelAI.Agent.Tests/SentinelAI.Agent.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Core.Tests/SentinelAI.Core.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Rules.Tests/SentinelAI.Rules.Tests.csproj" --configuration Release --no-build --no-restore
dotnet run --project "$repo_root/tests/SentinelAI.Scoring.Tests/SentinelAI.Scoring.Tests.csproj" --configuration Release --no-build --no-restore

cd "$repo_root/dashboard"
npm test
