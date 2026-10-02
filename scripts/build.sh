#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet restore "$repo_root/SentinelAI.sln"
dotnet build "$repo_root/SentinelAI.sln" --configuration Release --no-restore

cd "$repo_root/dashboard"
npm ci
node --check assets/app.js
node --check assets/device-view.js
node --check assets/alert-view.js
npm run build
