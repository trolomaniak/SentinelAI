# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform. This repository currently contains the project scaffold; application features begin in later tasks.

The backend uses .NET 10 and contains the Agent, Core web host, and shared contracts projects. The dashboard is a dependency-free static shell built with Node.js 20 or newer.

From the repository root, run:

```sh
./scripts/build.sh
./scripts/test.sh
```

The build script restores and builds the .NET solution, then builds the dashboard. The test script runs the initial Agent and Core scaffold checks. The Core host intentionally has no API endpoints yet.
