TASK-003 — Endpoint Agent Heartbeat

Objective

Implement the first end-to-end communication flow between SentinelAI Endpoint Agent and SentinelAI Core.

Agent Requirements

Create a Windows Service capable of:

starting without interactive UI,

reading configuration,

identifying its installation,

periodically sending heartbeat messages to Core,

retrying after temporary communication failure,

remaining operational when Core is unavailable.

Core Requirements

Implement:

heartbeat endpoint,

device record,

last_seen timestamp,

basic health status,

persistence in SQLite.

Shared Contracts

Define explicit request/response contracts in shared/contracts/.

Avoid duplicating transport models between Agent and Core.

Out of Scope

Do not implement:

secure enrollment,

inventory collection,

telemetry,

security rules,

licensing.

Definition of Done

Agent project can run as a Windows Service.

Agent sends heartbeat to Core.

Core persists endpoint state.

last_seen updates correctly.

temporary Core outage does not crash Agent.

automatic retry works.

tests cover heartbeat behavior.

.agent/STATUS.md is updated.
