TASK-015 — Pilot Installer

Objective

Create an installation workflow suitable for the first SentinelAI pilot deployment.

Components

Support installation of:

SentinelAI Core.

SentinelAI Endpoint Agent.

Requirements

Installer must provide a clear path for:

installing Core,

configuring local Core,

initial administrator setup,

configuring enrollment,

installing Agent,

enrolling Agent,

verifying heartbeat,

confirming device visibility in dashboard.

Windows Requirements

Agent must install correctly as a Windows Service.

Uninstallation should cleanly remove the service without deleting data unexpectedly.

Security

no embedded production credentials.

no private signing keys.

clear privilege elevation.

validate installation paths and configuration.

logs must not contain secrets.

Pilot Documentation

Create a concise pilot installation guide.

Definition of Done

A new supported Windows test environment can:

install Core,

start Core,

install Agent,

enroll Agent,

receive heartbeat,

report inventory,

display endpoint in dashboard.

Document all known limitations.

Update .agent/STATUS.md.

Development sequence

Tasks are intended to be completed in this order:

001 → 002 → 003 → 004 → 005 → 006 → 007 → 008 → 009 → 010 → 011 → 012 → 013 → 014 → 015

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
