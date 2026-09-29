# SentinelAI

SentinelAI is a Windows-first, local-first cybersecurity platform.

## Sources of truth

Product:
docs/PRODUCT.md

Architecture:
docs/ARCHITECTURE.md

Security:
docs/SECURITY.md

MVP:
docs/MVP.md

Current development state:
.agent/STATUS.md

Tasks:
.agent/tasks/

## Workflow

For every task:

1. Read .agent/STATUS.md.
2. Read only the assigned task.
3. Search for relevant source code before opening large files.
4. Read only documentation relevant to the task.
5. Implement the smallest complete solution.
6. Add or update tests.
7. Run relevant builds and tests.
8. Inspect git diff.
9. Update .agent/STATUS.md.

Work autonomously for ordinary implementation decisions.

Ask the user only when:
- product requirements materially conflict,
- a security boundary must change,
- public contracts need a breaking change,
- a destructive migration is necessary,
- required credentials are unavailable.

Never:
- expose secrets,
- weaken security controls to pass tests,
- place private signing keys in the repository,
- use real customer telemetry in tests.
