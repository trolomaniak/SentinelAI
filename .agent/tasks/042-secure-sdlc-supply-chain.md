TASK-042 — Secure SDLC and Software Supply Chain

Objective

Establish release-grade secure development and software supply-chain controls for SentinelAI.

Requirements

Add or document:

- threat model,
- security architecture review checklist,
- SBOM generation for releases,
- dependency vulnerability scanning,
- secret scanning,
- static analysis,
- selected fuzz/property testing for critical parsers and security boundaries,
- reproducible/provenance-aware release metadata where practical,
- code-signing/release-signing process,
- vulnerability disclosure process,
- dependency/update response procedure.

Standards

Use applicable secure-development guidance such as NIST SSDF as a baseline, while documenting what is implemented and what remains organizational/process work.

Constraints

Do not claim certification from automated tooling.

Definition of Done

- Release produces an SBOM.
- CI/release checks include selected security gates.
- Threat model covers Desktop, Core, Agent, Setup/Updater, License API and AI Gateway.
- Secret scanning and dependency scanning are enforced.
- Vulnerability disclosure/response documentation exists.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
