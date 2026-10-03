TASK-044 — Compliance, Standards and Legal Release Gate

Objective

Perform a formal standards, regulatory and product-security gap assessment before production release.

Scope

Assess applicability and implementation evidence for relevant areas including:

- ISO/IEC 27001/27002 controls relevant to the organization/product environment,
- ISO/IEC 27005 risk-management concepts,
- ISO/IEC 27035 incident-management concepts,
- ISO/IEC 29147 vulnerability disclosure,
- ISO/IEC 30111 vulnerability handling,
- secure-development guidance such as NIST SSDF,
- OWASP guidance applicable to APIs/desktop/software supply chain,
- EU Cyber Resilience Act,
- GDPR/RODO security and data-protection obligations,
- NIS2 / Polish KSC applicability to SentinelAI and target customers,
- EU AI Act applicability to the assistive AI feature.

Requirements

Distinguish:

- product technical control,
- organization/process requirement,
- customer responsibility,
- not applicable,
- future/legal review required.

Create a traceable compliance matrix with evidence references.

Legal

This task must identify areas requiring qualified legal or certification review; it must not claim formal legal advice or ISO certification merely from code review.

Definition of Done

- Compliance/gap matrix exists.
- Every applicable requirement has evidence, remediation, owner or documented gap.
- Privacy/data-flow review is complete.
- No unresolved Critical/High security release blockers remain.
- Release claims are accurate and do not overstate certification/compliance.
- `.agent/STATUS.md` is updated.

Development sequence

Tasks are intended to be completed in this order:

016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 → 025 → 026 → 027 → 028 → 029 → 030 → 031 → 032 → 033 → 034 → 035 → 036 → 037 → 038 → 039 → 040 → 041 → 042 → 043 → 044 → 045

Do not begin the next task until the current task satisfies its Definition of Done unless parallel work has been explicitly approved.

Each task should normally result in one scoped branch and one Pull Request.
