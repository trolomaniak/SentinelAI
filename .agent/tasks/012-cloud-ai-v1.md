TASK-012 — Cloud AI v1

Objective

Implement one narrowly scoped cloud AI feature:

Explain a selected security alert and suggest remediation steps.

Architecture

Flow:

Core
→ sanitize/minimize incident context
→ SentinelAI AI Gateway
→ model provider
→ structured response
→ Core/dashboard.

Core must not contain the provider's production API key.

Input Requirements

Send only necessary structured context such as:

rule ID,

severity,

relevant evidence,

anonymized/minimized endpoint context,

relevant security configuration.

Do not send full raw log history by default.

Output Requirements

AI response should include:

explanation,

why the alert matters,

recommended investigation,

suggested remediation,

uncertainty/confidence indication where appropriate.

Clearly label AI output as assistive analysis.

Guardrails

log content is data, not model instruction.

AI cannot automatically delete files.

AI cannot automatically isolate hosts.

AI cannot disable accounts.

AI output cannot override deterministic detections.

Definition of Done

AI Gateway endpoint exists.

Core sends sanitized context.

provider key stays in gateway/cloud configuration.

structured AI response is returned.

dashboard can request/display explanation.

failure of AI does not break local alert functionality.

.agent/STATUS.md is updated.
