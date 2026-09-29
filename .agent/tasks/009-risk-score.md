TASK-009 — Risk Scoring

Objective

Implement deterministic risk scoring for endpoints and the organization.

Requirements

Risk scoring must consider concepts from the product specification:

severity,

detection confidence,

asset criticality,

exposure,

correlated signals,

mitigation/remediation state,

alert age where appropriate.

The calculation must be explainable.

The UI must not show only a number; it must expose the factors contributing to the score.

Constraints

AI must not determine the final score.

Avoid unexplained magic constants.

Scoring rules should be configurable or centralized.

Definition of Done

endpoint risk score exists.

organization-level score exists.

score updates when relevant alert state changes.

contributing factors are available through API.

dashboard displays score and explanation.

scoring tests cover boundary cases.

.agent/STATUS.md is updated.
