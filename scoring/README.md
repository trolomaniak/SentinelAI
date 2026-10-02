# Deterministic risk scoring v1

`RiskScorer` has no clock, database, telemetry collection, network or AI dependency. Core supplies the evaluation time, one tracked alert per endpoint/rule, the latest inventory timestamp, and the declared endpoint context. The calculation is a prioritization policy over tracked findings. A zero score does not establish effective protection or telemetry completeness.

## Formula

For each alert:

```text
beforeMitigation = severityPoints × confidence × assetMultiplier × exposureMultiplier × ageMultiplier
contribution = beforeMitigation × remainingRisk
mitigationReduction = beforeMitigation − contribution

baseCorrelationBonus = min(max(distinctEligibleGroups − 1, 0) × pointsPerExtraGroup, maximumBaseBonus)
correlationBonus = baseCorrelationBonus × assetMultiplier × exposureMultiplier
rawEndpointScore = sum(contribution) + correlationBonus
endpointScore = roundAwayFromZero(clamp(rawEndpointScore, 0, 100))
organizationScore = maximum(endpointScore); empty organization = 0
```

Arithmetic uses decimals and rounds only the final endpoint score. Raw points and saturation remain visible, including positive raw values below 0.5 that display as zero. Zero can also reflect resolved or deliberately discounted findings and missing observations; it is not proof of endpoint safety. Organization scoring uses the maximum so healthy or unobserved endpoints cannot dilute an endpoint with critical findings. The API returns one stable representative of the highest-score endpoints, their total count, and whether the IDs were truncated.

## Central policy defaults

These are explicit v1 policy choices, not fitted probabilities or guarantees. `ScoringPolicy` can be supplied at construction, and the scorer copies it into an immutable validated `Policy` snapshot. Core exposes that snapshot and can bind overrides from `SentinelAI:RiskScoring:Policy`.

| Factor | Default |
| --- | --- |
| Severity points | info 1; low 5; medium 15; high 25; critical 50 |
| Detection confidence weight | 1; optional per-rule overrides from 0 to 1 |
| Asset criticality | low 0.75; standard 1; high 1.5; critical 2 |
| Exposure | isolated 0.75; internal 1; internet 1.5; unknown 1 |
| Fresh observation age | at most 7 days: 1 |
| Aging observation age | more than 7, at most 30 days: 0.75 |
| Old observation age | more than 30 days: 0.5 |
| Remaining risk | open, investigating, accepted: 1; resolved: 0 |
| Correlation | 5 points per extra distinct eligible group; base bonus capped at 20 |
| Endpoint score scale | fixed 0–100 |

The default confidence of 1 means the configured weight for an explicit reported configuration finding. It is not statistical confidence that runtime protection is ineffective. Per-rule confidence overrides are identified in each contribution; a deliberate zero override contributes no points and cannot earn correlation points.

The context defaults to asset `standard` and exposure `unknown`, each labeled `policyDefault`. Operator declarations are labeled `userDeclared` independently for asset and exposure. Registry settings, hostname, RDP enablement and firewall posture do not establish Internet exposure or asset importance. Configuration does not execute remediation.

Open, Investigating and Accepted are all risk-bearing. Acceptance is acknowledgement of a finding, not evidence of remediation. Resolved contributes zero, and a later positive observation can reopen the persisted alert through Core's existing lifecycle. This status mapping is fixed and validated; overrides contradicting it fail startup. Age never closes or erases a tracked finding. Time since the last positive observation, rather than first observation, determines age; future clock skew clamps age to zero and is flagged.

## Correlation

Correlation requires positive weighted contribution, an unresolved alert, observation age within the fresh window, and exact equality between its last-positive timestamp and the latest inventory timestamp. Historical positives that were not reconfirmed by that snapshot remain individually scored but cannot correlate. A missing snapshot disables correlation. The known rules map to seven groups: FW, UAC, RDP, SMB, LOGON, LSA and UPDATE. Multiple firewall profiles or RDP settings are one group each. Unknown rule IDs receive no group unless policy explicitly maps them.

The **base** cap applies before asset/exposure. With critical asset (2) and declared Internet exposure (1.5), a capped base bonus of 20 becomes 60 final points. Both values are exposed; the overall endpoint still caps at 100. This models correlated posture observations, not evidence of an attack sequence.

## Examples

- One fresh High/Open finding with default context: `25 × 1 × 1 × 1 × 1 × 1 = 25`.
- Two fresh Medium/Open findings in distinct groups confirmed by the latest snapshot: `15 + 15 + 5 = 35`.
- The same two findings in one group: `15 + 15 = 30`.
- A High finding with confidence 0.5, critical asset, Internet exposure and age 10 days: `25 × 0.5 × 2 × 1.5 × 0.75 = 28.125`, displayed score 28.
- Resolving that finding reduces its contribution to 0. Accepting it preserves 28.125.
- A fresh Critical finding on a critical Internet-exposed asset: raw 150, score 100, `saturated=true`.

## Validation and limits

Severity weights are positive, nondecreasing by severity and at most 100. Asset and exposure multipliers are positive and at most 10, ordered by criticality and from isolated to internal to Internet. Unknown exposure remains its explicitly configured label, not an inferred trust category. Default confidence is positive and at most 1; per-rule confidence is 0–1. Age thresholds satisfy `1 <= freshDays < agingDays <= 3650`; age weights satisfy `1 >= aging >= old > 0`. Correlation rate and base cap are 0–100. All expected severity/context/status keys must exist; unexpected keys and unknown input labels are rejected. The score scale is always 100. These bounds limit invalid configuration and keep policy review explicit.

One endpoint cannot be scored twice in an organization input, and an endpoint cannot contain duplicate alert IDs or rule IDs. Contributions and representative endpoints have stable ordering. Each contribution exposes its factor values, age and clock-skew flag, points before mitigation, mitigation reduction, current-snapshot confirmation, group and correlation eligibility. Core separately explains inventory coverage and freshness; this library does not infer missing telemetry or unimplemented posture signals.
