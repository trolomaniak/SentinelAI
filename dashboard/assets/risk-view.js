import { formatTimestamp, routeFromHash } from "./device-view.js";
import { alertStatusPresentation, severityPresentation } from "./alert-view.js";

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

export function formatRiskNumber(value) {
  return Number.isFinite(value)
    ? new Intl.NumberFormat(undefined, { maximumFractionDigits: 4 }).format(value)
    : "Unknown";
}

function multiplier(value) { return `× ${formatRiskNumber(value)}`; }

function facts(items) {
  const grid = node("dl", "fact-grid");
  for (const [label, value] of items) {
    const item = node("div");
    const definition = node("dd");
    definition.append(value instanceof Node ? value : document.createTextNode(String(value)));
    item.append(node("dt", null, label), definition);
    grid.append(item);
  }
  return grid;
}

function panel(title, ...content) {
  const section = node("section", "panel detail-panel");
  section.append(node("h2", null, title), ...content);
  return section;
}

function time(value, missing = "Not observed") {
  const formatted = formatTimestamp(value, missing);
  if (!value || formatted === "Unknown") return node("span", "muted", formatted);
  const element = node("time", null, formatted);
  element.dateTime = value;
  return element;
}

export function riskListPath(offset, limit = 50) {
  return `/api/admin/risk?${new URLSearchParams({ offset: String(offset), limit: String(limit) })}`;
}

export function riskLink(endpointId, label = "View risk factors") {
  if (routeFromHash(`#/risk/${endpointId}`).kind !== "risk-detail") return node("span", "muted", "Endpoint risk unavailable");
  const link = node("a", "risk-link", label);
  link.href = `#/risk/${endpointId}`;
  return link;
}

function sourceLabel(source) {
  if (source === "policyDefault") return "Assumed policy default";
  if (source === "userDeclared") return "Operator declared";
  if (source === "rulePolicyOverride") return "Configured rule policy override";
  return source || "Source unknown";
}

function contextValue(value, weight, source) {
  return `${value || "Unknown"} · ${multiplier(weight)} · ${sourceLabel(source)}`;
}

const scoreMeaning = "Higher scores prioritize recorded risks. A zero rounded score can still include small contributions, policy discounts, or missing observations; it does not establish that the endpoint is secure. Review raw points and coverage. Unknown or stale telemetry can conceal risks.";
const confidenceMeaning = "Detection confidence is a configured evidence weight, not a statistical probability. Asset criticality and exposure are operator declarations or explicit policy assumptions; exposure is not inferred from firewall or RDP settings.";
const stateMeaning = "Investigating and Accepted do not reduce remaining risk. Resolved contributes zero under the current policy and can reopen after a newer matching observation. No status change performs remediation on the endpoint.";

function scoreFacts(score, rawScore, saturated) {
  return facts([
    ["Risk score", `${formatRiskNumber(score)} / 100`],
    ["Raw points before score cap", formatRiskNumber(rawScore)],
    ["Score cap", saturated === true ? "Capped at 100" : "Maximum 100"],
    ["Rounding", "Nearest integer; halves away from zero"],
  ]);
}

function coverageText(coverage) {
  if (!coverage) return "Unknown coverage";
  return `Inventory: ${coverage.inventoryState || "unknown"}; signals: ${coverage.signalCoverage || "unknown"}; ${formatRiskNumber(coverage.knownRuleSignals)} of ${formatRiskNumber(coverage.totalRuleSignals)} known`;
}

function policyPanel(policy, inventoryFreshForHours) {
  if (!policy) return panel("Scoring policy unavailable", node("p", "helper-text", "Core did not return the active scoring policy."));
  return panel("Active scoring policy", facts([
    ["Version", policy.version || "Unknown"],
    ["Inventory refresh expectation", `Within ${formatRiskNumber(inventoryFreshForHours)} hours`],
    ["Full age weight and correlation window", `Up to ${formatRiskNumber(policy.freshForDays)} days · × 1`],
    ["Aging observations", `Over ${formatRiskNumber(policy.freshForDays)} through ${formatRiskNumber(policy.agingForDays)} days · ${multiplier(policy.agingMultiplier)}`],
    ["Old observations", `Over ${formatRiskNumber(policy.agingForDays)} days · ${multiplier(policy.oldMultiplier)}`],
    ["Correlation per extra distinct group", `${formatRiskNumber(policy.correlationPointsPerExtraGroup)} base points`],
    ["Correlation base cap", `${formatRiskNumber(policy.maximumCorrelationBaseBonus)} points before asset and exposure multipliers`],
    ["Final score cap", formatRiskNumber(policy.maximumScore)],
  ]), node("p", "helper-text", "Age weights reduce prioritization of older observations; they do not prove that a recorded risky setting was remediated. The remaining unresolved contribution does not disappear with age."));
}

export function renderRiskOverview(page) {
  const container = node("div", "risk-layout");
  const organization = page.organization;
  const summary = panel("Organization risk", facts([
    ["Risk score", `${formatRiskNumber(organization.score)} / 100`],
    ["Aggregation", organization.method === "maximumEndpointScore" ? "Highest endpoint score" : organization.method || "Unknown"],
    ["Enrolled endpoints", String(organization.endpointCount ?? page.total)],
    ["Evaluated", time(organization.evaluatedUtc, "Unknown")],
    ["Endpoints with observed inventory", String(organization.observedEndpointCount ?? "Unknown")],
    ["Missing inventory", String(organization.missingInventoryCount ?? "Unknown")],
    ["Endpoints with unknown signals", String(organization.unknownSignalCount ?? "Unknown")],
    ["Endpoints with partial signals", String(organization.partialSignalCount ?? "Unknown")],
    ["Stale inventory", String(organization.staleInventoryCount ?? "Unknown")],
  ]), node("p", "risk-explanation", organization.explanation || "The organization score reflects the highest endpoint score."));
  summary.append(node("p", "helper-text", "Using the highest endpoint score prevents many low-scoring endpoints from hiding one urgent endpoint. Enrollment alone does not provide coverage."));
  if (organization.highestRiskEndpointIds?.length) {
    summary.append(riskLink(organization.highestRiskEndpointIds[0], "Review a highest-scoring endpoint"),
      node("p", "helper-text", `${organization.highestRiskEndpointCount ?? organization.highestRiskEndpointIds.length} endpoints share the highest score.`));
  }
  container.append(summary);

  if (!page.endpoints.length) {
    container.append(panel("No endpoints on this page", node("p", null, page.total === 0
      ? "Enroll an Agent to start receiving observations. An empty workspace provides no security assessment."
      : "Return to an earlier page to review enrolled endpoints.")));
  } else {
    const wrapper = node("div", "panel table-wrap");
    const table = node("table", "device-table risk-table");
    const header = node("thead");
    const headerRow = node("tr");
    for (const title of ["Endpoint", "Risk score", "Coverage", "Unresolved alerts", "Highest contribution", "Inventory observed"]) {
      const cell = node("th", null, title);
      cell.scope = "col";
      headerRow.append(cell);
    }
    header.append(headerRow);
    const body = node("tbody");
    for (const endpoint of page.endpoints) {
      const row = node("tr");
      const name = node("td");
      name.append(riskLink(endpoint.endpointId, endpoint.endpointName || "Unnamed endpoint"));
      const score = node("td");
      score.append(node("strong", "risk-number", `${formatRiskNumber(endpoint.score)} / 100`), node("span", "rule-id", `Raw ${formatRiskNumber(endpoint.rawScore)} points`));
      const coverage = node("td", "secondary-cell", coverageText(endpoint.coverage));
      if (endpoint.coverage?.caution) coverage.append(node("span", "rule-id", endpoint.coverage.caution));
      const observed = node("td", "secondary-cell");
      observed.append(time(endpoint.inventoryCollectedUtc));
      row.append(name, score, coverage, node("td", null, String(endpoint.unresolvedAlertCount ?? "Unknown")),
        node("td", "risk-reason", endpoint.highestContributorReason || "No contributing reason was returned; review raw points and coverage."), observed);
      body.append(row);
    }
    table.append(node("caption", "visually-hidden", "Enrolled endpoints ranked by deterministic risk with observation coverage and contributing reasons"), header, body);
    wrapper.append(table);
    container.append(wrapper);
  }
  container.append(panel("How to interpret the score", node("p", null, scoreMeaning), node("p", null, confidenceMeaning), node("p", null, stateMeaning)), policyPanel(page.policy, page.inventoryFreshForHours));
  return container;
}

function factorCard(factor, alerts) {
  const alert = alerts.find((item) => item.alertId === factor.alertId);
  const card = panel(alert?.title || factor.ruleId || "Tracked finding");
  const link = node("a", "risk-link", "Review alert and evidence");
  if (routeFromHash(`#/alerts/${factor.alertId}`).kind === "alert-detail") {
    link.href = `#/alerts/${factor.alertId}`;
    card.append(link);
  }
  card.append(facts([
    ["Rule", factor.ruleId || "Unknown"],
    ["Contribution", `${formatRiskNumber(factor.contribution)} points`],
    ["Severity", `${severityPresentation(factor.severity).label} · ${formatRiskNumber(factor.severityPoints)} points`],
    ["Detection confidence weight", `${multiplier(factor.detectionConfidence)} · ${sourceLabel(factor.confidenceSource)}`],
    ["Asset criticality multiplier", multiplier(factor.assetCriticalityMultiplier)],
    ["Exposure multiplier", multiplier(factor.exposureMultiplier)],
    ["Age", `${formatRiskNumber(factor.ageDays)} days · ${factor.ageBand || "Unknown"} · ${multiplier(factor.ageMultiplier)}`],
    ["Last matching observation", time(factor.lastObservedUtc)],
    ["Review status", alertStatusPresentation(factor.status).label],
    ["Remaining risk multiplier", multiplier(factor.remainingRiskMultiplier)],
    ["Points before mitigation", formatRiskNumber(factor.pointsBeforeMitigation)],
    ["Mitigation reduction", `${formatRiskNumber(factor.mitigationReduction)} points`],
    ["Correlation group", factor.correlationGroup || "No configured group"],
    ["Latest snapshot confirms finding", factor.latestSnapshotConfirmed === true ? "Yes" : "No"],
    ["Eligible for correlation", factor.correlationEligible === true ? "Yes" : "No"],
  ]));
  if (factor.futureTimestampClamped) card.append(node("p", "helper-text", "The observation timestamp is in the future; age is clamped to zero, not treated as a newer proof of protection."));
  card.append(node("p", "risk-formula", `${formatRiskNumber(factor.severityPoints)} × ${formatRiskNumber(factor.detectionConfidence)} × ${formatRiskNumber(factor.assetCriticalityMultiplier)} × ${formatRiskNumber(factor.exposureMultiplier)} × ${formatRiskNumber(factor.ageMultiplier)} − ${formatRiskNumber(factor.mitigationReduction)} = ${formatRiskNumber(factor.contribution)} points`));
  return card;
}

export function renderEndpointRisk(detail) {
  const risk = detail.risk;
  const context = risk.context || {};
  const container = node("div", "risk-layout");
  const heading = node("h1", null, `${detail.endpointName || "Unnamed endpoint"} risk`);
  heading.id = "risk-detail-heading";
  container.append(heading, node("p", "lead", risk.explanation || "The score is calculated from tracked alert contributions and correlation."));
  const deviceLink = node("a", "risk-link", "View endpoint inventory");
  if (routeFromHash(`#/devices/${detail.endpointId}`).kind === "detail") {
    deviceLink.href = `#/devices/${detail.endpointId}`;
    container.append(deviceLink);
  }
  const summary = panel("Endpoint score", scoreFacts(risk.score, risk.rawScore, risk.saturated), facts([
    ["Evaluated", time(risk.calculatedUtc, "Unknown")],
    ["Inventory observed", time(detail.inventoryCollectedUtc)],
    ["Coverage", coverageText(detail.coverage)],
  ]), node("p", "helper-text", detail.coverage?.caution || "Observation coverage is unknown."), node("p", "helper-text", scoreMeaning));
  const contextPanel = panel("Context and assumptions", facts([
    ["Asset criticality", contextValue(context.assetCriticality, risk.assetCriticalityMultiplier, context.assetCriticalitySource)],
    ["Exposure", contextValue(context.exposure, risk.exposureMultiplier, context.exposureSource)],
  ]), node("p", "helper-text", confidenceMeaning));
  const summaryGrid = node("div", "detail-grid");
  summaryGrid.append(summary, contextPanel);
  container.append(summaryGrid);
  const correlation = panel("Correlation", facts([
    ["Contributing distinct groups", risk.correlatedGroups?.length ? risk.correlatedGroups.join(", ") : "None"],
    ["Base bonus", `${formatRiskNumber(risk.correlationBaseBonus)} points`],
    ["Applied bonus", `${formatRiskNumber(risk.correlationBonus)} points after asset and exposure weighting`],
  ]), node("p", "helper-text", "Correlation combines distinct configured rule groups confirmed by the latest inventory, with matching observations inside the policy correlation window. Repeated settings from one group do not count as independent signals. Resolved, unconfirmed, ungrouped, or observations outside that window do not increase this bonus. This window is separate from the shorter inventory refresh expectation and does not establish live protection."));
  container.append(correlation);
  const factors = Array.isArray(risk.contributions) ? risk.contributions : [];
  container.append(node("h2", "risk-factors-heading", "Alert contributions"), node("p", "helper-text", stateMeaning));
  if (!factors.length) {
    container.append(panel("No tracked findings", node("p", null, "No tracked findings contribute to this score. Missing or unsupported observations remain unknown.")));
  } else {
    const cards = node("div", "detail-grid");
    for (const factor of factors) cards.append(factorCard(factor, detail.alerts || []));
    container.append(cards);
  }
  container.append(policyPanel(detail.policy, detail.inventoryFreshForHours));
  return container;
}
