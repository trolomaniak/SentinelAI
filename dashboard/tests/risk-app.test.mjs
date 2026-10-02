import test from 'node:test';
import assert from 'node:assert/strict';
import { deferred, response, settle, startDashboard } from './dom-harness.mjs';
import { routeFromHash } from '../assets/device-view.js';

const endpointId = '2ecfd214-1aab-4393-9c69-091441eaad7b';
const alertId = '6c9bafbc-3616-4642-b61d-a3bc2e69cc64';
const observed = '2026-10-02T09:00:00Z';
const maliciousName = '<img src=x onerror="alert(1)"> Development workstation';
const policy = {
  version: 'risk-v1', freshForDays: 7, agingForDays: 30, agingMultiplier: 0.75,
  oldMultiplier: 0.5, correlationPointsPerExtraGroup: 5,
  maximumCorrelationBaseBonus: 20, maximumScore: 100,
};
const coverage = {
  inventoryState: 'current', signalCoverage: 'partial', knownRuleSignals: 3,
  totalRuleSignals: 13, caution: 'Only supported configuration signals are assessed; live protection is unknown.',
};
const factor = {
  alertId, ruleId: 'SA-FW-001', severity: 'high', status: 'open', lastObservedUtc: observed,
  ageDays: 1, ageBand: 'fresh', futureTimestampClamped: false,
  severityPoints: 25, detectionConfidence: 1, confidenceSource: 'policyDefault',
  assetCriticalityMultiplier: 1, exposureMultiplier: 1, ageMultiplier: 1,
  remainingRiskMultiplier: 1, pointsBeforeMitigation: 25, mitigationReduction: 0,
  contribution: 25, correlationGroup: 'FW', latestSnapshotConfirmed: true, correlationEligible: true,
};
const trackedAlert = {
  alertId, endpointId, endpointName: maliciousName, ruleId: 'SA-FW-001', title: 'Public firewall disabled',
  reason: 'An observed firewall configuration requires review.', severity: 'high', status: 'open',
  lastObservedUtc: observed, version: 1, evidence: [], statusHistory: [],
};
const detail = {
  endpointId, endpointName: maliciousName, inventoryCollectedUtc: observed, coverage,
  policy, inventoryFreshForHours: 12, alerts: [trackedAlert],
  risk: {
    endpointId, score: 25, rawScore: 25, saturated: false, calculatedUtc: observed,
    context: { assetCriticality: 'standard', exposure: 'unknown', latestInventoryUtc: observed,
      assetCriticalitySource: 'policyDefault', exposureSource: 'policyDefault' },
    assetCriticalityMultiplier: 1, exposureMultiplier: 1, contributions: [factor],
    correlatedGroups: ['FW'], correlationBaseBonus: 0, correlationBonus: 0,
    explanation: 'Sum of weighted tracked findings, plus correlation; capped at 100.',
  },
};
const summary = {
  endpointId, endpointName: maliciousName, inventoryCollectedUtc: observed,
  score: 25, rawScore: 25, coverage, unresolvedAlertCount: 1,
  highestContributorReason: trackedAlert.reason, evaluatedUtc: observed,
};
function page(overrides = {}) {
  return {
    organization: {
      score: 25, endpointCount: 2, highestRiskEndpointIds: [endpointId], highestRiskEndpointCount: 1,
      method: 'maximumEndpointScore', explanation: 'The organization score is the maximum enrolled endpoint score.',
      evaluatedUtc: observed, observedEndpointCount: 1, missingInventoryCount: 1,
      unknownSignalCount: 1, partialSignalCount: 1, staleInventoryCount: 0,
      alertStatusCounts: { open: 1, investigating: 0, accepted: 0, resolved: 0 },
    },
    endpoints: [summary], total: 2, offset: 0, limit: 50, policy, inventoryFreshForHours: 12,
    ...overrides,
  };
}
function authenticate(call) {
  return call.path === '/api/auth/login' ? response(200, { accessToken: 'development-test-token' }) : null;
}

test('risk routes accept only endpoint GUIDs and normalize IDs', () => {
  assert.deepEqual(routeFromHash('#/risk'), { kind: 'risk' });
  assert.deepEqual(routeFromHash(`#/risk/${endpointId.toUpperCase()}`), { kind: 'risk-detail', endpointId });
  assert.deepEqual(routeFromHash('#/risk/../api/auth/login'), { kind: 'invalid' });
});

test('organization risk exposes highest-endpoint aggregation, observation gaps, and per-endpoint reasons', async () => {
  const unobserved = { ...summary, endpointName: 'Unobserved endpoint', score: 0, rawScore: 0,
    inventoryCollectedUtc: null, unresolvedAlertCount: 0,
    highestContributorReason: 'No scored tracked findings; inventory is missing.',
    coverage: { inventoryState: 'missing', signalCoverage: 'unknown', knownRuleSignals: 0, totalRuleSignals: 13, caution: 'No inventory received.' } };
  const app = await startDashboard((call) => authenticate(call) ?? response(200, page({ endpoints: [summary, unobserved] })), '#/risk');
  try {
    await app.login();
    assert.equal(app.get('#risk-view').hidden, false);
    assert.equal(app.get('#risk-nav').getAttribute('aria-current'), 'page');
    const content = app.get('#risk-content');
    for (const text of ['Highest endpoint score', 'Missing inventory', 'Endpoints with unknown signals',
      'Endpoints with partial signals', trackedAlert.reason, 'Unobserved endpoint',
      'Inventory: missing; signals: unknown; 0 of 13 known', 'No inventory received.',
      'A zero rounded score', '7 days', '12 hours', 'risk-v1']) {
      assert.ok(content.textContent.includes(text), `overview displays ${text}`);
    }
    assert.ok(content.textContent.includes(maliciousName));
    assert.equal(content.querySelectorAll('img, script').length, 0);
    assert.equal(content.textContent.includes('[object Object]'), false);
    assert.ok(content.querySelectorAll('a').some((link) => link.href === `#/risk/${endpointId}`));
    const request = app.calls.at(-1);
    assert.equal(request.headers.Authorization, 'Bearer development-test-token');
    assert.equal(request.cache, 'no-store');
    assert.equal(request.credentials, 'omit');
  } finally { app.restore(); }
});

test('endpoint risk exposes assumptions, every contribution factor, policy caps, and alert evidence links', async () => {
  const enhanced = { ...detail, risk: { ...detail.risk, score: 100, rawScore: 150, saturated: true,
    assetCriticalityMultiplier: 2, exposureMultiplier: 1.5,
    context: { ...detail.risk.context, assetCriticality: 'critical', exposure: 'internet', assetCriticalitySource: 'userDeclared', exposureSource: 'userDeclared' },
    correlationBaseBonus: 20, correlationBonus: 60, correlatedGroups: ['FW', 'UAC'],
    contributions: [{ ...factor, confidenceSource: 'rulePolicyOverride', futureTimestampClamped: true }] } };
  const app = await startDashboard((call) => authenticate(call) ?? response(200, enhanced), `#/risk/${endpointId}`);
  try {
    await app.login();
    const content = app.get('#risk-detail-content');
    for (const text of ['Raw points before score cap', '150', 'Capped at 100', 'Nearest integer; halves away from zero',
      'critical · × 2 · Operator declared', 'internet · × 1.5 · Operator declared',
      'Detection confidence weight', 'Configured rule policy override', 'not a statistical probability',
      'Asset criticality multiplier', 'Exposure multiplier', 'Remaining risk multiplier',
      'Points before mitigation', 'Mitigation reduction', 'Latest snapshot confirms finding',
      'Eligible for correlation', 'Correlation base cap', '20 points before asset and exposure multipliers',
      '60 points after asset and exposure weighting', 'FW, UAC',
      'age is clamped to zero', 'Evaluated', 'Inventory observed', 'signals: partial; 3 of 13 known',
      'Investigating and Accepted do not reduce', 'does not establish live protection']) {
      assert.ok(content.textContent.includes(text), `detail displays ${text}`);
    }
    assert.equal(content.querySelectorAll('img, script').length, 0);
    assert.ok(content.querySelectorAll('a').some((link) => link.href === `#/alerts/${alertId}`));
    assert.ok(content.querySelectorAll('a').some((link) => link.href === `#/devices/${endpointId}`));
  } finally { app.restore(); }
});

test('default endpoint context is visibly assumed and does not infer Internet reachability', async () => {
  const lowWeightedRisk = { ...detail, risk: { ...detail.risk, score: 0, rawScore: 0.1,
    contributions: [{ ...factor, severity: 'info', severityPoints: 1, detectionConfidence: 0.1,
      confidenceSource: 'rulePolicyOverride', pointsBeforeMitigation: 0.1, contribution: 0.1 }] } };
  const app = await startDashboard((call) => authenticate(call) ?? response(200, lowWeightedRisk), `#/risk/${endpointId}`);
  try {
    await app.login();
    const text = app.get('#risk-detail-content').textContent;
    assert.ok(text.includes('standard · × 1 · Assumed policy default'));
    assert.ok(text.includes('unknown · × 1 · Assumed policy default'));
    assert.ok(text.includes('exposure is not inferred from firewall or RDP settings'));
    assert.ok(text.includes('0 / 100'));
    assert.ok(text.includes('0.1 points'));
    assert.ok(text.includes('A zero rounded score can still include small contributions'));
    assert.ok(text.includes('does not establish that the endpoint is secure'));
  } finally { app.restore(); }
});

test('risk navigation after an alert status change fetches the updated score without cached findings', async () => {
  let resolved = false;
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    if (call.path === `/api/admin/devices/${endpointId}/risk`) {
      return response(200, resolved ? { ...detail, risk: { ...detail.risk, score: 0, rawScore: 0,
        contributions: [{ ...factor, status: 'resolved', contribution: 0, remainingRiskMultiplier: 0, mitigationReduction: 25,
          correlationEligible: false }], correlatedGroups: [] } } : detail);
    }
    if (call.method === 'PUT') {
      resolved = true;
      return response(200, { ...trackedAlert, status: 'resolved', version: 2 });
    }
    return response(200, trackedAlert);
  }, `#/risk/${endpointId}`);
  try {
    await app.login();
    assert.ok(app.get('#risk-detail-content').textContent.includes('25 / 100'));
    await app.navigate(`#/alerts/${alertId}`);
    assert.ok(app.get('#alert-detail-content').querySelectorAll('a').some((link) => link.href === `#/risk/${endpointId}`));
    app.get('#alert-status-select').value = 'resolved';
    await app.get('#alert-status-select').trigger('change');
    await app.get('#alert-status-form').trigger('submit');
    await settle();
    await app.navigate(`#/risk/${endpointId}`);
    assert.ok(app.get('#risk-detail-content').textContent.includes('0 / 100'));
    assert.ok(app.get('#risk-detail-content').textContent.includes('Resolved'));
    assert.ok(app.get('#risk-detail-content').textContent.includes('does not establish that the endpoint is secure'));
    const riskRequests = app.calls.filter((call) => call.path === `/api/admin/devices/${endpointId}/risk`);
    assert.equal(riskRequests.length, 2);
    assert.equal(riskRequests.every((call) => call.cache === 'no-store'), true);
  } finally { app.restore(); }
});

test('risk pagination uses bounded server pages', async () => {
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    const offset = Number(new URL(call.path, 'http://127.0.0.1').searchParams.get('offset'));
    return response(200, page({ total: 51, offset, limit: 50 }));
  }, '#/risk');
  try {
    await app.login();
    assert.equal(app.get('#risk-previous').disabled, true);
    assert.equal(app.get('#risk-next').disabled, false);
    await app.get('#risk-next').trigger('click');
    await settle();
    assert.equal(app.calls.at(-1).path, '/api/admin/risk?offset=50&limit=50');
    assert.equal(app.get('#risk-previous').disabled, false);
    assert.equal(app.get('#risk-next').disabled, true);
    await app.get('#risk-previous').trigger('click');
    await settle();
    assert.equal(app.calls.at(-1).path, '/api/admin/risk?offset=0&limit=50');
  } finally { app.restore(); }
});

test('risk loading, empty workspace, and failures explain their state and allow retry', async () => {
  const loading = deferred();
  let loads = 0;
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    loads += 1;
    if (loads === 1) return loading.promise;
    if (loads === 2) return response(503, {});
    return response(200, page());
  }, '#/risk');
  try {
    await app.login();
    assert.match(app.get('#risk-status').textContent, /loading/i);
    assert.equal(app.get('#risk-next').disabled, true);
    loading.resolve(response(200, page({ endpoints: [], total: 0,
      organization: { ...page().organization, score: 0, endpointCount: 0, highestRiskEndpointIds: [] } })));
    await settle();
    assert.match(app.get('#risk-content').textContent, /empty workspace provides no security assessment/i);
    await app.get('#refresh-risk').trigger('click');
    await settle();
    assert.match(app.get('#risk-content').textContent, /unavailable/i);
    await app.get('#risk-content').querySelector('button').trigger('click');
    await settle();
    assert.ok(app.get('#risk-content').textContent.includes(trackedAlert.reason));
  } finally { app.restore(); }
});

test('risk detail 404 and session expiry provide an accurate recovery view', async () => {
  let loads = 0;
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    loads += 1;
    return response(loads === 1 ? 404 : 401, {});
  }, `#/risk/${endpointId}`);
  try {
    await app.login();
    assert.match(app.get('#risk-detail-content').textContent, /endpoint not found/i);
    await app.get('#refresh-risk-detail').trigger('click');
    await settle();
    assert.equal(app.get('#login-view').hidden, false);
    assert.equal(app.get('#risk-detail-view').hidden, true);
    assert.equal(app.get('#risk-detail-content').textContent, '');
    assert.equal(app.get('#risk-content').textContent, '');
    assert.match(app.get('#login-message').textContent, /session ended/i);
  } finally { app.restore(); }
});

for (const action of ['sign out', 'navigate away']) {
  test(`late risk response cannot restore content after ${action}`, async () => {
    const pending = deferred();
    const app = await startDashboard((call) => {
      const login = authenticate(call);
      if (login) return login;
      if (call.path === '/api/admin/devices') return response(200, []);
      return pending.promise;
    }, `#/risk/${endpointId}`);
    try {
      await app.login();
      if (action === 'sign out') {
        await app.get('#sign-out').trigger('click');
        await settle();
      } else {
        await app.navigate('#/devices');
      }
      pending.resolve(response(200, detail));
      await settle();
      assert.equal(app.get('#risk-detail-view').hidden, true);
      assert.equal(app.get('#risk-detail-content').textContent, '');
      if (action === 'sign out') assert.equal(app.get('#login-view').hidden, false);
      else assert.equal(app.get('#devices-view').hidden, false);
    } finally { app.restore(); }
  });
}
