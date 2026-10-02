import test from 'node:test';
import assert from 'node:assert/strict';
import { deferred, response, settle, startDashboard } from './dom-harness.mjs';

const alertId = '6c9bafbc-3616-4642-b61d-a3bc2e69cc64';
const alert = {
  alertId, endpointId: '2ecfd214-1aab-4393-9c69-091441eaad7b', endpointName: 'Synthetic workstation',
  ruleId: 'SA-FW-003', title: 'Public firewall disabled', severity: 'high', status: 'open', version: 1,
  reason: 'The reported public firewall configuration is disabled.',
  recommendedAction: 'Review the firewall configuration.',
  evidence: [{ field: 'securityPosture.publicFirewallEnabled', value: false }], statusHistory: [],
};
const explanation = {
  label: 'AI assistive analysis',
  analysis: {
    explanation: '<script>deleteFiles()</script> A reported firewall setting is disabled.',
    whyItMatters: '<img src=x onerror="isolateHost()"> Unwanted connections may be allowed.',
    recommendedInvestigation: ['Confirm the currently applied profile.', '[Run me](javascript:disableAccounts())'],
    suggestedRemediation: ['Review required application exceptions before enabling the firewall.'],
    confidence: 'medium', uncertainty: 'Reported settings may be stale; inspect the endpoint before acting.',
  },
};

function authenticate(call, token = 'development-test-token') {
  return call.path === '/api/auth/login' ? response(200, { accessToken: token }) : null;
}

function serveAlert(call) {
  if (call.path === '/api/admin/devices') return response(200, []);
  if (call.method === 'PUT') return response(200, { ...alert, status: JSON.parse(call.body).status, version: 2 });
  return response(200, alert);
}

test('explicit AI request sends only the selected alert ID and renders structured output literally', async () => {
  const app = await startDashboard((call) => authenticate(call) ??
    (call.method === 'POST' ? response(200, explanation) : serveAlert(call)), `#/alerts/${alertId}`);
  try {
    await app.login();
    assert.equal(app.calls.filter((call) => call.path.endsWith('/explanation')).length, 0, 'loading an alert must not invoke paid AI');
    const panel = app.get('#alert-ai-panel');
    assert.match(panel.textContent, /AI assistive analysis/);
    assert.match(panel.textContent, /Hostnames and raw log history are excluded/);
    assert.match(panel.textContent, /Review suggestions before taking any action/);
    await app.get('#explain-alert').trigger('click');
    const request = app.calls.find((call) => call.path.endsWith('/explanation'));
    assert.equal(request.path, `/api/admin/alerts/${alertId}/explanation`);
    assert.equal(request.method, 'POST');
    assert.equal(request.body, undefined, 'the browser does not supply incident evidence or a destination');
    assert.equal(request.headers.Authorization, 'Bearer development-test-token');
    assert.equal(request.headers['Content-Type'], undefined);
    assert.equal(request.cache, 'no-store');
    assert.equal(request.credentials, 'omit');
    const output = app.get('#alert-ai-analysis');
    for (const text of [explanation.analysis.explanation, explanation.analysis.whyItMatters,
      ...explanation.analysis.recommendedInvestigation, ...explanation.analysis.suggestedRemediation,
      'Model confidence: medium', explanation.analysis.uncertainty]) {
      assert.ok(output.textContent.includes(text), `analysis displays ${text}`);
    }
    assert.equal(output.querySelectorAll('script, img, a, button').length, 0, 'AI text is neither markup nor actionable UI');
    assert.ok(app.get('#alert-detail-content').textContent.includes(alert.reason), 'deterministic finding remains displayed');
    assert.equal(app.get('#alert-status-select').value, 'open');
    assert.equal(app.calls.filter((call) => call.method === 'PUT').length, 0, 'an explanation cannot change alert status');
    assert.equal(app.get('#explain-alert').disabled, false);
  } finally {
    app.restore();
  }
});

test('pending explanation disables duplicate requests while preserving local status controls', async () => {
  const ai = deferred();
  const app = await startDashboard((call) => authenticate(call) ??
    (call.path.endsWith('/explanation') ? ai.promise : serveAlert(call)), `#/alerts/${alertId}`);
  try {
    await app.login();
    const button = app.get('#explain-alert');
    const pending = button.trigger('click');
    await settle();
    assert.equal(button.disabled, true);
    assert.match(app.get('#alert-ai-status').textContent, /Requesting AI/);
    assert.equal(app.get('#alert-status-select').disabled, false);
    await button.trigger('click');
    assert.equal(app.calls.filter((call) => call.path.endsWith('/explanation')).length, 1);
    ai.resolve(response(200, explanation));
    await pending;
    assert.equal(button.disabled, false);
  } finally {
    app.restore();
  }
});

for (const failure of ['unavailable', 'network', 'malformed']) {
  test(`AI ${failure} failure allows retry and local alert status updates`, async () => {
    let requests = 0;
    const app = await startDashboard((call) => {
      const login = authenticate(call);
      if (login) return login;
      if (call.path.endsWith('/explanation')) {
        requests += 1;
        if (requests > 1) return response(200, explanation);
        if (failure === 'network') throw new Error('Synthetic network failure');
        return failure === 'malformed' ? response(200, { label: explanation.label, analysis: { explanation: 'incomplete' } })
          : response(503, { error: 'Synthetic private provider error that must not be displayed' });
      }
      return serveAlert(call);
    }, `#/alerts/${alertId}`);
    try {
      await app.login();
      await app.get('#explain-alert').trigger('click');
      assert.match(app.get('#alert-ai-status').textContent, /unavailable/);
      assert.equal(app.get('#alert-ai-analysis').textContent, '');
      assert.ok(!app.get('#alert-ai-panel').textContent.includes('Synthetic private provider error'));
      assert.equal(app.get('#explain-alert').disabled, false);
      await app.get('#explain-alert').trigger('click');
      assert.ok(app.get('#alert-ai-analysis').textContent.includes(explanation.analysis.explanation));
      app.get('#alert-status-select').value = 'investigating';
      await app.get('#alert-status-select').trigger('change');
      await app.get('#alert-status-form').trigger('submit');
      await settle();
      assert.equal(app.get('#alert-status-select').value, 'investigating');
      assert.ok(app.get('#alert-detail-content').textContent.includes(alert.reason));
      assert.equal(app.get('#alert-ai-analysis').textContent, '', 'a status re-render discards previous AI output');
    } finally {
      app.restore();
    }
  });
}

for (const [status, message] of [[403, /current license or operating mode/], [422, /supported configuration evidence/], [429, /Wait before trying again/]]) {
  test(`AI HTTP ${status} produces a safe message and keeps local review available`, async () => {
    const app = await startDashboard((call) => authenticate(call) ??
      (call.path.endsWith('/explanation') ? response(status, {}) : serveAlert(call)), `#/alerts/${alertId}`);
    try {
      await app.login();
      await app.get('#explain-alert').trigger('click');
      assert.match(app.get('#alert-ai-status').textContent, message);
      assert.equal(app.get('#alert-detail-view').hidden, false);
      assert.equal(app.get('#alert-status-select').disabled, false);
      assert.equal(app.get('#explain-alert').disabled, false);
    } finally {
      app.restore();
    }
  });
}

test('AI session expiry clears alert and AI data and requires sign-in', async () => {
  const app = await startDashboard((call) => authenticate(call) ??
    (call.path.endsWith('/explanation') ? response(401, {}) : serveAlert(call)), `#/alerts/${alertId}`);
  try {
    await app.login();
    await app.get('#explain-alert').trigger('click');
    assert.equal(app.get('#login-view').hidden, false);
    assert.equal(app.get('#alert-detail-view').hidden, true);
    assert.equal(app.get('#alert-detail-content').textContent, '');
    assert.equal(app.get('#workspace-nav').hidden, true);
    assert.match(app.get('#login-message').textContent, /session ended/);
  } finally {
    app.restore();
  }
});

for (const action of ['navigate away', 'sign out', 'update status', 'reload alert', 'new session']) {
  test(`a late AI explanation cannot restore stale content after ${action}`, async () => {
    const ai = deferred();
    let logins = 0;
    const app = await startDashboard((call) => {
      if (call.path === '/api/auth/login') return authenticate(call, `development-session-${++logins}`);
      return call.path.endsWith('/explanation') ? ai.promise : serveAlert(call);
    }, `#/alerts/${alertId}`);
    try {
      await app.login();
      const pending = app.get('#explain-alert').trigger('click');
      await settle();
      if (action === 'navigate away') {
        await app.navigate('#/devices');
      } else if (action === 'sign out' || action === 'new session') {
        await app.get('#sign-out').trigger('click');
        await settle();
        if (action === 'new session') {
          await app.login();
          await app.navigate(`#/alerts/${alertId}`);
        }
      } else if (action === 'reload alert') {
        await app.navigate('#/devices');
        await app.navigate(`#/alerts/${alertId}`);
      } else {
        app.get('#alert-status-select').value = 'resolved';
        await app.get('#alert-status-select').trigger('change');
        await app.get('#alert-status-form').trigger('submit');
        await settle();
      }
      ai.resolve(response(200, explanation));
      await pending;
      assert.ok(!app.get('#alert-detail-content').textContent.includes(explanation.analysis.explanation));
      if (action === 'navigate away') assert.equal(app.get('#devices-view').hidden, false);
      else if (action === 'sign out') assert.equal(app.get('#login-view').hidden, false);
      else assert.equal(app.get('#alert-ai-analysis').textContent, '');
      if (action === 'update status') assert.equal(app.get('#alert-status-select').value, 'resolved');
    } finally {
      app.restore();
    }
  });
}

test('an old AI request cannot expire a newer signed-in session', async () => {
  const ai = deferred();
  let logins = 0;
  const app = await startDashboard((call) => {
    if (call.path === '/api/auth/login') return authenticate(call, `development-session-${++logins}`);
    return call.path.endsWith('/explanation') ? ai.promise : serveAlert(call);
  }, `#/alerts/${alertId}`);
  try {
    await app.login();
    const pending = app.get('#explain-alert').trigger('click');
    await settle();
    await app.get('#sign-out').trigger('click');
    await app.login();
    await app.navigate(`#/alerts/${alertId}`);
    ai.resolve(response(401, {}));
    await pending;
    assert.equal(app.get('#login-view').hidden, true);
    assert.equal(app.get('#alert-detail-view').hidden, false);
    assert.equal(app.get('#alert-ai-analysis').textContent, '');
  } finally {
    app.restore();
  }
});
