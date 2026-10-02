import test from 'node:test';
import assert from 'node:assert/strict';
import { deferred, response, settle, startDashboard } from './dom-harness.mjs';

const alertId = '6c9bafbc-3616-4642-b61d-a3bc2e69cc64';
const endpointId = '2ecfd214-1aab-4393-9c69-091441eaad7b';
const maliciousTitle = '<img src=x onerror="alert(1)"> Firewall disabled';
const alert = {
  alertId, endpointId, endpointName: 'Development workstation', ruleId: 'firewall.public.disabled',
  title: maliciousTitle, severity: 'high', status: 'open',
  firstObservedUtc: '2026-10-02T08:00:00Z', lastObservedUtc: '2026-10-02T09:00:00Z',
  createdUtc: '2026-10-02T08:00:00Z', updatedUtc: '2026-10-02T09:00:00Z',
  statusChangedUtc: '2026-10-02T08:00:00Z', version: 1,
  reason: 'A disabled public firewall exposes the endpoint to unwanted inbound connections.',
  evidence: [{ field: 'publicFirewallEnabled', value: false }, { field: 'configuredCount', value: 3 }],
  recommendedAction: 'Review the public profile and enable the firewall when appropriate.',
  statusHistory: [{ previousStatus: null, status: 'open', changedUtc: '2026-10-02T08:00:00Z', changedBy: 'Core' }],
};

function authenticate(call) {
  if (call.path !== '/api/auth/login') return null;
  return response(200, { accessToken: 'development-test-token' });
}

function alertPage(call, items = [alert]) {
  const query = new URL(call.path, 'http://127.0.0.1').searchParams;
  const limit = Number(query.get('limit') ?? 50);
  return response(200, { alerts: items, total: limit + 1, offset: Number(query.get('offset') ?? 0), limit });
}

test('signed-in alert list filters severity/status and navigates pages with authenticated requests', async () => {
  const app = await startDashboard((call) => authenticate(call) ?? alertPage(call));
  try {
    await app.login();
    assert.equal(app.get('#alerts-view').hidden, false);
    assert.equal(app.get('#workspace-nav').hidden, false);
    const content = app.get('#alerts-content');
    assert.ok(content.textContent.includes(maliciousTitle));
    assert.ok(content.textContent.includes(alert.endpointName));
    assert.equal(content.querySelectorAll('img, script').length, 0);
    const detailLink = content.querySelectorAll('a').find((link) => link.href === `#/alerts/${alertId}`);
    assert.ok(detailLink, 'each alert links to its detail route');

    app.get('#severity-filter').value = 'high';
    app.get('#status-filter').value = 'investigating';
    await app.get('#alert-filters').trigger('submit');
    await settle();
    let requests = app.calls.filter((call) => call.path.startsWith('/api/admin/alerts?'));
    let params = new URL(requests.at(-1).path, 'http://127.0.0.1').searchParams;
    assert.equal(params.get('severity'), 'high');
    assert.equal(params.get('status'), 'investigating');
    assert.equal(Number(params.get('offset')), 0);
    const limit = Number(params.get('limit'));
    assert.ok(limit > 0);
    assert.equal(app.get('#alerts-next').disabled, false);
    assert.equal(app.get('#alerts-previous').disabled, true);

    await app.get('#alerts-next').trigger('click');
    await settle();
    requests = app.calls.filter((call) => call.path.startsWith('/api/admin/alerts?'));
    params = new URL(requests.at(-1).path, 'http://127.0.0.1').searchParams;
    assert.equal(Number(params.get('offset')), limit);
    assert.equal(params.get('severity'), 'high');
    assert.equal(params.get('status'), 'investigating');
    assert.equal(app.get('#alerts-previous').disabled, false);
    assert.equal(app.get('#alerts-next').disabled, true);

    await app.get('#alerts-previous').trigger('click');
    await settle();
    const last = app.calls.at(-1);
    assert.equal(new URL(last.path, 'http://127.0.0.1').searchParams.get('offset'), '0');
    assert.equal(last.headers.Authorization, 'Bearer development-test-token');
    assert.equal(last.cache, 'no-store');
    assert.equal(last.credentials, 'omit');
    assert.equal(app.get('#password').value, '');
  } finally {
    app.restore();
  }
});

test('alert details answer the incident questions and keep evidence as literal text', async () => {
  const evidenceText = '<script>window.compromised=true</script>';
  const detail = { ...alert, statusHistoryCount: 101,
    evidence: [...alert.evidence, { field: evidenceText, value: false }] };
  const app = await startDashboard((call) => authenticate(call) ?? response(200, detail), `#/alerts/${alertId}`);
  try {
    await app.login();
    assert.equal(app.get('#alert-detail-view').hidden, false);
    const content = app.get('#alert-detail-content');
    for (const text of [maliciousTitle, alert.reason, alert.endpointName, alert.recommendedAction,
      'publicFirewallEnabled', 'false', 'configuredCount', '3', evidenceText]) {
      assert.ok(content.textContent.includes(text), `detail displays ${text}`);
    }
    assert.equal(content.querySelectorAll('img, script').length, 0);
    assert.match(content.textContent, /latest 1 of 101 status changes/i,
      'bounded status history makes retained earlier entries visible to administrators');
    assert.ok(content.querySelectorAll('a').some((link) => link.href === `#/devices/${endpointId}`));
    const options = app.get('#alert-status-select').querySelectorAll('option').map((option) => option.value);
    assert.deepEqual(options, ['open', 'investigating', 'resolved', 'accepted']);
  } finally {
    app.restore();
  }
});

test('status save uses the displayed version, disables controls while pending, and displays the returned state', async () => {
  const save = deferred();
  const app = await startDashboard((call) => {
    if (call.method === 'PUT') return save.promise;
    return authenticate(call) ?? response(200, alert);
  }, `#/alerts/${alertId}`);
  try {
    await app.login();
    const select = app.get('#alert-status-select');
    const submit = app.get('#save-alert-status');
    select.value = 'resolved';
    await select.trigger('change');
    const pending = app.get('#alert-status-form').trigger('submit');
    await settle();
    assert.equal(select.disabled, true);
    assert.equal(submit.disabled, true);
    const request = app.calls.find((call) => call.method === 'PUT');
    assert.equal(request.path, `/api/admin/alerts/${alertId}/status`);
    assert.deepEqual(JSON.parse(request.body), { status: 'resolved', expectedVersion: 1 });
    assert.equal(request.headers.Authorization, 'Bearer development-test-token');
    assert.equal(request.headers['Content-Type'], 'application/json');
    save.resolve(response(200, { ...alert, status: 'resolved', version: 2 }));
    await pending;
    await settle();
    assert.equal(app.get('#alert-status-select').value, 'resolved');
    assert.equal(app.get('#alert-status-select').disabled, false);
    assert.equal(app.get('#save-alert-status').disabled, true, 'saving requires another explicit status change');
    assert.match(app.get('#alert-status-message').textContent, /saved|updated/i);
    assert.equal(app.calls.filter((call) => call.method === 'PUT').length, 1);
  } finally {
    app.restore();
  }
});

test('a concurrent status change reloads current detail and requires a fresh administrator choice', async () => {
  let detailLoads = 0;
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    if (call.method === 'PUT') return response(409, { error: 'Alert status has changed.' });
    detailLoads += 1;
    return response(200, detailLoads === 1 ? alert : { ...alert, status: 'accepted', version: 2 });
  }, `#/alerts/${alertId}`);
  try {
    await app.login();
    app.get('#alert-status-select').value = 'resolved';
    await app.get('#alert-status-select').trigger('change');
    await app.get('#alert-status-form').trigger('submit');
    await settle();
    assert.equal(detailLoads, 2);
    assert.equal(app.calls.filter((call) => call.method === 'PUT').length, 1, 'a conflict must never retry a write');
    assert.equal(app.get('#alert-status-select').value, 'accepted');
    assert.match(app.get('#alert-status-message').textContent, /changed|conflict|another/i);
    assert.equal(app.get('#save-alert-status').disabled, true);

    // A later explicit submission uses the refreshed version.
    app.get('#alert-status-select').value = 'investigating';
    await app.get('#alert-status-select').trigger('change');
    await app.get('#alert-status-form').trigger('submit');
    await settle();
    const writes = app.calls.filter((call) => call.method === 'PUT');
    assert.deepEqual(JSON.parse(writes[1].body), { status: 'investigating', expectedVersion: 2 });
  } finally {
    app.restore();
  }
});

test('session expiry during a status write clears the alert content and returns to sign-in', async () => {
  const app = await startDashboard((call) => {
    if (call.method === 'PUT') return response(401, {});
    return authenticate(call) ?? response(200, alert);
  }, `#/alerts/${alertId}`);
  try {
    await app.login();
    app.get('#alert-status-select').value = 'investigating';
    await app.get('#alert-status-select').trigger('change');
    await app.get('#alert-status-form').trigger('submit');
    await settle();
    assert.equal(app.get('#login-view').hidden, false);
    assert.equal(app.get('#alert-detail-view').hidden, true);
    assert.equal(app.get('#workspace-nav').hidden, true);
    assert.equal(app.get('#alert-detail-content').textContent, '');
    assert.equal(app.get('#alerts-content').textContent, '');
    assert.match(app.get('#login-message').textContent, /session ended/i);
  } finally {
    app.restore();
  }
});

test('device navigation remains available after adding alerts', async () => {
  const app = await startDashboard((call) => authenticate(call) ?? response(200, [{
    endpointId, name: 'Development workstation', operatingSystem: 'Windows 11',
    healthState: 'healthy', lastSeenUtc: '2026-10-02T09:00:00Z', agentVersion: '0.1.0',
    securityPostureSummary: 'Firewall enabled',
  }]), '#/devices');
  try {
    await app.login();
    assert.equal(app.get('#devices-view').hidden, false);
    assert.ok(app.get('#devices-content').textContent.includes('Development workstation'));
    assert.equal(app.calls.at(-1).path, '/api/admin/devices');
  } finally {
    app.restore();
  }
});

for (const action of ['sign out', 'navigate away']) {
  test(`a late conflicting status response cannot restore an alert after ${action}`, async () => {
    const save = deferred();
    const app = await startDashboard((call) => {
      const login = authenticate(call);
      if (login) return login;
      if (call.method === 'PUT') return save.promise;
      if (call.path === '/api/admin/devices') return response(200, []);
      return response(200, alert);
    }, `#/alerts/${alertId}`);
    try {
      await app.login();
      app.get('#alert-status-select').value = 'resolved';
      await app.get('#alert-status-select').trigger('change');
      await app.get('#alert-status-form').trigger('submit');
      await settle();
      if (action === 'sign out') {
        await app.get('#sign-out').trigger('click');
        await settle();
      } else {
        await app.navigate('#/devices');
      }
      save.resolve(response(409, {}));
      await settle();
      assert.equal(app.calls.filter((call) => call.path === `/api/admin/alerts/${alertId}`).length, 1,
        'a stale write must not start a conflict reload for an abandoned view');
      assert.equal(app.get('#alert-detail-view').hidden, true);
      if (action === 'sign out') {
        assert.equal(app.get('#login-view').hidden, false);
        assert.equal(app.get('#alert-detail-content').textContent, '');
      } else {
        assert.equal(app.get('#devices-view').hidden, false);
        assert.ok(app.get('#devices-content').textContent.includes('No devices yet'));
      }
    } finally {
      app.restore();
    }
  });
}

test('alert loading, empty results, and retryable failures explain the current state', async () => {
  const list = deferred();
  let requests = 0;
  const app = await startDashboard((call) => {
    const login = authenticate(call);
    if (login) return login;
    requests += 1;
    if (requests === 1) return list.promise;
    if (requests === 2) return response(503, {});
    return response(200, { alerts: [alert], total: 1, offset: 0, limit: 50 });
  });
  try {
    await app.login();
    assert.match(app.get('#alerts-status').textContent, /loading/i);
    assert.equal(app.get('#alerts-content').textContent, '');
    assert.equal(app.get('#alerts-next').disabled, true);
    list.resolve(response(200, { alerts: [], total: 0, offset: 0, limit: 50 }));
    await settle();
    assert.match(app.get('#alerts-content').textContent, /no matching alerts/i);
    assert.match(app.get('#alerts-content').textContent, /unknown|unsupported/i);
    await app.get('#refresh-alerts').trigger('click');
    await settle();
    assert.match(app.get('#alerts-status').textContent, /could not load/i);
    assert.match(app.get('#alerts-content').textContent, /unavailable/i);
    await app.get('#alerts-content').querySelector('button').trigger('click');
    await settle();
    assert.ok(app.get('#alerts-content').textContent.includes(alert.title));
    assert.equal(requests, 3);
  } finally {
    app.restore();
  }
});
