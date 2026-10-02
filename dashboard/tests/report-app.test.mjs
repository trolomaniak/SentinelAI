import test from 'node:test';
import assert from 'node:assert/strict';
import { previousUtcMonth, reportRangeError } from '../assets/report-view.js';
import { routeFromHash } from '../assets/device-view.js';
import { deferred, response, settle, startDashboard } from './dom-harness.mjs';

const reportHtml = '<!doctype html><html><body><h1>Synthetic security report</h1><script>unexpected()</script></body></html>';
const from = '2026-09-01';
const to = '2026-09-30';
const reportRequest = (call) => call.path.startsWith('/api/admin/reports/security?');
const htmlResponse = () => new Response(reportHtml, {
  headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': 'attachment; filename="untrusted-name.html"' },
});

async function withReports(handler, run, origin) {
  const create = URL.createObjectURL;
  const revoke = URL.revokeObjectURL;
  const created = [];
  const revoked = [];
  URL.createObjectURL = (blob) => {
    const url = `blob:synthetic-report-${created.length + 1}`;
    created.push({ blob, url });
    return url;
  };
  URL.revokeObjectURL = (url) => { revoked.push(url); };
  let app;
  try {
    app = await startDashboard((call) => call.path === '/api/auth/login'
      ? response(200, { accessToken: 'synthetic-admin-token' })
      : reportRequest(call) ? handler(call) : response(200, []), '#/reports', origin);
    await run({ ...app, created, revoked });
  } finally {
    app?.restore();
    URL.createObjectURL = create;
    URL.revokeObjectURL = revoke;
  }
}

function selectPeriod(app) {
  app.get('#report-from').value = from;
  app.get('#report-to').value = to;
}

test('report route is explicit and default dates use the previous complete UTC calendar month', async () => {
  assert.deepEqual(routeFromHash('#/reports'), { kind: 'reports' });
  assert.deepEqual(routeFromHash('#/reports/../api'), { kind: 'invalid' });
  for (const [now, expected] of [
    ['2026-01-01T00:01:00Z', { from: '2025-12-01', to: '2025-12-31' }],
    ['2024-03-31T23:59:59Z', { from: '2024-02-01', to: '2024-02-29' }],
    ['2025-03-01T00:00:00Z', { from: '2025-02-01', to: '2025-02-28' }],
    ['2026-03-01T00:30:00+02:00', { from: '2026-01-01', to: '2026-01-31' }],
  ]) assert.deepEqual(previousUtcMonth(new Date(now)), expected);
  await withReports(htmlResponse, async (app) => {
    assert.equal(app.get('#reports-view').hidden, true, 'report generation requires sign-in');
    await app.login();
    assert.equal(app.get('#reports-view').hidden, false);
    assert.equal(app.get('#reports-nav').getAttribute('aria-current'), 'page');
    assert.deepEqual({ from: app.get('#report-from').value, to: app.get('#report-to').value }, previousUtcMonth());
    assert.equal(app.calls.filter(reportRequest).length, 0, 'navigation alone does not generate a report');
    assert.match(app.get('#reports-view').textContent, /without cloud AI/);
    assert.match(app.get('#reports-view').textContent, /current snapshot/);
    assert.match(app.get('#reports-view').textContent, /historical score trends are unavailable/);
  });
});

test('an explicit report request creates a local download and never injects the returned HTML into the dashboard', async () => {
  await withReports(htmlResponse, async (app) => {
    await app.login();
    selectPeriod(app);
    await app.get('#report-form').trigger('submit');
    const request = app.calls.find(reportRequest);
    assert.equal(request.path, `/api/admin/reports/security?from=${from}&to=${to}`);
    assert.equal(request.method, 'GET');
    assert.equal(request.headers.Authorization, 'Bearer synthetic-admin-token');
    assert.equal(request.body, undefined);
    assert.equal(request.cache, 'no-store');
    assert.equal(request.credentials, 'omit');
    assert.equal(request.redirect, 'error');
    assert.ok(!request.path.includes('token'));
    assert.equal(app.created.length, 1);
    assert.equal(await app.created[0].blob.text(), reportHtml);
    const download = app.get('#download-report');
    assert.equal(download.href, app.created[0].url);
    assert.equal(download.download, `SentinelAI-security-report-${from}-${to}.html`);
    assert.equal(download.target, undefined, 'download requires a separate user action');
    assert.equal(download.rel, 'noopener');
    assert.equal(app.get('#report-content').querySelectorAll('script, iframe, img').length, 0);
    assert.ok(!app.get('#report-content').textContent.includes(reportHtml));
    assert.ok(!app.get('#report-content').textContent.includes('synthetic-admin-token'));
    assert.equal(app.calls.some((call) => /license|explanation|cloud/.test(call.path)), false);
    assert.equal(app.get('#generate-report').disabled, false);
    assert.match(app.get('#report-status').textContent, /generated locally/);
  });
});

test('required strict calendar dates and the inclusive 366-day bound prevent invalid requests', async () => {
  assert.equal(reportRangeError('2024-01-01', '2024-12-31'), null);
  assert.notEqual(reportRangeError('2024-01-01', '2025-01-01'), null);
  assert.equal(reportRangeError('2026-09-30', '2026-09-30'), null);
  await withReports(htmlResponse, async (app) => {
    await app.login();
    for (const [start, end] of [['', to], [from, ''], ['2026-02-30', to], ['2026-9-01', to],
      ['0000-01-01', '0000-01-02'], ['2026-10-01', to], ['2024-01-01', '2025-01-01'], ['9999-12-01', '9999-12-31']]) {
      app.get('#report-from').value = start;
      app.get('#report-to').value = end;
      await app.get('#report-form').trigger('submit');
      assert.ok(app.get('#report-status').textContent, 'validation explains each invalid date range');
      assert.equal(app.get('#generate-report').disabled, false);
    }
    assert.equal(app.calls.filter(reportRequest).length, 0);
  });
});

test('a pending generation prevents duplicate requests and disables date edits until ready', async () => {
  const pending = deferred();
  await withReports(() => pending.promise, async (app) => {
    await app.login();
    selectPeriod(app);
    const generation = app.get('#report-form').trigger('submit');
    await settle();
    assert.equal(app.get('#generate-report').disabled, true);
    assert.equal(app.get('#report-from').disabled, true);
    assert.equal(app.get('#report-to').disabled, true);
    assert.equal(app.get('#report-form').getAttribute('aria-busy'), 'true');
    await app.get('#report-form').trigger('submit');
    assert.equal(app.calls.filter(reportRequest).length, 1);
    pending.resolve(htmlResponse());
    await generation;
    assert.equal(app.get('#generate-report').disabled, false);
    assert.equal(app.get('#report-from').disabled, false);
    assert.equal(app.get('#report-form').getAttribute('aria-busy'), 'false');
  });
});

for (const [failure, message] of [
  [400, /rejected this date range/], [422, /exceeds local generation limits/], [503, /Core connection/],
  ['network', /Core connection/], ['wrong type', /Core connection/],
]) {
  test(`report ${failure} failure is safe, preserves dates, and supports retry`, async () => {
    let attempts = 0;
    await withReports(() => {
      attempts += 1;
      if (attempts > 1) return htmlResponse();
      if (failure === 'network') throw new Error('Private synthetic network information');
      if (failure === 'wrong type') return new Response('Private synthetic error', { headers: { 'Content-Type': 'application/json' } });
      return response(failure, { error: 'Private synthetic internal information' });
    }, async (app) => {
      await app.login();
      selectPeriod(app);
      await app.get('#report-form').trigger('submit');
      assert.match(app.get('#report-status').textContent, message);
      assert.ok(!app.get('#report-status').textContent.includes('Private synthetic'));
      assert.equal(app.get('#report-content').textContent, '');
      assert.equal(app.created.length, 0);
      assert.equal(app.get('#report-from').value, from);
      assert.equal(app.get('#report-to').value, to);
      assert.equal(app.get('#generate-report').disabled, false);
      await app.get('#report-form').trigger('submit');
      assert.ok(app.get('#download-report'));
      assert.equal(attempts, 2);
    });
  });
}

test('new requests revoke the prior object URL before generating another report', async () => {
  await withReports(htmlResponse, async (app) => {
    await app.login();
    selectPeriod(app);
    await app.get('#report-form').trigger('submit');
    const prior = app.created[0].url;
    await app.get('#report-form').trigger('submit');
    assert.deepEqual(app.revoked, [prior]);
    assert.equal(app.created.length, 2);
    assert.equal(app.get('#download-report').href, app.created[1].url);
    app.get('#report-from').value = '';
    await app.get('#report-form').trigger('submit');
    assert.deepEqual(app.revoked, [prior, app.created[1].url]);
    assert.equal(app.get('#report-content').textContent, '');
  });
});

for (const action of ['navigation', 'sign out', 'expiry']) {
  test(`an existing report download is revoked on ${action}`, async () => {
    let requests = 0;
    await withReports(() => ++requests === 1 ? htmlResponse() : response(401, {}), async (app) => {
      await app.login();
      selectPeriod(app);
      await app.get('#report-form').trigger('submit');
      const prior = app.created[0].url;
      if (action === 'navigation') await app.navigate('#/devices');
      else if (action === 'sign out') await app.get('#sign-out').trigger('click');
      else await app.get('#report-form').trigger('submit');
      await settle();
      assert.deepEqual(app.revoked, [prior]);
      assert.equal(app.get('#report-content').textContent, '');
      assert.equal(app.get('#reports-view').hidden, true);
      if (action === 'expiry') {
        assert.match(app.get('#login-message').textContent, /session ended/);
        assert.equal(app.get('#workspace-nav').hidden, true);
      }
    });
  });
}

for (const action of ['navigation', 'sign out', 'new report view']) {
  test(`a late report response cannot restore a download after ${action}`, async () => {
    const pending = deferred();
    await withReports(() => pending.promise, async (app) => {
      await app.login();
      selectPeriod(app);
      const generation = app.get('#report-form').trigger('submit');
      await settle();
      if (action === 'sign out') await app.get('#sign-out').trigger('click');
      else {
        await app.navigate('#/devices');
        if (action === 'new report view') await app.navigate('#/reports');
      }
      pending.resolve(htmlResponse());
      await generation;
      assert.equal(app.created.length, 0);
      assert.equal(app.get('#report-content').textContent, '');
      assert.equal(app.get('#generate-report').disabled, false);
    });
  });
}

test('a late report body is discarded when navigation occurs while the body is being read', async () => {
  const body = deferred();
  await withReports(() => ({ status: 200, ok: true, headers: new Headers({ 'Content-Type': 'text/html' }), blob: () => body.promise }), async (app) => {
    await app.login();
    selectPeriod(app);
    const generation = app.get('#report-form').trigger('submit');
    await settle();
    await app.navigate('#/devices');
    body.resolve(new Blob([reportHtml], { type: 'text/html' }));
    await generation;
    assert.equal(app.created.length, 0);
    assert.equal(app.get('#devices-view').hidden, false);
  });
});

for (const status of [200, 401]) {
test(`an older session's HTTP ${status} report cannot expire or repopulate a newly signed-in session`, async () => {
  const pending = deferred();
  const create = URL.createObjectURL;
  const revoke = URL.revokeObjectURL;
  const created = [];
  URL.createObjectURL = (blob) => { created.push(blob); return 'blob:synthetic-unused'; };
  URL.revokeObjectURL = () => {};
  let sessions = 0;
  const app = await startDashboard((call) => call.path === '/api/auth/login'
    ? response(200, { accessToken: `synthetic-session-${++sessions}` })
    : reportRequest(call) ? pending.promise : response(200, []), '#/reports');
  try {
    await app.login();
    selectPeriod(app);
    const generation = app.get('#report-form').trigger('submit');
    await settle();
    await app.get('#sign-out').trigger('click');
    await app.login();
    await app.navigate('#/reports');
    pending.resolve(status === 200 ? htmlResponse() : response(401, {}));
    await generation;
    assert.equal(app.get('#login-view').hidden, true);
    assert.equal(app.get('#reports-view').hidden, false);
    assert.equal(app.get('#report-content').textContent, '');
    assert.equal(created.length, 0);
  } finally {
    app.restore();
    URL.createObjectURL = create;
    URL.revokeObjectURL = revoke;
  }
});
}

test('report generation remains inaccessible from an untrusted HTTP origin', async () => {
  await withReports(htmlResponse, async (app) => {
    await app.login();
    selectPeriod(app);
    await app.get('#report-form').trigger('submit');
    assert.equal(app.calls.length, 0);
    assert.equal(app.get('#reports-view').hidden, true);
    assert.equal(app.get('#login-submit').disabled, true);
    assert.match(app.get('#login-message').textContent, /HTTPS/);
  }, { protocol: 'http:', hostname: 'core.example.test' });
});
