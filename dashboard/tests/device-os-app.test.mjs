import test from 'node:test';
import assert from 'node:assert/strict';
import { response, startDashboard } from './dom-harness.mjs';

const endpointId = '2ecfd214-1aab-4393-9c69-091441eaad7b';
const device = {
  endpointId, name: 'Development workstation',
  operatingSystem: 'Windows 11 26H2 10.0.26200.0',
  healthState: 'healthy', lastSeenUtc: '2026-10-02T09:00:00Z',
  agentVersion: '0.1.0', securityPostureSummary: 'Firewall enabled',
};

function authenticate(call) {
  return call.path === '/api/auth/login'
    ? response(200, { accessToken: 'development-test-token' })
    : null;
}

function facts(content) {
  return Object.fromEntries(content.querySelectorAll('dl').flatMap((grid) =>
    grid.children.map((item) => [item.querySelector('dt').textContent, item.querySelector('dd').textContent])));
}

test('device list displays the complete OS while detail separates its name and version', async () => {
  const detail = { device, osName: 'Windows 11', osVersion: '26H2 10.0.26200.0' };
  const app = await startDashboard((call) => authenticate(call) ??
    response(200, call.path === '/api/admin/devices' ? [device] : detail), '#/devices');
  try {
    await app.login();
    const cells = app.get('#devices-content').querySelectorAll('td');
    assert.equal(cells[1].textContent, 'Windows 11 26H2 10.0.26200.0');
    await app.navigate(`#/devices/${endpointId}`);
    const values = facts(app.get('#detail-content'));
    assert.equal(values.OS, 'Windows 11');
    assert.equal(values['OS Version'], '26H2 10.0.26200.0');
  } finally {
    app.restore();
  }
});

test('Server Core installation text supplied by Core remains in the complete list display', async () => {
  const server = { ...device, operatingSystem: 'Windows Server 2025 24H2 Server Core 10.0.26100.0' };
  const app = await startDashboard((call) => authenticate(call) ?? response(200, [server]), '#/devices');
  try {
    await app.login();
    assert.equal(app.get('#devices-content').querySelectorAll('td')[1].textContent,
      'Windows Server 2025 24H2 Server Core 10.0.26100.0');
  } finally {
    app.restore();
  }
});

test('legacy device detail without an OS name keeps its existing operating system fallback', async () => {
  const legacyDevice = { ...device, operatingSystem: 'Microsoft Windows NT 10.0.26200.0' };
  const app = await startDashboard((call) => authenticate(call) ??
    response(200, { device: legacyDevice, osVersion: '10.0.26200.0' }), `#/devices/${endpointId}`);
  try {
    await app.login();
    const values = facts(app.get('#detail-content'));
    assert.equal(values.OS, legacyDevice.operatingSystem);
    assert.equal(values['OS Version'], '10.0.26200.0');
  } finally {
    app.restore();
  }
});

test('device detail marks absent OS inventory as not reported', async () => {
  const app = await startDashboard((call) => authenticate(call) ?? response(200, {
    device: { ...device, operatingSystem: null }, osName: null, osVersion: null,
  }), `#/devices/${endpointId}`);
  try {
    await app.login();
    const values = facts(app.get('#detail-content'));
    assert.equal(values.OS, 'Not reported');
    assert.equal(values['OS Version'], 'Not reported');
  } finally {
    app.restore();
  }
});

test('untrusted OS inventory is rendered as literal text in the list and detail', async () => {
  const osName = '<img src=x onerror="alert(1)"> Windows 11';
  const osVersion = '<script>window.compromised=true</script> 10.0.26200.0';
  const untrustedDevice = { ...device, operatingSystem: `${osName} ${osVersion}` };
  const app = await startDashboard((call) => authenticate(call) ?? response(200,
    call.path === '/api/admin/devices' ? [untrustedDevice] : { device: untrustedDevice, osName, osVersion }), '#/devices');
  try {
    await app.login();
    const list = app.get('#devices-content');
    assert.equal(list.querySelectorAll('td')[1].textContent, untrustedDevice.operatingSystem);
    assert.equal(list.querySelectorAll('img, script').length, 0);
    await app.navigate(`#/devices/${endpointId}`);
    const detail = app.get('#detail-content');
    const values = facts(detail);
    assert.equal(values.OS, osName);
    assert.equal(values['OS Version'], osVersion);
    assert.equal(detail.querySelectorAll('img, script').length, 0);
  } finally {
    app.restore();
  }
});
