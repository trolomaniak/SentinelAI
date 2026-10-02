import test from 'node:test';
import assert from 'node:assert/strict';
import {
  firewallLabel,
  formatBytes,
  formatTimestamp,
  healthPresentation,
  isTrustedDashboardOrigin,
  routeFromHash,
} from '../assets/device-view.js';

test('health always has a visible text label and a bounded style', () => {
  assert.deepEqual(healthPresentation('healthy'), { label: 'Healthy', className: 'health-healthy' });
  assert.deepEqual(healthPresentation('warning'), { label: 'Warning', className: 'health-warning' });
  assert.deepEqual(healthPresentation('offline'), { label: 'Offline', className: 'health-offline' });
  assert.deepEqual(healthPresentation('unexpected'), { label: 'Unknown', className: 'health-unknown' });
});

test('detail routes accept only endpoint IDs', () => {
  const id = '2ecfd214-1aab-7393-5c69-091441eaad7b';
  assert.deepEqual(routeFromHash(''), { kind: 'list' });
  assert.deepEqual(routeFromHash('#/devices'), { kind: 'list' });
  assert.deepEqual(routeFromHash(`#/devices/${id.toUpperCase()}`), { kind: 'detail', endpointId: id });
  assert.deepEqual(routeFromHash('#/devices/../api/auth/login'), { kind: 'invalid' });
});

test('dashboard sign-in requires HTTPS or a loopback HTTP origin', () => {
  assert.equal(isTrustedDashboardOrigin({ protocol: 'http:', hostname: '127.0.0.1' }), true);
  assert.equal(isTrustedDashboardOrigin({ protocol: 'http:', hostname: 'localhost' }), true);
  assert.equal(isTrustedDashboardOrigin({ protocol: 'https:', hostname: 'core.example.test' }), true);
  assert.equal(isTrustedDashboardOrigin({ protocol: 'http:', hostname: 'core.example.test' }), false);
  assert.equal(isTrustedDashboardOrigin({ protocol: 'file:', hostname: '' }), false);
});

test('missing and unavailable telemetry never appears as a healthy value', () => {
  assert.equal(formatTimestamp(null), 'Never reported');
  assert.equal(formatTimestamp('bad-date'), 'Unknown');
  assert.equal(formatBytes(null), 'Not reported');
  assert.equal(formatBytes(16 * 1024 ** 3), '16 GB');
  assert.equal(firewallLabel(null), 'Unknown');
  assert.equal(firewallLabel(false), 'Disabled');
});
