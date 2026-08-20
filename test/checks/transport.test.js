import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transportChecks } from '../../src/checks/transport.js';

const goodCert = {
  issuer: "Let's Encrypt", subjectCommonName: 'example.com',
  validFrom: new Date(Date.now() - 1e9).toISOString(),
  validTo: new Date(Date.now() + 60 * 86400000).toISOString(),
  altNames: ['example.com'], keyType: 'RSA', keyBits: 2048,
};
function ev(tls, headers = {}) {
  return { tls, https: { headers } };
}
const byId = (rs, id) => rs.find((r) => r.id === id);

test('no TLS connection is a single critical failure carrying the dimension', () => {
  const rs = transportChecks(ev({ connected: false, error: 'ECONNREFUSED' }));
  assert.equal(rs.length, 1);
  assert.equal(rs[0].id, 'tls-available');
  assert.equal(rs[0].status, 'fail');
  assert.equal(rs[0].severity, 'critical');
});

test('TLS 1.0 still offered is a critical finding', () => {
  const rs = transportChecks(ev({
    connected: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256',
    authorized: true, certificate: goodCert, legacyProbed: true, legacyProtocols: ['TLSv1'],
  }));
  const p = byId(rs, 'tls-protocol-versions');
  assert.equal(p.status, 'fail');
  assert.equal(p.severity, 'critical');
});

test('a modern, valid, TLS1.3-only host passes transport cleanly', () => {
  const rs = transportChecks(ev(
    { connected: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_256_GCM_SHA384',
      authorized: true, certificate: goodCert, legacyProbed: true, legacyProtocols: [] },
    { 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload' },
  ));
  for (const id of ['tls-protocol-versions', 'tls-certificate-valid', 'tls-key-strength',
    'tls-forward-secrecy', 'tls-hsts']) {
    assert.equal(byId(rs, id).status, 'pass', `${id} should pass`);
  }
});

test('an untrusted certificate is a critical failure', () => {
  const rs = transportChecks(ev({
    connected: true, protocol: 'TLSv1.2', cipherName: 'ECDHE-RSA-AES128-GCM-SHA256',
    authorized: false, authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN',
    certificate: goodCert, legacyProbed: true, legacyProtocols: [],
  }));
  const c = byId(rs, 'tls-certificate-valid');
  assert.equal(c.status, 'fail');
  assert.equal(c.severity, 'critical');
});

test('an expired certificate is critical; one expiring soon warns', () => {
  const expired = { ...goodCert, validTo: new Date(Date.now() - 86400000).toISOString() };
  const soon = { ...goodCert, validTo: new Date(Date.now() + 10 * 86400000).toISOString() };
  const base = { connected: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_128_GCM_SHA256',
    authorized: true, legacyProbed: true, legacyProtocols: [] };
  assert.equal(byId(transportChecks(ev({ ...base, certificate: expired })), 'tls-certificate-expiry').severity, 'critical');
  assert.equal(byId(transportChecks(ev({ ...base, certificate: soon })), 'tls-certificate-expiry').status, 'warn');
});
