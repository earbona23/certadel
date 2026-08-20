import { test } from 'node:test';
import assert from 'node:assert/strict';
import { headerChecks } from '../../src/checks/headers.js';
import { cookieChecks } from '../../src/checks/cookies.js';

const byId = (rs, id) => rs.find((r) => r.id === id);

test('a fully hardened set of headers passes', () => {
  const rs = headerChecks({ https: { headers: {
    'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
  } } });
  for (const id of ['header-csp', 'header-content-type-options', 'header-framing',
    'header-referrer-policy', 'header-permissions-policy']) {
    assert.equal(byId(rs, id).status, 'pass', `${id}`);
  }
});

test("a CSP with 'unsafe-inline' script-src warns rather than passing", () => {
  const rs = headerChecks({ https: { headers: { 'content-security-policy': "script-src 'self' 'unsafe-inline'" } } });
  const csp = byId(rs, 'header-csp');
  assert.equal(csp.status, 'warn');
  assert.match(csp.detail, /unsafe-inline/);
});

test('missing CSP fails high; a version-leaking Server banner warns', () => {
  const rs = headerChecks({ https: { headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/8.1.2' } } });
  assert.equal(byId(rs, 'header-csp').status, 'fail');
  assert.equal(byId(rs, 'header-csp').severity, 'high');
  assert.equal(byId(rs, 'header-version-disclosure').status, 'warn');
});

test('CSP frame-ancestors counts as clickjacking protection without X-Frame-Options', () => {
  const rs = headerChecks({ https: { headers: { 'content-security-policy': "frame-ancestors 'none'" } } });
  assert.equal(byId(rs, 'header-framing').status, 'pass');
});

test('cookies missing Secure/HttpOnly/SameSite each fail their flag', () => {
  const rs = cookieChecks({ https: { setCookie: ['sid=abc; Path=/'] } });
  assert.equal(byId(rs, 'cookie-secure').status, 'fail');
  assert.equal(byId(rs, 'cookie-httponly').status, 'fail');
  assert.equal(byId(rs, 'cookie-samesite').status, 'fail');
});

test('a fully-flagged cookie passes and SameSite=None counts as cross-site', () => {
  const good = cookieChecks({ https: { setCookie: ['sid=abc; Secure; HttpOnly; SameSite=Lax'] } });
  assert.equal(byId(good, 'cookie-secure').status, 'pass');
  const none = cookieChecks({ https: { setCookie: ['sid=abc; Secure; HttpOnly; SameSite=None'] } });
  assert.equal(byId(none, 'cookie-samesite').status, 'fail');
});

test('a site with no cookies skips the cookie dimension (not pass)', () => {
  const rs = cookieChecks({ https: { setCookie: [] } });
  assert.equal(rs[0].status, 'skip');
});
