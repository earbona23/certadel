/**
 * The authorization gate. These tests protect the property that certadel cannot be
 * pointed at something you did not authorize -- the safety analogue of a read-only
 * guarantee, and the reason the tool is defensible to run.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeScope, validateAsset, scopeGuard, ScopeError } from '../src/scope.js';

test('a scope must name the organisation and at least one asset', () => {
  assert.throws(() => normalizeScope({ assets: ['example.com'] }), ScopeError);
  assert.throws(() => normalizeScope({ organization: 'X' }), ScopeError);
  assert.throws(() => normalizeScope({ organization: 'X', assets: [] }), ScopeError);
});

test('valid assets are lower-cased and de-duplicated', () => {
  const scope = normalizeScope({
    organization: 'Acme',
    assets: ['Example.com', 'example.com', 'API.example.com'],
  });
  assert.deepEqual(scope.assets, ['example.com', 'api.example.com']);
});

test('a URL, port, CIDR, IP or wildcard is refused as an asset', () => {
  for (const bad of [
    'https://example.com/path',
    'example.com:443',
    '10.0.0.0/8',
    '192.168.1.1',
    '*.example.com',
    'not a host',
  ]) {
    assert.throws(() => validateAsset(bad), ScopeError, `should reject ${bad}`);
  }
});

test('the scope guard admits authorized hosts and their subdomains, nothing else', () => {
  const guard = scopeGuard(normalizeScope({ organization: 'Acme', assets: ['example.com'] }));
  assert.equal(guard('example.com'), true);
  assert.equal(guard('mta-sts.example.com'), true, 'subdomains are needed by email checks');
  assert.equal(guard('example.com.'), true, 'trailing dot tolerated');
  assert.equal(guard('evil.com'), false);
  assert.equal(guard('notexample.com'), false, 'suffix must be on a dot boundary');
  assert.equal(guard('example.com.evil.com'), false);
});
