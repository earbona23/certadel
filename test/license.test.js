/**
 * The Pro license layer. Verified with an ephemeral keypair injected as the public key,
 * so the real signing key is never needed to test the mechanism. Plus the SARIF export.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyLicenseKey } from '../src/license/verify.js';
import { renderSarif } from '../src/report/sarif.js';

function mint(payload, privateKey) {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  return `CERTADEL-${bytes.toString('base64url')}.${sign(null, bytes, privateKey).toString('base64url')}`;
}
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'pem' });

test('a properly signed key verifies; an expired one does not', () => {
  const good = mint({ sub: 'Acme', plan: 'team', iat: 1000 }, privateKey);
  assert.equal(verifyLicenseKey(good, { publicKeyPem: pub, now: 2000 }).valid, true);
  const expired = mint({ sub: 'Acme', plan: 'pro', iat: 1000, exp: 1500 }, privateKey);
  const r = verifyLicenseKey(expired, { publicKeyPem: pub, now: 2000 });
  assert.equal(r.valid, false);
  assert.match(r.reason, /expired/i);
});

test('a key signed by a different key does not verify', () => {
  const other = generateKeyPairSync('ed25519');
  const key = mint({ sub: 'x', plan: 'team', iat: 1 }, other.privateKey);
  assert.equal(verifyLicenseKey(key, { publicKeyPem: pub }).valid, false);
});

test('junk and non-certadel keys are rejected cleanly', () => {
  for (const junk of ['', 'nope', 'CERTADEL-bad', 'BLASTRADIUS-a.b']) {
    const r = verifyLicenseKey(junk, { publicKeyPem: pub });
    assert.equal(r.valid, false);
    assert.ok(typeof r.reason === 'string');
  }
});

test('the embedded default public key rejects an ephemeral key', async () => {
  const { LICENSE_PUBLIC_KEY_PEM } = await import('../src/license/keys.js');
  assert.match(LICENSE_PUBLIC_KEY_PEM, /BEGIN PUBLIC KEY/);
  assert.equal(verifyLicenseKey(mint({ sub: 'x', plan: 'pro', iat: 1 }, privateKey)).valid, false);
});

test('SARIF export contains a result per failing/warning finding', () => {
  const report = {
    assets: [
      {
        host: 'a.example',
        findings: [
          { id: 'tls-hsts', title: 'HSTS', dimension: 'transport', status: 'fail', severity: 'medium', detail: 'no hsts', remediation: 'add it' },
          { id: 'x', title: 'ok', dimension: 'headers', status: 'pass', severity: 'info' },
          { id: 'email-dmarc', title: 'DMARC', dimension: 'email', status: 'warn', severity: 'high', detail: 'weak' },
        ],
      },
    ],
  };
  const sarif = JSON.parse(renderSarif(report, { version: '1.0.0' }));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 2, 'pass is not a finding');
  assert.equal(sarif.runs[0].tool.driver.name, 'certadel');
  assert.ok(sarif.runs[0].results[0].message.text.includes('a.example'));
});
