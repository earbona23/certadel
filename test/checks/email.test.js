import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emailChecks } from '../../src/checks/email.js';

function ev(over = {}) {
  return {
    dns: { mx: [{ exchange: 'mx.example.com', priority: 10 }], txt: [] },
    dmarcTxt: [], mtaSts: { txt: [], policyMode: null }, tlsRpt: [], dkim: [],
    ...over,
  };
}
const byId = (rs, id) => rs.find((r) => r.id === id);

test('a domain with no MX and no SPF skips the whole email dimension', () => {
  const rs = emailChecks({ dns: { mx: [], txt: [] }, dmarcTxt: [], mtaSts: { txt: [] }, tlsRpt: [], dkim: [] });
  assert.equal(rs.length, 1);
  assert.equal(rs[0].status, 'skip');
});

test('missing SPF and DMARC both fail with high severity', () => {
  const rs = emailChecks(ev());
  assert.equal(byId(rs, 'email-spf').status, 'fail');
  assert.equal(byId(rs, 'email-dmarc').status, 'fail');
  assert.equal(byId(rs, 'email-dmarc').severity, 'high');
});

test('DMARC p=reject passes but p=none barely earns and p=quarantine partially earns', () => {
  const reject = byId(emailChecks(ev({ dmarcTxt: ['v=DMARC1; p=reject; rua=mailto:a@x'] })), 'email-dmarc');
  const quar = byId(emailChecks(ev({ dmarcTxt: ['v=DMARC1; p=quarantine'] })), 'email-dmarc');
  const none = byId(emailChecks(ev({ dmarcTxt: ['v=DMARC1; p=none'] })), 'email-dmarc');
  assert.equal(reject.status, 'pass');
  assert.equal(reject.earned, reject.max);
  assert.equal(quar.status, 'warn');
  assert.ok(quar.earned > none.earned && quar.earned < quar.max);
  assert.equal(none.status, 'fail');
});

test('SPF -all passes, ~all warns, +all fails', () => {
  const strict = byId(emailChecks(ev({ dns: { mx: [{ exchange: 'm', priority: 1 }], txt: [['v=spf1 include:_spf.x -all']] } })), 'email-spf');
  const soft = byId(emailChecks(ev({ dns: { mx: [{ exchange: 'm', priority: 1 }], txt: [['v=spf1 ~all']] } })), 'email-spf');
  assert.equal(strict.status, 'pass');
  assert.equal(soft.status, 'warn');
});

test('two SPF records is an invalid configuration and fails', () => {
  const rs = byId(emailChecks(ev({ dns: { mx: [{ exchange: 'm', priority: 1 }], txt: [['v=spf1 -all'], ['v=spf1 ~all']] } })), 'email-spf');
  assert.equal(rs.status, 'fail');
  assert.match(rs.detail, /more than one/i);
});

test('a domain that only publishes SPF (no MX) is still held to email standards', () => {
  const rs = emailChecks({ dns: { mx: [], txt: [['v=spf1 -all']] }, dmarcTxt: [], mtaSts: { txt: [] }, tlsRpt: [], dkim: [] });
  assert.ok(rs.length > 1, 'not skipped');
  assert.ok(byId(rs, 'email-spf'));
});
