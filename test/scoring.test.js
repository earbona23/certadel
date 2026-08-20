/**
 * The rubric and its gates. The gates are the honest core of the certificate: a high
 * score cannot buy back a critical hole, and the company grade follows its weakest asset.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { grade, rollUp } from '../src/scoring/grade.js';
import { result, skipped } from '../src/util/model.js';

function pass(id, dim, max) { return result({ id, title: id, dimension: dim, status: 'pass', max }); }
function fail(id, dim, max, severity) {
  return result({ id, title: id, dimension: dim, status: 'fail', severity, max });
}

test('score is the share of applicable points earned', () => {
  const g = grade([pass('a', 'headers', 10), fail('b', 'headers', 10, 'medium')]);
  assert.equal(g.score, 50);
});

test('skipped checks leave the denominator, so N/A neither helps nor hurts', () => {
  const withSkip = grade([
    pass('a', 'headers', 10),
    skipped({ id: 'b', title: 'b', dimension: 'email', reason: 'no mail', max: 40 }),
  ]);
  assert.equal(withSkip.score, 100, 'the skipped 40-point check must not drag the score down');
});

test('a critical failure caps the tier at uncertified regardless of score', () => {
  // 95 out of 100 points, but one critical control is failing.
  const g = grade([pass('good', 'headers', 95), fail('tls', 'transport', 5, 'critical')]);
  assert.ok(g.score >= 90);
  assert.equal(g.tier, 'uncertified');
  assert.equal(g.gated, true);
  assert.match(g.gateReason, /critical/i);
});

test('a high failure caps the tier at bronze', () => {
  const g = grade([pass('good', 'headers', 92), fail('h', 'headers', 8, 'high')]);
  assert.equal(g.scoreTier, 'gold', 'the score alone would be Gold');
  assert.equal(g.tier, 'bronze', 'but a high failure caps it');
  assert.equal(g.gated, true);
});

test('with no gated failures the tier follows the score', () => {
  const g = grade([pass('a', 'headers', 90), fail('b', 'headers', 10, 'low')]);
  assert.equal(g.gated, false);
  assert.equal(g.tier, 'gold');
});

test('the organisation grade follows the weakest asset, not the mean', () => {
  const strong = grade([pass('a', 'headers', 100)]);
  const weak = grade([fail('tls', 'transport', 100, 'critical')]);
  const roll = rollUp([
    { host: 'strong.example', grade: strong },
    { host: 'weak.example', grade: weak },
  ]);
  assert.equal(roll.tier, 'uncertified', 'one broken asset uncertifies the company');
  assert.equal(roll.weakest, 'weak.example');
});
