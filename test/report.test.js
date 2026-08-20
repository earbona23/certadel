/**
 * The certificate and its outputs. The escaping test matters most: certificate fields
 * and Server banners are attacker-controllable, and the report must render them as text.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeReport, verificationCode } from '../src/report/serialize.js';
import { renderHtml } from '../src/report/html.js';
import { renderBadge } from '../src/report/badge.js';
import { renderTerminal } from '../src/report/terminal.js';
import { grade } from '../src/scoring/grade.js';
import { result } from '../src/util/model.js';

function assessment(host, results) {
  return { host, results, grade: grade(results), evidence: {}, notes: [] };
}
const scope = { organization: 'Acme Ltd', assets: ['a.example', 'b.example'], authorizedBy: 'ciso@acme' };

const xssResults = [
  result({
    id: 'header-version-disclosure', title: 'Server does not advertise versions',
    dimension: 'headers', status: 'warn', severity: 'low', max: 3,
    detail: 'Version disclosed: <script>alert(1)</script>',
    evidence: { server: '<img src=x onerror=alert(1)>' },
  }),
  result({ id: 'tls-available', title: 'HTTPS is served', dimension: 'transport', status: 'pass', max: 40 }),
];

test('the HTML certificate is a complete, self-contained document', () => {
  const report = serializeReport(scope, [assessment('a.example', xssResults)], { generatedAt: '2026-03-01T00:00:00Z' });
  const html = renderHtml(report);
  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /<\/html>\s*$/);
  // Nothing loaded from the network.
  assert.doesNotMatch(html, /<script[^>]+src=/i);
  assert.doesNotMatch(html, /<link[^>]+stylesheet/i);
  assert.doesNotMatch(html, /https?:\/\/[^"'\s]*\.(css|js|woff2?)/i);
});

test('tenant-controlled text is escaped, never executed', () => {
  const report = serializeReport(scope, [assessment('a.example', xssResults)], { generatedAt: '2026-03-01T00:00:00Z' });
  const html = renderHtml(report);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<img src=x onerror/);
});

test('the certificate states it is a self-assessment, not an accredited audit', () => {
  const report = serializeReport(scope, [assessment('a.example', xssResults)]);
  const html = renderHtml(report);
  assert.match(html, /self-assessment/i);
  assert.match(html, /not an accredited audit/i);
});

test('the verification code is stable across timestamps but changes with posture', () => {
  const r1 = serializeReport(scope, [assessment('a.example', xssResults)], { generatedAt: '2026-01-01T00:00:00Z' });
  const r2 = serializeReport(scope, [assessment('a.example', xssResults)], { generatedAt: '2026-09-09T00:00:00Z' });
  assert.equal(r1.verificationCode, r2.verificationCode, 'timestamp must not affect the code');
  assert.match(r1.verificationCode, /^CERTADEL(-[0-9A-F]{4}){3}$/);

  const worse = [result({ id: 'tls-available', title: 'x', dimension: 'transport', status: 'fail', severity: 'critical', max: 40 })];
  const r3 = serializeReport(scope, [assessment('a.example', worse)]);
  assert.notEqual(r1.verificationCode, r3.verificationCode, 'a posture change must change the code');
});

test('the badge is valid standalone SVG carrying the tier', () => {
  const svg = renderBadge({ tier: 'gold', score: 88 });
  assert.match(svg, /^<svg[\s\S]+<\/svg>$/);
  assert.match(svg, /Gold/);
  // No external RESOURCES are referenced (the SVG namespace URI is not a fetch).
  assert.doesNotMatch(svg, /<image\b/i);
  assert.doesNotMatch(svg, /xlink:href/i);
});

test('the terminal summary shows the gate when a high score is capped', () => {
  // High score (90/100) but one critical failure, so the gate demotes it to uncertified
  // and the summary must say so -- a capped grade must never read as a passing one.
  const capped = [
    result({ id: 'good', title: 'lots of good', dimension: 'headers', status: 'pass', max: 90 }),
    result({ id: 'tls-available', title: 'HTTPS is served', dimension: 'transport', status: 'fail', severity: 'critical', max: 10 }),
  ];
  const report = serializeReport(scope, [assessment('a.example', capped)]);
  const text = renderTerminal(report, { color: false });
  assert.match(text, /Not certified/);
  assert.match(text, /capped/i);
});
