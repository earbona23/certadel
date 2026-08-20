#!/usr/bin/env node
/**
 * Renders the sample certificate shown in the README, from synthetic evidence run
 * through the real check-and-score pipeline.
 *
 * Everything here is invented -- fictional hosts in a reserved example space, no real
 * certificate, no real DNS. But the evidence is fed through the same runChecks() and
 * grade() the tool uses on a live target, so the sample is laid out and scored exactly
 * as a real report would be. No network is touched and no real data appears.
 *
 * Usage: node examples/generate-sample.js [outDir]
 */
import { writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runChecks } from '../src/checks/index.js';
import { grade } from '../src/scoring/grade.js';
import { serializeReport } from '../src/report/serialize.js';
import { renderHtml } from '../src/report/html.js';
import { renderBadge } from '../src/report/badge.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const outDir = process.argv[2] || join(HERE, '..', 'docs', 'images');

// Relative to now so the sample certificate is always genuinely valid; the tier and
// score depend on status, not on the exact dates, so the sample stays stable.
const future = (days) => new Date(Date.now() + days * 86400000).toISOString();

function strongEvidence(host) {
  return {
    host,
    https: {
      status: 200,
      headers: {
        'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'geolocation=(), camera=(), microphone=()',
        'content-type': 'text/html; charset=utf-8',
      },
      setCookie: ['session=redacted; Secure; HttpOnly; SameSite=Lax'],
      body: '<!doctype html><title>Example</title>',
      truncated: false,
      redirects: [],
    },
    httpsError: null,
    http: { url: `https://${host}/`, redirects: [{ status: 301 }], status: 200, headers: {}, setCookie: [], body: '', truncated: false },
    tls: {
      connected: true, protocol: 'TLSv1.3', cipherName: 'TLS_AES_256_GCM_SHA384',
      authorized: true, authorizationError: null, legacyProbed: true, legacyProtocols: [],
      certificate: { issuer: "Let's Encrypt", subjectCommonName: host, validFrom: future(-30),
        validTo: future(70), altNames: [host], keyType: 'EC', keyBits: 256, curve: 'prime256v1' },
    },
    dns: {
      a: ['203.0.113.10'], aaaa: ['2001:db8::10'],
      mx: [{ exchange: 'mail.northwind.example', priority: 10 }],
      ns: ['ns1.northwind.example', 'ns2.northwind.example'],
      txt: [['v=spf1 include:_spf.northwind.example -all']],
      caa: [{ critical: 0, issue: 'letsencrypt.org', value: 'letsencrypt.org' }], resolves: true,
    },
    dmarcTxt: ['v=DMARC1; p=reject; rua=mailto:dmarc@northwind.example'],
    mtaSts: { txt: ['v=STSv1; id=2026'], policyMode: 'enforce' },
    tlsRpt: ['v=TLSRPTv1; rua=mailto:tlsrpt@northwind.example'],
    dkim: [{ selector: 'google', found: true }],
    securityTxt: { status: 200, headers: {}, body: 'Contact: mailto:security@northwind.example\nExpires: 2027-01-01T00:00:00Z\n', truncated: false, setCookie: [], redirects: [] },
    dnssec: { ok: true, authenticatedData: true, resolver: 'cloudflare-dns.com' },
  };
}

function silverEvidence(host) {
  const ev = strongEvidence(host);
  delete ev.https.headers['permissions-policy'];
  ev.https.headers['content-security-policy'] = "script-src 'self' 'unsafe-inline'; object-src 'none'";
  ev.https.headers['server'] = 'nginx/1.24.0';
  ev.dmarcTxt = ['v=DMARC1; p=quarantine; rua=mailto:dmarc@northwind.example'];
  ev.dnssec = { ok: true, authenticatedData: false, resolver: 'cloudflare-dns.com' };
  ev.securityTxt = null;
  return ev;
}

function bronzeEvidence(host) {
  const ev = strongEvidence(host);
  // Missing CSP is a high-severity gap that caps this host at Bronze no matter its
  // score; a few other headers are present so it still clears the Bronze floor.
  ev.https.headers = {
    'strict-transport-security': 'max-age=15552000',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'x-frame-options': 'SAMEORIGIN',
    'content-type': 'text/html',
  };
  ev.https.setCookie = ['tracker=1; Secure; Path=/'];
  ev.tls.protocol = 'TLSv1.2';
  ev.tls.cipherName = 'ECDHE-RSA-AES128-GCM-SHA256';
  ev.tls.certificate.keyType = 'RSA';
  ev.tls.certificate.keyBits = 2048;
  ev.dns.caa = [];
  ev.dmarcTxt = [];
  ev.dns.txt = [];
  ev.mtaSts = { txt: [], policyMode: null };
  ev.tlsRpt = [];
  ev.dkim = [{ selector: 'google', found: false }];
  ev.securityTxt = null;
  ev.dnssec = { ok: true, authenticatedData: false, resolver: 'cloudflare-dns.com' };
  return ev;
}

function assess(host, evidence) {
  const results = runChecks(evidence);
  return { host, results, grade: grade(results), evidence, notes: [] };
}

const scope = {
  organization: 'Northwind Retail Group',
  authorizedBy: 'ciso@northwind.example',
  reference: 'ENG-2026-014',
  assets: ['shop.northwind.example', 'api.northwind.example', 'blog.northwind.example'],
};

const assessments = [
  assess('shop.northwind.example', strongEvidence('shop.northwind.example')),
  assess('api.northwind.example', silverEvidence('api.northwind.example')),
  assess('blog.northwind.example', bronzeEvidence('blog.northwind.example')),
];

const report = serializeReport(scope, assessments, {
  toolVersion: '1.0.0',
  generatedAt: '2026-03-14T09:41:00Z',
});

await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'sample-certificate.html'), renderHtml(report));
await writeFile(join(outDir, 'sample-report.json'), JSON.stringify(report, null, 2) + '\n');
await writeFile(join(outDir, 'sample-badge.svg'), renderBadge({ tier: report.rollup.tier, score: report.rollup.score }));

console.log(`Wrote sample certificate to ${outDir}`);
console.log(`Org grade: ${report.rollup.tierLabel} (${report.rollup.score}), weakest: ${report.rollup.weakest}`);
for (const a of report.assets) console.log(`  ${a.host}: ${a.tierLabel} ${a.score}`);
