/**
 * Assessment orchestration: gather the evidence for an asset (passively, within scope),
 * run the checks, grade the result; then do that for every asset in a scope and roll the
 * results into one company grade.
 *
 * The collection and the judgement are kept apart on purpose. Everything that touches
 * the network lives in `collectEvidence`; everything that decides a grade is pure over
 * the evidence object. That is what lets the entire check-and-score surface be tested
 * deterministically, with no network, against synthetic evidence -- and it is why a
 * failure to reach a host degrades into honest `skip`/`fail` results rather than a crash.
 *
 * @module assess
 */

import { inspectTls } from './net/tls.js';
import { collectDns, resolveTxt, checkDnssec } from './net/dns.js';
import { fetchResource } from './net/http.js';
import { scopeGuard } from './scope.js';
import { runChecks } from './checks/index.js';
import { grade } from './scoring/grade.js';

/**
 * @typedef {Object} AssetEvidence
 * @property {string} host
 * @property {import('./net/http.js').FetchResult | null} https
 * @property {string | null} httpsError
 * @property {import('./net/http.js').FetchResult | null} http
 * @property {import('./net/tls.js').TlsEvidence | null} tls
 * @property {import('./net/dns.js').DnsEvidence | null} dns
 * @property {string[]} dmarcTxt
 * @property {{ txt: string[], policyMode: string | null }} mtaSts
 * @property {string[]} tlsRpt
 * @property {{ selector: string, found: boolean }[]} dkim
 * @property {import('./net/http.js').FetchResult | null} securityTxt
 * @property {{ ok: boolean, authenticatedData: boolean | null, resolver: string, error?: string } | null} dnssec
 */

/** DKIM selectors published by common providers; a best-effort probe, never exhaustive. */
const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'default', 'dkim', 's1'];

/**
 * @typedef {Object} AssetAssessment
 * @property {string} host
 * @property {import('./util/model.js').CheckResult[]} results
 * @property {import('./scoring/grade.js').Grade} grade
 * @property {AssetEvidence} evidence
 * @property {string[]} notes
 */

/**
 * Collect passive evidence for a single host. Every network call is guarded by the
 * scope predicate, and every failure is caught and turned into an absence the checks
 * interpret, never a thrown error.
 *
 * @param {string} host
 * @param {(h: string) => boolean} inScope
 * @param {Object} [options]
 * @param {number} [options.timeout]
 * @param {boolean} [options.probeLegacyTls]
 * @param {boolean} [options.checkDnssec]
 * @param {string[]} [options.dkimSelectors]
 * @returns {Promise<AssetEvidence>}
 */
export async function collectEvidence(host, inScope, options = {}) {
  if (!inScope(host)) {
    throw new Error(
      `Refusing to assess '${host}': it is not in the authorized scope. This should ` +
        'never happen -- assets come from the scope file itself.',
    );
  }

  const timeout = options.timeout;
  const notes = [];

  const [httpsRes, httpRes, tls, dns] = await Promise.all([
    fetchResource(`https://${host}/`, { inScope, timeout }).catch((e) => {
      notes.push(`https fetch: ${e.message}`);
      return null;
    }),
    fetchResource(`http://${host}/`, { inScope, timeout }).catch(() => null),
    inspectTls(host, { timeout, probeLegacy: options.probeLegacyTls !== false }).catch(() => null),
    collectDns(host).catch(() => null),
  ]);

  // Email and hygiene evidence, at names derived from (and within) the host.
  const selectors = options.dkimSelectors ?? COMMON_DKIM_SELECTORS;
  const [dmarcTxt, mtaStsTxt, tlsRptTxt, dkim, securityTxt, dnssec] = await Promise.all([
    resolveTxt(`_dmarc.${host}`).catch(() => []),
    resolveTxt(`_mta-sts.${host}`).catch(() => []),
    resolveTxt(`_smtp._tls.${host}`).catch(() => []),
    probeDkim(host, selectors),
    fetchResource(`https://${host}/.well-known/security.txt`, { inScope, timeout }).catch(
      () => null,
    ),
    options.checkDnssec === false
      ? Promise.resolve(null)
      : checkDnssec(host).catch(() => null),
  ]);

  let mtaStsPolicyMode = null;
  if (mtaStsTxt.some((t) => /^v=stsv1/i.test(t.trim()))) {
    const policy = await fetchResource(`https://mta-sts.${host}/.well-known/mta-sts.txt`, {
      inScope,
      timeout,
    }).catch(() => null);
    if (policy && policy.status === 200) {
      const m = policy.body.match(/mode\s*:\s*(\w+)/i);
      mtaStsPolicyMode = m ? m[1].toLowerCase() : null;
    }
  }

  return {
    host,
    https: httpsRes,
    httpsError: httpsRes ? null : notes[0] ?? 'no HTTPS response',
    http: httpRes,
    tls,
    dns,
    dmarcTxt,
    mtaSts: { txt: mtaStsTxt, policyMode: mtaStsPolicyMode },
    tlsRpt: tlsRptTxt,
    dkim,
    securityTxt,
    dnssec,
  };
}

/**
 * @param {string} host
 * @param {string[]} selectors
 * @returns {Promise<{ selector: string, found: boolean }[]>}
 */
async function probeDkim(host, selectors) {
  return Promise.all(
    selectors.map(async (selector) => {
      const records = await resolveTxt(`${selector}._domainkey.${host}`).catch(() => []);
      return { selector, found: records.some((r) => /(^|;)\s*(v=dkim1|k=|p=)/i.test(r)) };
    }),
  );
}

/**
 * Assess a single host end to end: collect, check, grade.
 *
 * @param {string} host
 * @param {(h: string) => boolean} inScope
 * @param {Object} [options]
 * @returns {Promise<AssetAssessment>}
 */
export async function assessAsset(host, inScope, options = {}) {
  const evidence = await collectEvidence(host, inScope, options);
  const results = runChecks(evidence);
  return { host, results, grade: grade(results), evidence, notes: [] };
}

/**
 * Assess every asset in a scope. Assets are assessed sequentially by default so the tool
 * is a considerate guest on the networks it touches; raise `concurrency` for speed on
 * infrastructure you own.
 *
 * @param {import('./scope.js').Scope} scope
 * @param {Object} [options]
 * @param {number} [options.concurrency]
 * @param {number} [options.timeout]
 * @param {boolean} [options.probeLegacyTls]
 * @param {boolean} [options.checkDnssec]
 * @param {(host: string, index: number, total: number) => void} [options.onAssetStart]
 * @param {(assessment: AssetAssessment) => void} [options.onAssetDone]
 * @returns {Promise<AssetAssessment[]>}
 */
export async function assessScope(scope, options = {}) {
  const inScope = scopeGuard(scope);
  const concurrency = Math.max(1, options.concurrency ?? 1);
  /** @type {AssetAssessment[]} */
  const out = [];
  let index = 0;

  async function worker() {
    while (index < scope.assets.length) {
      const i = index++;
      const host = scope.assets[i];
      options.onAssetStart?.(host, i, scope.assets.length);
      const assessment = await assessAsset(host, inScope, options);
      out[i] = assessment;
      options.onAssetDone?.(assessment);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, scope.assets.length) }, worker));
  return out;
}
