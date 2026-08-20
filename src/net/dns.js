/**
 * DNS lookups the checks depend on.
 *
 * Most records come straight from the system resolver via node:dns. DNSSEC is the
 * exception: node:dns cannot report whether an answer was cryptographically validated,
 * so that one signal is obtained through a DNS-over-HTTPS query to a validating
 * resolver and read from the response's Authenticated Data flag. That is one deliberate
 * outbound call to a third-party resolver; when it cannot be made, the DNSSEC check
 * reports Skipped rather than guessing.
 *
 * @module net/dns
 */

import { Resolver } from 'node:dns/promises';
import { fetchResource } from './http.js';

/**
 * @typedef {Object} DnsEvidence
 * @property {string[]} a
 * @property {string[]} aaaa
 * @property {{ exchange: string, priority: number }[]} mx
 * @property {string[]} ns
 * @property {string[][]} txt              Root TXT records, each as chunks.
 * @property {{ critical: number, issue: string, value: string }[]} caa
 * @property {boolean} resolves
 */

const QUERY_TIMEOUT_MS = 8_000;

/**
 * Collect the base DNS records for a domain. Individual record types that do not exist
 * resolve to empty arrays rather than throwing, since "no CAA record" is itself a
 * finding, not an error.
 *
 * @param {string} domain
 * @returns {Promise<DnsEvidence>}
 */
export async function collectDns(domain) {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 2 });

  const [a, aaaa, mx, ns, txt, caa] = await Promise.all([
    safe(() => resolver.resolve4(domain), []),
    safe(() => resolver.resolve6(domain), []),
    safe(() => resolver.resolveMx(domain), []),
    safe(() => resolver.resolveNs(domain), []),
    safe(() => resolver.resolveTxt(domain), []),
    safe(() => resolver.resolveCaa(domain), []),
  ]);

  return {
    a,
    aaaa,
    mx: mx.map((m) => ({ exchange: m.exchange.toLowerCase(), priority: m.priority })),
    ns: ns.map((n) => n.toLowerCase()),
    txt,
    caa: caa.map((c) => ({
      critical: c.critical ?? 0,
      issue: c.issue ?? c.issuewild ?? c.iodef ?? '',
      value: c.issue ?? c.issuewild ?? c.iodef ?? '',
    })),
    resolves: a.length > 0 || aaaa.length > 0,
  };
}

/**
 * Resolve TXT records at a specific name (e.g. `_dmarc.example.com`), returning each
 * record as a single joined string. Absent records return an empty array.
 *
 * @param {string} name
 * @returns {Promise<string[]>}
 */
export async function resolveTxt(name) {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 2 });
  const records = await safe(() => resolver.resolveTxt(name), []);
  return records.map((chunks) => chunks.join(''));
}

/**
 * Ask a validating DNS-over-HTTPS resolver whether a name's answer is DNSSEC-validated,
 * by reading the AD (Authenticated Data) flag. Uses Cloudflare's resolver by default.
 *
 * @param {string} name
 * @param {Object} [options]
 * @param {string} [options.resolver] DoH JSON endpoint.
 * @param {(host: string) => boolean} [options.inScope]
 * @returns {Promise<{ ok: boolean, authenticatedData: boolean | null, resolver: string, error?: string }>}
 */
export async function checkDnssec(name, options = {}) {
  const endpoint = options.resolver ?? 'https://cloudflare-dns.com/dns-query';
  const resolverHost = new URL(endpoint).hostname;
  // The DoH resolver is infrastructure we query, not a target we assess, so it is
  // exempt from the target scope guard by design.
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=A&do=1`;
  try {
    const res = await fetchResource(url, {
      method: 'GET',
      inScope: (h) => h === resolverHost,
      timeout: QUERY_TIMEOUT_MS,
    });
    const parsed = JSON.parse(res.body);
    return {
      ok: true,
      authenticatedData: typeof parsed.AD === 'boolean' ? parsed.AD : false,
      resolver: resolverHost,
    };
  } catch (err) {
    return {
      ok: false,
      authenticatedData: null,
      resolver: resolverHost,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * @template T
 * @param {() => Promise<T>} fn
 * @param {T} fallback
 * @returns {Promise<T>}
 */
async function safe(fn, fallback) {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}
