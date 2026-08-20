/**
 * The authorization gate. certadel will not touch a host that is not written down here.
 *
 * Passive as this tool is, an external assessment is still something you run against
 * infrastructure, and running it against infrastructure you do not control is not your
 * call to make. The scope file is how consent is made explicit and auditable: it names
 * the organisation and the exact hosts you are authorized to assess, and the collector
 * refuses every host that is not on the list. There is no `--all`, no wildcard that
 * expands to "the internet", and no flag to skip this check.
 *
 * This is the safety analogue of a read-only guarantee: the boundary is enforced in
 * code and covered by tests, not promised in a sentence.
 *
 * @module scope
 */

import { readFile } from 'node:fs/promises';

/**
 * @typedef {Object} Scope
 * @property {string} organization   The entity being assessed, shown on the certificate.
 * @property {string[]} assets       Authorized hostnames (apex domains or hostnames).
 * @property {string} [authorizedBy] Who authorized the assessment. Recorded, not verified.
 * @property {string} [reference]    A ticket or engagement id. Recorded, not verified.
 */

// Accepts a single-label host (e.g. an internal 'intranet' or 'localhost') as well as
// a dotted FQDN. Each label is 1-63 chars and may not begin or end with a hyphen. IPs,
// URLs, ports and wildcards are rejected earlier, before this pattern is consulted.
const HOSTNAME_RE =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/**
 * Read and validate a scope file. Throws on anything that would let the tool reach
 * further than intended -- a missing asset list, a malformed hostname, a URL or an IP
 * range where a hostname belongs.
 *
 * @param {string} path
 * @returns {Promise<Scope>}
 */
export async function loadScope(path) {
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    throw new ScopeError(`Could not read the scope file '${path}': ${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ScopeError(`The scope file '${path}' is not valid JSON: ${err.message}`);
  }

  return normalizeScope(parsed, path);
}

/**
 * Validate an already-parsed scope object. Separated from file reading so it can be
 * exercised directly and so callers can supply a scope programmatically.
 *
 * @param {unknown} parsed
 * @param {string} [source] Label used in error messages.
 * @returns {Scope}
 */
export function normalizeScope(parsed, source = 'scope') {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ScopeError(`The scope (${source}) must be a JSON object.`);
  }

  const org = /** @type {any} */ (parsed).organization;
  if (typeof org !== 'string' || org.trim() === '') {
    throw new ScopeError(
      `The scope (${source}) must name the 'organization' being assessed. ` +
        'This appears on the certificate and forces you to say whose posture this is.',
    );
  }

  const assetsRaw = /** @type {any} */ (parsed).assets;
  if (!Array.isArray(assetsRaw) || assetsRaw.length === 0) {
    throw new ScopeError(
      `The scope (${source}) must list at least one authorized host in 'assets'. ` +
        'certadel never assesses a host you did not explicitly authorize.',
    );
  }

  const assets = [];
  const seen = new Set();
  for (const entry of assetsRaw) {
    const host = validateAsset(entry, source);
    if (!seen.has(host)) {
      seen.add(host);
      assets.push(host);
    }
  }

  return {
    organization: org.trim(),
    assets,
    authorizedBy:
      typeof (/** @type {any} */ (parsed).authorizedBy) === 'string'
        ? /** @type {any} */ (parsed).authorizedBy.trim()
        : undefined,
    reference:
      typeof (/** @type {any} */ (parsed).reference) === 'string'
        ? /** @type {any} */ (parsed).reference.trim()
        : undefined,
  };
}

/**
 * Reduce one asset entry to a bare, validated hostname.
 *
 * Rejects the shapes that would quietly widen scope: a URL (which carries a path and
 * could be mistaken for permission to crawl), an IP address or CIDR range (assessing
 * by address is a different authorization than assessing a named host), a wildcard,
 * or a port. What you authorize is a host, spelled out.
 *
 * @param {unknown} entry
 * @param {string} source
 * @returns {string} lower-cased hostname
 */
export function validateAsset(entry, source = 'scope') {
  if (typeof entry !== 'string' || entry.trim() === '') {
    throw new ScopeError(`Every asset in ${source} must be a non-empty hostname string.`);
  }
  const host = entry.trim().toLowerCase();

  if (host.includes('/') || host.includes(':')) {
    throw new ScopeError(
      `Asset '${entry}' looks like a URL, port or CIDR range. List a bare hostname ` +
        "such as 'example.com' or 'api.example.com'. certadel decides for itself which " +
        'endpoints to inspect on that host, and inspects only public configuration.',
    );
  }
  if (host.includes('*')) {
    throw new ScopeError(
      `Asset '${entry}' contains a wildcard. Authorization must name each host ` +
        'explicitly; a wildcard is an invitation to reach further than intended.',
    );
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    throw new ScopeError(
      `Asset '${entry}' is an IP address. Assess named hosts, not addresses.`,
    );
  }
  if (!HOSTNAME_RE.test(host)) {
    throw new ScopeError(`Asset '${entry}' is not a valid hostname.`);
  }
  return host;
}

/**
 * The enforcement point. Given a validated scope, returns a predicate that the network
 * layer consults before every single connection. A host is in scope if it is an
 * authorized asset or a subdomain of one -- so authorizing `example.com` also permits
 * `mta-sts.example.com`, which the email checks legitimately need, but never permits an
 * unrelated domain.
 *
 * @param {Scope} scope
 * @returns {(host: string) => boolean}
 */
export function scopeGuard(scope) {
  const authorized = scope.assets.map((h) => h.toLowerCase());
  return (host) => {
    if (typeof host !== 'string') return false;
    const h = host.trim().toLowerCase().replace(/\.$/, '');
    if (!h) return false;
    return authorized.some((a) => h === a || h.endsWith(`.${a}`));
  };
}

/** Error type for anything wrong with a scope, so callers can present it cleanly. */
export class ScopeError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'ScopeError';
  }
}
