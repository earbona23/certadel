/**
 * Small, dependency-free parsers for the header and record formats the checks read.
 *
 * Each is intentionally lenient about whitespace and case, because real-world servers
 * and DNS operators are, and strict about the one thing that decides a finding, because
 * that is what the grade turns on.
 *
 * @module util/parse
 */

/**
 * Read a single header value, collapsing the array form Node uses for repeated headers.
 * @param {Record<string, string | string[]> | undefined} headers
 * @param {string} name
 * @returns {string | undefined}
 */
export function header(headers, name) {
  if (!headers) return undefined;
  const v = headers[name.toLowerCase()];
  if (Array.isArray(v)) return v.join(', ');
  return v;
}

/**
 * Parse a Strict-Transport-Security value.
 * @param {string | undefined} value
 * @returns {{ present: boolean, maxAge: number | null, includeSubDomains: boolean, preload: boolean }}
 */
export function parseHsts(value) {
  if (!value) return { present: false, maxAge: null, includeSubDomains: false, preload: false };
  const lower = value.toLowerCase();
  const maxAgeMatch = lower.match(/max-age\s*=\s*"?(\d+)"?/);
  return {
    present: true,
    maxAge: maxAgeMatch ? Number(maxAgeMatch[1]) : null,
    includeSubDomains: /includesubdomains/.test(lower),
    preload: /preload/.test(lower),
  };
}

/**
 * Parse a Content-Security-Policy into a directive map and flag the weakenings that
 * matter most: a script-src (or default-src) that allows inline script or is wide open.
 * @param {string | undefined} value
 */
export function parseCsp(value) {
  if (!value) return { present: false, directives: {}, weaknesses: [] };
  /** @type {Record<string, string[]>} */
  const directives = {};
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1).map((t) => t.toLowerCase());
  }
  const scriptSrc = directives['script-src'] ?? directives['default-src'] ?? [];
  const weaknesses = [];
  if (scriptSrc.includes("'unsafe-inline'")) weaknesses.push("script-src allows 'unsafe-inline'");
  if (scriptSrc.includes("'unsafe-eval'")) weaknesses.push("script-src allows 'unsafe-eval'");
  if (scriptSrc.includes('*')) weaknesses.push('script-src allows any host (*)');
  if (!('object-src' in directives) && !('default-src' in directives))
    weaknesses.push('no object-src or default-src to restrict plugins');
  const hasFrameAncestors = 'frame-ancestors' in directives;
  return { present: true, directives, weaknesses, scriptSrc, hasFrameAncestors };
}

/**
 * Parse one Set-Cookie line into its name and the security-relevant flags.
 * @param {string} raw
 */
export function parseSetCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = nameValue.split('=')[0].trim();
  const lowerAttrs = attrs.map((a) => a.toLowerCase());
  const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith('samesite='));
  return {
    name,
    secure: lowerAttrs.includes('secure'),
    httpOnly: lowerAttrs.includes('httponly'),
    sameSite: sameSiteAttr ? sameSiteAttr.split('=')[1].trim().toLowerCase() : null,
  };
}

/**
 * Parse a DMARC record into policy and reporting.
 * @param {string} record
 */
export function parseDmarc(record) {
  const tags = keyValueTags(record);
  return {
    version: tags.v ?? null,
    policy: tags.p ? tags.p.toLowerCase() : null,
    subdomainPolicy: tags.sp ? tags.sp.toLowerCase() : null,
    pct: tags.pct ? Number(tags.pct) : 100,
    rua: tags.rua ?? null,
    ruf: tags.ruf ?? null,
  };
}

/**
 * Parse an SPF record's mechanisms and its "all" qualifier, which decides whether
 * unlisted senders are rejected (`-all`), soft-failed (`~all`) or waved through (`?all`,
 * `+all`).
 * @param {string} record
 */
export function parseSpf(record) {
  const terms = record.trim().split(/\s+/);
  const allTerm = terms.find((t) => /all$/i.test(t));
  let qualifier = null;
  if (allTerm) {
    const q = allTerm[0];
    qualifier = '+-~?'.includes(q) ? q : '+';
  }
  const lookups = terms.filter((t) =>
    /^(\+|-|~|\?)?(include|a|mx|ptr|exists|redirect)[:=]?/i.test(t),
  ).length;
  return { qualifier, lookups, terms };
}

/**
 * Split a `k=v; k=v` style record into a tag map, lower-casing keys.
 * @param {string} record
 * @returns {Record<string, string>}
 */
export function keyValueTags(record) {
  /** @type {Record<string, string>} */
  const tags = {};
  for (const part of record.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().toLowerCase();
    const v = part.slice(idx + 1).trim();
    if (k) tags[k] = v;
  }
  return tags;
}
