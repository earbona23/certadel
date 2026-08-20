/**
 * Cookie-flag checks. Reads Set-Cookie from the main HTTPS response and grades whether
 * each cookie is protected against interception (Secure), theft via script (HttpOnly),
 * and cross-site sending (SameSite).
 *
 * @module checks/cookies
 */

import { result, skipped } from '../util/model.js';
import { parseSetCookie } from '../util/parse.js';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function cookieChecks(ev) {
  const cookies = ev.https?.setCookie ?? [];
  if (cookies.length === 0) {
    // A site that sets no cookies has nothing to get wrong here. Skipped, not passed,
    // so it neither earns nor loses the dimension's points.
    return [
      skipped({
        id: 'cookies-none',
        title: 'Cookie security flags',
        dimension: 'cookies',
        reason: 'The main response set no cookies, so there are no cookie flags to grade.',
        max: 0,
      }),
    ];
  }

  const parsed = cookies.map(parseSetCookie);
  const insecure = parsed.filter((c) => !c.secure);
  const scriptable = parsed.filter((c) => !c.httpOnly);
  const crossSite = parsed.filter((c) => c.sameSite === null || c.sameSite === 'none');

  return [
    flag(
      'cookie-secure',
      'Cookies are marked Secure',
      insecure,
      parsed,
      'high',
      8,
      'Add the Secure attribute so cookies are never sent over plaintext HTTP.',
    ),
    flag(
      'cookie-httponly',
      'Session cookies are marked HttpOnly',
      scriptable,
      parsed,
      'medium',
      8,
      'Add HttpOnly to cookies that scripts do not need to read, so an XSS flaw cannot ' +
        'steal them.',
    ),
    flag(
      'cookie-samesite',
      'Cookies set an explicit SameSite policy',
      crossSite,
      parsed,
      'medium',
      6,
      'Set SameSite=Lax or Strict to blunt cross-site request forgery.',
    ),
  ];
}

/**
 * @param {string} id
 * @param {string} title
 * @param {ReturnType<import('../util/parse.js').parseSetCookie>[]} offending
 * @param {ReturnType<import('../util/parse.js').parseSetCookie>[]} all
 * @param {import('../util/model.js').Severity} severity
 * @param {number} max
 * @param {string} remediation
 */
function flag(id, title, offending, all, severity, max, remediation) {
  const ok = offending.length === 0;
  return result({
    id,
    title,
    dimension: 'cookies',
    status: ok ? 'pass' : 'fail',
    severity: ok ? 'info' : severity,
    max,
    detail: ok
      ? `All ${all.length} cookie(s) satisfy this flag.`
      : `${offending.length} of ${all.length} cookie(s) miss it: ${offending
          .map((c) => c.name)
          .join(', ')}.`,
    remediation: ok ? undefined : remediation,
    reference: 'https://developer.mozilla.org/docs/Web/HTTP/Cookies',
    evidence: { offending: offending.map((c) => c.name), total: all.length },
  });
}
