/**
 * HTTP security-header checks. They read the headers of the main HTTPS response and
 * grade the browser-facing defences: content policy, MIME sniffing, framing, referrer
 * leakage, feature permissions, and whether the server advertises its own version.
 *
 * @module checks/headers
 */

import { result, skipped } from '../util/model.js';
import { header, parseCsp } from '../util/parse.js';

const REF = 'https://developer.mozilla.org/docs/Web/HTTP/Headers';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function headerChecks(ev) {
  const res = ev.https;
  if (!res) {
    return [
      skipped({
        id: 'headers-unavailable',
        title: 'HTTP security headers',
        dimension: 'headers',
        reason: 'No HTTPS response was available to read headers from.',
        max: 0,
      }),
    ];
  }
  const h = res.headers;
  return [
    checkCsp(h),
    checkContentTypeOptions(h),
    checkFraming(h),
    checkReferrerPolicy(h),
    checkPermissionsPolicy(h),
    checkServerBanner(h),
  ];
}

/** @param {Record<string, string | string[]>} h */
function checkCsp(h) {
  const csp = parseCsp(header(h, 'content-security-policy'));
  if (!csp.present) {
    return result({
      id: 'header-csp',
      title: 'Content-Security-Policy is present',
      dimension: 'headers',
      status: 'fail',
      severity: 'high',
      max: 7,
      detail: 'No Content-Security-Policy header was returned.',
      remediation:
        'Add a Content-Security-Policy. Even a conservative policy that sets ' +
        "default-src 'self' and object-src 'none' materially reduces XSS impact.",
      reference: `${REF}/Content-Security-Policy`,
      evidence: { present: false },
    });
  }
  if (csp.weaknesses.length > 0) {
    return result({
      id: 'header-csp',
      title: 'Content-Security-Policy is present',
      dimension: 'headers',
      status: 'warn',
      severity: 'medium',
      max: 7,
      detail: `CSP present but weakened: ${csp.weaknesses.join('; ')}.`,
      remediation:
        "Remove 'unsafe-inline' and 'unsafe-eval' from script-src and avoid wildcard " +
        'sources; adopt nonces or hashes for inline scripts.',
      reference: `${REF}/Content-Security-Policy`,
      evidence: { weaknesses: csp.weaknesses },
    });
  }
  return result({
    id: 'header-csp',
    title: 'Content-Security-Policy is present',
    dimension: 'headers',
    status: 'pass',
    max: 7,
    detail: 'A Content-Security-Policy is present with no obvious script-source weakening.',
    reference: `${REF}/Content-Security-Policy`,
    evidence: { directives: Object.keys(csp.directives) },
  });
}

/** @param {Record<string, string | string[]>} h */
function checkContentTypeOptions(h) {
  const value = (header(h, 'x-content-type-options') ?? '').toLowerCase();
  const ok = value === 'nosniff';
  return result({
    id: 'header-content-type-options',
    title: 'X-Content-Type-Options is nosniff',
    dimension: 'headers',
    status: ok ? 'pass' : 'fail',
    severity: ok ? 'info' : 'medium',
    max: 3,
    detail: ok ? 'nosniff is set.' : 'X-Content-Type-Options: nosniff is not set.',
    remediation: ok ? undefined : 'Send "X-Content-Type-Options: nosniff" on all responses.',
    reference: `${REF}/X-Content-Type-Options`,
    evidence: { value: value || null },
  });
}

/** @param {Record<string, string | string[]>} h */
function checkFraming(h) {
  const xfo = (header(h, 'x-frame-options') ?? '').toLowerCase();
  const csp = parseCsp(header(h, 'content-security-policy'));
  const protectedByCsp = csp.hasFrameAncestors;
  const protectedByXfo = xfo === 'deny' || xfo === 'sameorigin';
  const ok = protectedByCsp || protectedByXfo;
  return result({
    id: 'header-framing',
    title: 'Clickjacking protection is present',
    dimension: 'headers',
    status: ok ? 'pass' : 'fail',
    severity: ok ? 'info' : 'medium',
    max: 4,
    detail: ok
      ? `Framing is restricted via ${protectedByCsp ? 'CSP frame-ancestors' : 'X-Frame-Options'}.`
      : 'Neither CSP frame-ancestors nor a restrictive X-Frame-Options is set.',
    remediation: ok
      ? undefined
      : "Set CSP frame-ancestors 'self' (preferred) or X-Frame-Options: SAMEORIGIN.",
    reference: `${REF}/X-Frame-Options`,
    evidence: { xFrameOptions: xfo || null, cspFrameAncestors: protectedByCsp },
  });
}

/** @param {Record<string, string | string[]>} h */
function checkReferrerPolicy(h) {
  const value = (header(h, 'referrer-policy') ?? '').toLowerCase();
  const leaky = new Set(['', 'unsafe-url', 'no-referrer-when-downgrade']);
  const ok = value !== '' && !leaky.has(value);
  return result({
    id: 'header-referrer-policy',
    title: 'Referrer-Policy avoids leaking full URLs',
    dimension: 'headers',
    status: ok ? 'pass' : value === '' ? 'fail' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 3,
    detail: value ? `Referrer-Policy is "${value}".` : 'No Referrer-Policy header is set.',
    remediation: ok
      ? undefined
      : 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.',
    reference: `${REF}/Referrer-Policy`,
    evidence: { value: value || null },
  });
}

/** @param {Record<string, string | string[]>} h */
function checkPermissionsPolicy(h) {
  const value = header(h, 'permissions-policy') ?? header(h, 'feature-policy');
  const ok = Boolean(value);
  return result({
    id: 'header-permissions-policy',
    title: 'Permissions-Policy restricts powerful features',
    dimension: 'headers',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 3,
    detail: ok
      ? 'A Permissions-Policy header is present.'
      : 'No Permissions-Policy header is set.',
    remediation: ok
      ? undefined
      : 'Add a Permissions-Policy that disables features the site does not use ' +
        '(camera, microphone, geolocation, etc.).',
    reference: `${REF}/Permissions-Policy`,
    evidence: { present: ok },
  });
}

/** @param {Record<string, string | string[]>} h */
function checkServerBanner(h) {
  const server = header(h, 'server') ?? '';
  const poweredBy = header(h, 'x-powered-by') ?? '';
  const leaksVersion = /\d+\.\d+/.test(server) || poweredBy !== '';
  return result({
    id: 'header-version-disclosure',
    title: 'Server does not advertise software versions',
    dimension: 'headers',
    status: leaksVersion ? 'warn' : 'pass',
    severity: leaksVersion ? 'low' : 'info',
    max: 3,
    detail: leaksVersion
      ? `Version information is disclosed: ${[server, poweredBy].filter(Boolean).join('; ')}.`
      : 'No precise software versions are advertised in response headers.',
    remediation: leaksVersion
      ? 'Suppress version detail in the Server header and remove X-Powered-By. It hands ' +
        'an attacker a shortlist of version-specific exploits for free.'
      : undefined,
    reference: `${REF}/Server`,
    evidence: { server: server || null, xPoweredBy: poweredBy || null },
  });
}
