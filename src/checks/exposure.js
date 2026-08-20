/**
 * Exposure and hygiene checks: does plain HTTP redirect to HTTPS, is there a valid
 * security.txt telling researchers how to report a problem, and does the homepage pull
 * any resources over insecure HTTP.
 *
 * @module checks/exposure
 */

import { result, skipped } from '../util/model.js';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function exposureChecks(ev) {
  return [checkHttpsRedirect(ev), checkSecurityTxt(ev), checkMixedContent(ev)];
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkHttpsRedirect(ev) {
  if (!ev.http) {
    return skipped({
      id: 'exposure-https-redirect',
      title: 'Plain HTTP redirects to HTTPS',
      dimension: 'exposure',
      reason: 'No plain-HTTP response was available to judge the redirect.',
      max: 4,
    });
  }
  const finalUrl = ev.http.url;
  const endedHttps = finalUrl.startsWith('https://');
  const redirected = ev.http.redirects.length > 0;
  const ok = endedHttps;
  return result({
    id: 'exposure-https-redirect',
    title: 'Plain HTTP redirects to HTTPS',
    dimension: 'exposure',
    status: ok ? 'pass' : 'fail',
    severity: ok ? 'info' : 'medium',
    max: 4,
    detail: ok
      ? `An HTTP request was redirected to ${finalUrl}.`
      : 'An HTTP request was served without redirecting to HTTPS.',
    remediation: ok
      ? undefined
      : 'Redirect all plain-HTTP requests to HTTPS with a 301, so no request is ever ' +
        'answered in the clear.',
    reference: 'https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security',
    evidence: { finalUrl, redirected },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkSecurityTxt(ev) {
  const res = ev.securityTxt;
  if (!res || res.status !== 200 || !res.body) {
    return result({
      id: 'exposure-security-txt',
      title: 'A security.txt tells researchers how to report issues',
      dimension: 'exposure',
      status: 'warn',
      severity: 'low',
      max: 3,
      detail: 'No security.txt was served at /.well-known/security.txt.',
      remediation:
        'Publish /.well-known/security.txt with at least a Contact and an Expires field ' +
        '(RFC 9116), so anyone who finds a flaw knows how to reach you.',
      reference: 'https://www.rfc-editor.org/rfc/rfc9116',
      evidence: { present: false },
    });
  }
  // security.txt fields are colon-delimited ('Contact: mailto:...'), not 'k=v'.
  const fields = new Set();
  for (const line of res.body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf(':');
    if (idx > 0) fields.add(trimmed.slice(0, idx).trim().toLowerCase());
  }
  const hasContact = fields.has('contact');
  const hasExpires = fields.has('expires');
  const ok = hasContact && hasExpires;
  return result({
    id: 'exposure-security-txt',
    title: 'A security.txt tells researchers how to report issues',
    dimension: 'exposure',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 3,
    detail: ok
      ? 'A security.txt is present with Contact and Expires fields.'
      : `security.txt is present but incomplete (missing ${[
          !hasContact ? 'Contact' : null,
          !hasExpires ? 'Expires' : null,
        ]
          .filter(Boolean)
          .join(' and ')}).`,
    remediation: ok ? undefined : 'Add the required Contact and Expires fields per RFC 9116.',
    reference: 'https://www.rfc-editor.org/rfc/rfc9116',
    evidence: { hasContact, hasExpires },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkMixedContent(ev) {
  const res = ev.https;
  if (!res || !res.body || res.truncated === undefined) {
    return skipped({
      id: 'exposure-mixed-content',
      title: 'The homepage loads no resources over plain HTTP',
      dimension: 'exposure',
      reason: 'No HTML body was available to inspect for mixed content.',
      max: 3,
    });
  }
  if (!/text\/html/i.test(String(res.headers['content-type'] ?? ''))) {
    return skipped({
      id: 'exposure-mixed-content',
      title: 'The homepage loads no resources over plain HTTP',
      dimension: 'exposure',
      reason: 'The root response was not HTML, so there is no page markup to inspect.',
      max: 3,
    });
  }
  // Look only for active-content references over http:// (script/link/iframe/img src).
  const matches = [
    ...res.body.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi),
  ].map((m) => m[1]);
  const external = matches.filter((u) => !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(u));
  const ok = external.length === 0;
  return result({
    id: 'exposure-mixed-content',
    title: 'The homepage loads no resources over plain HTTP',
    dimension: 'exposure',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'medium',
    max: 3,
    detail: ok
      ? 'No plain-HTTP resource references were found in the homepage markup.'
      : `${external.length} resource reference(s) use http:// and would be blocked or ` +
        'downgrade security.',
    remediation: ok
      ? undefined
      : 'Serve every subresource over HTTPS. Mixed content is blocked by browsers and ' +
        'undermines the padlock.',
    reference: 'https://developer.mozilla.org/docs/Web/Security/Mixed_content',
    evidence: { references: external.slice(0, 10), truncatedBody: res.truncated },
  });
}
