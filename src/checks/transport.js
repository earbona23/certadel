/**
 * Transport-security checks. They read the TLS evidence gathered by net/tls.js and the
 * HSTS header from the HTTPS response, and judge whether the front door is built to a
 * modern standard.
 *
 * @module checks/transport
 */

import { result, skipped } from '../util/model.js';
import { header, parseHsts } from '../util/parse.js';

const REF_TLS = 'https://ssl-config.mozilla.org/';
const REF_HSTS = 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function transportChecks(ev) {
  const tls = ev.tls;

  if (!tls || !tls.connected) {
    // No TLS at all is not a low score on transport -- it is the absence of the wall.
    // A single fail carries the whole dimension and, being critical, gates the grade.
    return [
      result({
        id: 'tls-available',
        title: 'HTTPS is served',
        dimension: 'transport',
        status: 'fail',
        severity: 'critical',
        max: 40,
        detail: tls?.error
          ? `A TLS connection to port 443 could not be completed: ${tls.error}`
          : 'No HTTPS service answered on port 443.',
        remediation:
          'Serve the site over HTTPS with a valid certificate. Everything else in this ' +
          'dimension depends on it.',
        reference: REF_TLS,
        evidence: { error: tls?.error ?? 'no connection' },
      }),
    ];
  }

  return [
    checkProtocolVersions(tls),
    checkCertificateValidity(tls),
    checkCertificateExpiry(tls),
    checkKeyStrength(tls),
    checkForwardSecrecy(tls),
    checkHsts(ev),
  ];
}

/** @param {import('../net/tls.js').TlsEvidence} tls */
function checkProtocolVersions(tls) {
  const legacy = tls.legacyProtocols;
  if (!tls.legacyProbed) {
    return skipped({
      id: 'tls-protocol-versions',
      title: 'Obsolete TLS versions are disabled',
      dimension: 'transport',
      reason: 'Legacy-protocol probing was disabled for this run.',
      max: 10,
    });
  }
  if (legacy.length === 0) {
    return result({
      id: 'tls-protocol-versions',
      title: 'Obsolete TLS versions are disabled',
      dimension: 'transport',
      status: 'pass',
      max: 10,
      detail: `The host declined TLS 1.0 and 1.1; strongest negotiated was ${tls.protocol}.`,
      reference: REF_TLS,
      evidence: { strongest: tls.protocol, legacyAccepted: [] },
    });
  }
  const hasTls10 = legacy.includes('TLSv1');
  return result({
    id: 'tls-protocol-versions',
    title: 'Obsolete TLS versions are disabled',
    dimension: 'transport',
    status: 'fail',
    severity: hasTls10 ? 'critical' : 'high',
    max: 10,
    detail: `The host still negotiates ${legacy.join(' and ')}, deprecated and removable.`,
    remediation:
      'Disable TLS 1.0 and TLS 1.1 at the server or load balancer. Serve only TLS 1.2 ' +
      'and 1.3.',
    reference: REF_TLS,
    evidence: { legacyAccepted: legacy, strongest: tls.protocol },
  });
}

/** @param {import('../net/tls.js').TlsEvidence} tls */
function checkCertificateValidity(tls) {
  if (tls.authorized) {
    return result({
      id: 'tls-certificate-valid',
      title: 'Certificate chain is trusted and current',
      dimension: 'transport',
      status: 'pass',
      max: 12,
      detail: `Chain validated against system roots; issued by ${tls.certificate?.issuer ?? 'unknown'}.`,
      evidence: { issuer: tls.certificate?.issuer ?? null },
    });
  }
  return result({
    id: 'tls-certificate-valid',
    title: 'Certificate chain is trusted and current',
    dimension: 'transport',
    status: 'fail',
    severity: 'critical',
    max: 12,
    detail: `The certificate did not validate: ${tls.authorizationError}.`,
    remediation:
      'Install a certificate from a publicly trusted CA, include the full intermediate ' +
      'chain, and make sure it covers this hostname and is not expired.',
    reference: REF_TLS,
    evidence: { authorizationError: tls.authorizationError },
  });
}

/** @param {import('../net/tls.js').TlsEvidence} tls */
function checkCertificateExpiry(tls) {
  const validTo = tls.certificate?.validTo ? new Date(tls.certificate.validTo) : null;
  if (!validTo || Number.isNaN(validTo.getTime())) {
    return skipped({
      id: 'tls-certificate-expiry',
      title: 'Certificate is not near expiry',
      dimension: 'transport',
      reason: 'The certificate expiry date could not be read.',
      max: 4,
    });
  }
  const days = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
  if (days < 0) {
    return result({
      id: 'tls-certificate-expiry',
      title: 'Certificate is not near expiry',
      dimension: 'transport',
      status: 'fail',
      severity: 'critical',
      max: 4,
      detail: `The certificate expired ${Math.abs(days)} day(s) ago.`,
      remediation: 'Renew the certificate immediately and automate renewal.',
      evidence: { validTo: tls.certificate?.validTo, daysRemaining: days },
    });
  }
  if (days < 21) {
    return result({
      id: 'tls-certificate-expiry',
      title: 'Certificate is not near expiry',
      dimension: 'transport',
      status: 'warn',
      severity: 'medium',
      max: 4,
      detail: `The certificate expires in ${days} day(s).`,
      remediation: 'Renew ahead of expiry and automate renewal so this never approaches zero.',
      evidence: { validTo: tls.certificate?.validTo, daysRemaining: days },
    });
  }
  return result({
    id: 'tls-certificate-expiry',
    title: 'Certificate is not near expiry',
    dimension: 'transport',
    status: 'pass',
    max: 4,
    detail: `The certificate is valid for another ${days} day(s).`,
    evidence: { validTo: tls.certificate?.validTo, daysRemaining: days },
  });
}

/** @param {import('../net/tls.js').TlsEvidence} tls */
function checkKeyStrength(tls) {
  const cert = tls.certificate;
  if (!cert || !cert.keyType) {
    return skipped({
      id: 'tls-key-strength',
      title: 'Certificate key meets modern strength',
      dimension: 'transport',
      reason: 'The certificate key type could not be determined.',
      max: 6,
    });
  }
  const strong =
    (cert.keyType === 'RSA' && (cert.keyBits ?? 0) >= 2048) ||
    (cert.keyType === 'EC' && (cert.keyBits ?? 0) >= 256);
  return result({
    id: 'tls-key-strength',
    title: 'Certificate key meets modern strength',
    dimension: 'transport',
    status: strong ? 'pass' : 'fail',
    severity: strong ? 'info' : 'high',
    max: 6,
    detail: `${cert.keyType} key of ${cert.keyBits ?? '?'} bits.`,
    remediation: strong
      ? undefined
      : 'Reissue with at least a 2048-bit RSA or 256-bit ECDSA key.',
    evidence: { keyType: cert.keyType, keyBits: cert.keyBits },
  });
}

/** @param {import('../net/tls.js').TlsEvidence} tls */
function checkForwardSecrecy(tls) {
  const cipher = tls.cipherName ?? '';
  const isTls13 = tls.protocol === 'TLSv1.3';
  const ecdhe = /ECDHE/i.test(cipher) || /^TLS_/.test(cipher);
  const fs = isTls13 || ecdhe;
  return result({
    id: 'tls-forward-secrecy',
    title: 'Negotiated cipher provides forward secrecy',
    dimension: 'transport',
    status: fs ? 'pass' : 'warn',
    severity: fs ? 'info' : 'medium',
    max: 4,
    detail: `Negotiated ${tls.protocol} with ${cipher || 'an unknown cipher'}.`,
    remediation: fs
      ? undefined
      : 'Prefer ECDHE cipher suites (or TLS 1.3) so a future key compromise cannot ' +
        'decrypt past traffic.',
    evidence: { protocol: tls.protocol, cipher },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkHsts(ev) {
  const value = header(ev.https?.headers, 'strict-transport-security');
  const hsts = parseHsts(value);
  if (!hsts.present) {
    return result({
      id: 'tls-hsts',
      title: 'HSTS is enabled with a durable max-age',
      dimension: 'transport',
      status: 'fail',
      severity: 'medium',
      max: 4,
      detail: 'No Strict-Transport-Security header was returned over HTTPS.',
      remediation:
        'Send Strict-Transport-Security with a max-age of at least 15552000 (180 days) ' +
        'and includeSubDomains once every subdomain is HTTPS-ready.',
      reference: REF_HSTS,
      evidence: { present: false },
    });
  }
  const sixMonths = 15_552_000;
  const durable = (hsts.maxAge ?? 0) >= sixMonths;
  return result({
    id: 'tls-hsts',
    title: 'HSTS is enabled with a durable max-age',
    dimension: 'transport',
    status: durable ? 'pass' : 'warn',
    severity: durable ? 'info' : 'low',
    max: 4,
    detail: durable
      ? `HSTS present with max-age ${hsts.maxAge}${hsts.includeSubDomains ? ', includeSubDomains' : ''}${hsts.preload ? ', preload' : ''}.`
      : `HSTS present but max-age is only ${hsts.maxAge}.`,
    remediation: durable ? undefined : 'Raise HSTS max-age to at least 15552000 (180 days).',
    reference: REF_HSTS,
    evidence: hsts,
  });
}
