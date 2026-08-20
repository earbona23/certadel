/**
 * DNS and domain-hygiene checks: certificate-issuance control (CAA), authoritative
 * nameserver redundancy, and whether the zone is signed (DNSSEC).
 *
 * @module checks/dns
 */

import { result, skipped } from '../util/model.js';

const REF_CAA = 'https://developer.mozilla.org/docs/Web/Security/Practical_implementation_guides/CAA';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function dnsChecks(ev) {
  return [checkCaa(ev), checkNsRedundancy(ev), checkDnssec(ev)];
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkCaa(ev) {
  const caa = ev.dns?.caa ?? [];
  const ok = caa.length > 0;
  return result({
    id: 'dns-caa',
    title: 'A CAA record restricts certificate issuance',
    dimension: 'dns',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 4,
    detail: ok
      ? `CAA present, authorising: ${caa.map((c) => c.value).filter(Boolean).join(', ') || 'listed CAs'}.`
      : 'No CAA record was found, so any CA may issue certificates for this domain.',
    remediation: ok
      ? undefined
      : 'Publish a CAA record naming only the CAs you use, so no other CA can mis-issue ' +
        'a certificate for your domain.',
    reference: REF_CAA,
    evidence: { records: caa },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkNsRedundancy(ev) {
  const ns = ev.dns?.ns ?? [];
  if (ns.length === 0) {
    return skipped({
      id: 'dns-ns-redundancy',
      title: 'The domain has redundant nameservers',
      dimension: 'dns',
      reason: 'Nameserver records could not be read.',
      max: 3,
    });
  }
  const ok = ns.length >= 2;
  return result({
    id: 'dns-ns-redundancy',
    title: 'The domain has redundant nameservers',
    dimension: 'dns',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 3,
    detail: `${ns.length} authoritative nameserver(s) are published.`,
    remediation: ok
      ? undefined
      : 'Publish at least two authoritative nameservers so a single failure does not take ' +
        'the domain offline.',
    evidence: { nameservers: ns },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkDnssec(ev) {
  const d = ev.dnssec;
  if (!d || !d.ok) {
    return skipped({
      id: 'dns-dnssec',
      title: 'The zone is signed with DNSSEC',
      dimension: 'dns',
      reason: d?.error
        ? `DNSSEC validation could not be checked via the DoH resolver: ${d.error}.`
        : 'DNSSEC status was not checked.',
      max: 5,
    });
  }
  const ok = d.authenticatedData === true;
  return result({
    id: 'dns-dnssec',
    title: 'The zone is signed with DNSSEC',
    dimension: 'dns',
    status: ok ? 'pass' : 'warn',
    severity: ok ? 'info' : 'low',
    max: 5,
    detail: ok
      ? `A validating resolver (${d.resolver}) returned authenticated data for this zone.`
      : `The zone is not DNSSEC-validated according to ${d.resolver}.`,
    remediation: ok
      ? undefined
      : 'Enable DNSSEC signing at your DNS provider and publish the DS record at the ' +
        'registrar, so responses cannot be forged in transit.',
    reference: 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/',
    evidence: { authenticatedData: d.authenticatedData, resolver: d.resolver },
  });
}
