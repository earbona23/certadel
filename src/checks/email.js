/**
 * Email-authentication checks. A domain that sends mail -- or merely could, because it
 * has MX records -- is a domain an attacker can try to impersonate. These checks grade
 * the records that let receivers reject forged mail: SPF, DKIM, DMARC, MTA-STS and
 * TLS-RPT.
 *
 * The whole dimension is skipped, not failed, for a domain with no MX record and no SPF:
 * a domain that neither receives nor claims to send mail is not graded for mail it does
 * not handle. But a domain that publishes SPF is asserting that it sends mail, so it is
 * held to the standard even without MX.
 *
 * @module checks/email
 */

import { result, skipped } from '../util/model.js';
import { parseDmarc, parseSpf } from '../util/parse.js';

const REF_DMARC = 'https://dmarc.org/overview/';

/**
 * @param {import('../assess.js').AssetEvidence} ev
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function emailChecks(ev) {
  const hasMx = (ev.dns?.mx ?? []).length > 0;
  const spfRecords = (ev.dns?.txt ?? [])
    .map((chunks) => chunks.join(''))
    .filter((t) => /^v=spf1/i.test(t.trim()));
  const claimsMail = hasMx || spfRecords.length > 0;

  if (!claimsMail) {
    return [
      skipped({
        id: 'email-not-applicable',
        title: 'Email authentication',
        dimension: 'email',
        reason:
          'The domain has no MX record and publishes no SPF record, so it neither ' +
          'receives nor claims to send mail. Email authentication is not applicable.',
        max: 0,
      }),
    ];
  }

  return [
    checkSpf(spfRecords),
    checkDmarc(ev),
    checkDkim(ev),
    checkMtaSts(ev, hasMx),
    checkTlsRpt(ev, hasMx),
  ];
}

/** @param {string[]} spfRecords */
function checkSpf(spfRecords) {
  if (spfRecords.length === 0) {
    return result({
      id: 'email-spf',
      title: 'SPF authorises legitimate senders and rejects the rest',
      dimension: 'email',
      status: 'fail',
      severity: 'high',
      max: 7,
      detail: 'No SPF record was found.',
      remediation:
        'Publish an SPF record listing your authorised senders and ending in -all, so ' +
        'receivers can reject mail from anywhere else.',
      reference: REF_DMARC,
      evidence: { count: 0 },
    });
  }
  if (spfRecords.length > 1) {
    return result({
      id: 'email-spf',
      title: 'SPF authorises legitimate senders and rejects the rest',
      dimension: 'email',
      status: 'fail',
      severity: 'high',
      max: 7,
      detail: `${spfRecords.length} SPF records are published; more than one is invalid and voids SPF.`,
      remediation: 'Merge the SPF records into a single record.',
      reference: REF_DMARC,
      evidence: { count: spfRecords.length },
    });
  }
  const spf = parseSpf(spfRecords[0]);
  const strict = spf.qualifier === '-';
  const soft = spf.qualifier === '~';
  const status = strict ? 'pass' : soft ? 'warn' : 'fail';
  return result({
    id: 'email-spf',
    title: 'SPF authorises legitimate senders and rejects the rest',
    dimension: 'email',
    status,
    severity: strict ? 'info' : soft ? 'low' : 'high',
    max: 7,
    detail: strict
      ? 'A single SPF record ends in -all (hard fail for unlisted senders).'
      : soft
        ? 'SPF ends in ~all (soft fail); unlisted senders are marked, not rejected.'
        : `SPF ends in ${spf.qualifier ?? 'no all mechanism'}, which does not constrain senders.`,
    remediation: strict ? undefined : 'End the SPF record in -all once you are confident it is complete.',
    reference: REF_DMARC,
    evidence: { qualifier: spf.qualifier, lookups: spf.lookups },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkDmarc(ev) {
  const records = (ev.dmarcTxt ?? []).filter((t) => /^v=dmarc1/i.test(t.trim()));
  if (records.length === 0) {
    return result({
      id: 'email-dmarc',
      title: 'DMARC is published with an enforcing policy',
      dimension: 'email',
      status: 'fail',
      severity: 'high',
      max: 10,
      detail: 'No DMARC record was found at _dmarc.',
      remediation:
        'Publish a DMARC record. Start at p=none with a rua address to observe, then ' +
        'move to p=quarantine and p=reject as confidence grows.',
      reference: REF_DMARC,
      evidence: { present: false },
    });
  }
  const dmarc = parseDmarc(records[0]);
  const policy = dmarc.policy;
  if (policy === 'reject') {
    return result({
      id: 'email-dmarc',
      title: 'DMARC is published with an enforcing policy',
      dimension: 'email',
      status: 'pass',
      max: 10,
      detail: `DMARC p=reject${dmarc.rua ? ' with aggregate reporting' : ''}.`,
      reference: REF_DMARC,
      evidence: dmarc,
    });
  }
  if (policy === 'quarantine') {
    return result({
      id: 'email-dmarc',
      title: 'DMARC is published with an enforcing policy',
      dimension: 'email',
      status: 'warn',
      severity: 'medium',
      max: 10,
      earned: 6,
      detail: 'DMARC p=quarantine; forged mail is quarantined but not rejected outright.',
      remediation: 'Advance to p=reject once quarantine has shown no false positives.',
      reference: REF_DMARC,
      evidence: dmarc,
    });
  }
  return result({
    id: 'email-dmarc',
    title: 'DMARC is published with an enforcing policy',
    dimension: 'email',
    status: 'fail',
    severity: 'high',
    max: 10,
    earned: 2,
    detail: `DMARC policy is p=${policy ?? 'none'}, which only monitors and does not stop spoofing.`,
    remediation: 'Move the DMARC policy to quarantine, then reject.',
    reference: REF_DMARC,
    evidence: dmarc,
  });
}

/** @param {import('../assess.js').AssetEvidence} ev */
function checkDkim(ev) {
  const found = (ev.dkim ?? []).filter((d) => d.found);
  if (!ev.dkim || ev.dkim.length === 0) {
    return skipped({
      id: 'email-dkim',
      title: 'A DKIM signing key is published',
      dimension: 'email',
      reason: 'No DKIM selectors were probed for this run.',
      max: 4,
    });
  }
  if (found.length > 0) {
    return result({
      id: 'email-dkim',
      title: 'A DKIM signing key is published',
      dimension: 'email',
      status: 'pass',
      max: 4,
      detail: `A DKIM key was found at selector(s): ${found.map((d) => d.selector).join(', ')}.`,
      evidence: { selectors: found.map((d) => d.selector) },
    });
  }
  // No key at the common selectors is not proof of absence -- selectors are chosen by
  // the sender -- so this warns rather than fails.
  return result({
    id: 'email-dkim',
    title: 'A DKIM signing key is published',
    dimension: 'email',
    status: 'warn',
    severity: 'low',
    max: 4,
    detail:
      `No DKIM key was found at the common selectors probed ` +
      `(${ev.dkim.map((d) => d.selector).join(', ')}). It may use a custom selector.`,
    remediation:
      'Confirm DKIM is enabled at your mail provider. DKIM is what lets DMARC survive ' +
      'legitimate forwarding.',
    reference: REF_DMARC,
    evidence: { probed: ev.dkim.map((d) => d.selector) },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev @param {boolean} hasMx */
function checkMtaSts(ev, hasMx) {
  if (!hasMx) {
    return skipped({
      id: 'email-mta-sts',
      title: 'MTA-STS enforces TLS for inbound mail',
      dimension: 'email',
      reason: 'The domain has no MX record, so inbound mail transport does not apply.',
      max: 3,
    });
  }
  const record = (ev.mtaSts?.txt ?? []).some((t) => /^v=stsv1/i.test(t.trim()));
  const policy = ev.mtaSts?.policyMode ?? null;
  const enforce = policy === 'enforce';
  if (!record) {
    return result({
      id: 'email-mta-sts',
      title: 'MTA-STS enforces TLS for inbound mail',
      dimension: 'email',
      status: 'warn',
      severity: 'low',
      max: 3,
      detail: 'No MTA-STS policy is published.',
      remediation:
        'Publish an MTA-STS policy in enforce mode so sending servers require TLS and a ' +
        'valid certificate when delivering to you.',
      reference: 'https://www.rfc-editor.org/rfc/rfc8461',
      evidence: { present: false },
    });
  }
  return result({
    id: 'email-mta-sts',
    title: 'MTA-STS enforces TLS for inbound mail',
    dimension: 'email',
    status: enforce ? 'pass' : 'warn',
    severity: enforce ? 'info' : 'low',
    max: 3,
    detail: enforce
      ? 'MTA-STS is published in enforce mode.'
      : `MTA-STS is published but in ${policy ?? 'testing'} mode.`,
    remediation: enforce ? undefined : 'Move the MTA-STS policy to enforce mode.',
    reference: 'https://www.rfc-editor.org/rfc/rfc8461',
    evidence: { mode: policy },
  });
}

/** @param {import('../assess.js').AssetEvidence} ev @param {boolean} hasMx */
function checkTlsRpt(ev, hasMx) {
  if (!hasMx) {
    return skipped({
      id: 'email-tls-rpt',
      title: 'TLS-RPT requests transport-security reports',
      dimension: 'email',
      reason: 'The domain has no MX record, so inbound mail transport does not apply.',
      max: 1,
    });
  }
  const present = (ev.tlsRpt ?? []).some((t) => /^v=tlsrptv1/i.test(t.trim()));
  return result({
    id: 'email-tls-rpt',
    title: 'TLS-RPT requests transport-security reports',
    dimension: 'email',
    status: present ? 'pass' : 'warn',
    severity: present ? 'info' : 'low',
    max: 1,
    detail: present ? 'A TLS-RPT record is published.' : 'No TLS-RPT record is published.',
    remediation: present
      ? undefined
      : 'Publish a TLS-RPT record so you receive reports when senders fail to negotiate TLS.',
    reference: 'https://www.rfc-editor.org/rfc/rfc8460',
    evidence: { present },
  });
}
