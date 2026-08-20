/**
 * Turns raw assessments into the single serializable report object every renderer
 * consumes, and stamps it with a verification code.
 *
 * The verification code is a SHA-256 over the *posture* -- the organisation, each host's
 * tier and score, and every check's id and status -- and deliberately not over the
 * timestamp. So re-running an unchanged tenant yields the same code, and the code
 * changes exactly when something about the security posture changes. Anyone handed a
 * certificate can re-run certadel and confirm the code still matches, which is what
 * makes a self-issued certificate checkable rather than merely decorative.
 *
 * @module report/serialize
 */

import { createHash } from 'node:crypto';
import { rollUp } from '../scoring/grade.js';

/**
 * @param {import('../scope.js').Scope} scope
 * @param {import('../assess.js').AssetAssessment[]} assessments
 * @param {Object} [meta]
 * @param {string} [meta.generatedAt] ISO timestamp; caller supplies for determinism.
 * @param {string} [meta.toolVersion]
 * @returns {Object}
 */
export function serializeReport(scope, assessments, meta = {}) {
  const assets = assessments.map((a) => ({
    host: a.host,
    score: a.grade.score,
    tier: a.grade.tier,
    tierLabel: a.grade.tierLabel,
    certified: a.grade.certified,
    gated: a.grade.gated,
    gateReason: a.grade.gateReason,
    failures: a.grade.failures,
    dimensions: a.grade.dimensions,
    findings: a.results.map((r) => ({
      id: r.id,
      title: r.title,
      dimension: r.dimension,
      status: r.status,
      severity: r.severity,
      earned: r.earned,
      max: r.max,
      detail: r.detail,
      remediation: r.remediation,
      reference: r.reference,
      evidence: r.evidence,
    })),
  }));

  const rollup = rollUp(assessments.map((a) => ({ host: a.host, grade: a.grade })));

  const report = {
    tool: 'certadel',
    toolVersion: meta.toolVersion ?? '0.0.0',
    generatedAt: meta.generatedAt ?? new Date().toISOString(),
    organization: scope.organization,
    authorizedBy: scope.authorizedBy ?? null,
    reference: scope.reference ?? null,
    rollup,
    assets,
  };

  report.verificationCode = verificationCode(report);
  return report;
}

/**
 * A short, human-transcribable code derived from the posture only (not the timestamp).
 *
 * @param {Object} report
 * @returns {string} e.g. 'CERTADEL-7F3A-9C21-04BE'
 */
export function verificationCode(report) {
  const canonical = JSON.stringify({
    organization: report.organization,
    assets: report.assets
      .map((a) => ({
        host: a.host,
        tier: a.tier,
        score: a.score,
        findings: a.findings
          .map((f) => `${f.id}:${f.status}`)
          .sort(),
      }))
      .sort((x, y) => x.host.localeCompare(y.host)),
  });
  const hex = createHash('sha256').update(canonical).digest('hex').toUpperCase();
  return `CERTADEL-${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
}
