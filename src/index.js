/**
 * certadel — authorized, passive external security-posture assessment and certification.
 *
 * The public API. Everything a consumer needs to run an assessment and render its
 * outputs is re-exported here; the internal modules are free to move behind it.
 *
 * @module certadel
 */

export { loadScope, normalizeScope, validateAsset, scopeGuard, ScopeError } from './scope.js';
export { assessScope, assessAsset, collectEvidence } from './assess.js';
export { grade, rollUp } from './scoring/grade.js';
export { TIERS, GATES, tierForScore } from './scoring/rubric.js';
export { serializeReport, verificationCode } from './report/serialize.js';
export { renderHtml } from './report/html.js';
export { renderBadge } from './report/badge.js';
export { renderTerminal } from './report/terminal.js';
export { runChecks } from './checks/index.js';

import { loadScope } from './scope.js';
import { assessScope } from './assess.js';
import { serializeReport } from './report/serialize.js';

/**
 * The one-call convenience path: load a scope file, assess every asset, and return the
 * serialized report ready for any renderer.
 *
 * @param {string} scopePath
 * @param {Object} [options] Forwarded to {@link assessScope}, plus `toolVersion`.
 * @returns {Promise<Object>} Serialized report.
 */
export async function certify(scopePath, options = {}) {
  const scope = await loadScope(scopePath);
  const assessments = await assessScope(scope, options);
  return serializeReport(scope, assessments, {
    toolVersion: options.toolVersion,
    generatedAt: options.generatedAt,
  });
}
