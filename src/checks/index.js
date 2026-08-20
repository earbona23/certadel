/**
 * Runs every check group over one asset's evidence and returns the flat list of results.
 * This is the single place that knows the full battery of checks, so adding a dimension
 * is a one-line change here plus its module.
 *
 * @module checks/index
 */

import { transportChecks } from './transport.js';
import { headerChecks } from './headers.js';
import { cookieChecks } from './cookies.js';
import { dnsChecks } from './dns.js';
import { emailChecks } from './email.js';
import { exposureChecks } from './exposure.js';

/** Every check group, in report order. */
export const CHECK_GROUPS = Object.freeze([
  transportChecks,
  headerChecks,
  cookieChecks,
  dnsChecks,
  emailChecks,
  exposureChecks,
]);

/**
 * @param {import('../assess.js').AssetEvidence} evidence
 * @returns {import('../util/model.js').CheckResult[]}
 */
export function runChecks(evidence) {
  /** @type {import('../util/model.js').CheckResult[]} */
  const results = [];
  for (const group of CHECK_GROUPS) {
    for (const r of group(evidence)) results.push(r);
  }
  return results;
}
