/**
 * The certification rubric, in one place, as data.
 *
 * Everything about how a posture becomes a grade lives here so it can be read, argued
 * with, and tested. Two ideas do the work:
 *
 * 1. **A weighted score.** Every check contributes points toward its dimension; the
 *    dimensions' weights reflect blast radius, so transport security counts for more
 *    than a missing Permissions-Policy header. The score is the share of *applicable*
 *    points earned -- checks that were skipped (not applicable) leave the denominator,
 *    so a domain that sends no mail is neither rewarded nor punished for its mail setup.
 *
 * 2. **Gates.** A high score cannot paper over a hole. A single critical failure -- no
 *    HTTPS, an invalid or expired certificate, TLS 1.0 still enabled -- means the asset
 *    is not certified at all, whatever the arithmetic says. A high-severity failure caps
 *    the tier at Bronze. A certificate that let you reach Gold with the front door open
 *    would be worse than no certificate, because someone would trust it.
 *
 * @module scoring/rubric
 */

/**
 * Certification tiers, best to worst. `min` is the score floor; the gates in grade.js
 * can lower the tier below what the score alone would grant, but never raise it.
 */
export const TIERS = Object.freeze([
  { id: 'platinum', label: 'Platinum', min: 95, badgeColor: '#3fb6c2' },
  { id: 'gold', label: 'Gold', min: 85, badgeColor: '#c9a227' },
  { id: 'silver', label: 'Silver', min: 70, badgeColor: '#8a97a6' },
  { id: 'bronze', label: 'Bronze', min: 50, badgeColor: '#a0682d' },
  { id: 'uncertified', label: 'Not certified', min: 0, badgeColor: '#9a2b21' },
]);

/**
 * Gate rules, applied after the score is computed. Each caps the achievable tier when
 * its condition is met. Evaluated in order; the most restrictive cap wins.
 */
export const GATES = Object.freeze([
  {
    id: 'critical-failure',
    when: 'any check fails with critical severity',
    capTier: 'uncertified',
    reason:
      'A critical control is failing (for example: no HTTPS, an invalid or expired ' +
      'certificate, or an obsolete TLS version still enabled). An asset cannot be ' +
      'certified while a critical control is open, regardless of its score.',
  },
  {
    id: 'high-failure',
    when: 'any check fails with high severity',
    capTier: 'bronze',
    reason:
      'A high-severity control is failing. The asset can hold no more than Bronze until ' +
      'it is resolved.',
  },
]);

/** The lowest tier still considered "certified". Below this, the asset is uncertified. */
export const MIN_CERTIFIED_TIER = 'bronze';

/**
 * @param {number} score
 * @returns {typeof TIERS[number]}
 */
export function tierForScore(score) {
  for (const tier of TIERS) {
    if (score >= tier.min) return tier;
  }
  return TIERS[TIERS.length - 1];
}

/**
 * @param {string} tierId
 * @returns {number} index into TIERS (0 = best)
 */
export function tierRank(tierId) {
  const idx = TIERS.findIndex((t) => t.id === tierId);
  return idx === -1 ? TIERS.length - 1 : idx;
}
