/**
 * Turns a bag of check results into a score, a tier, and an honest account of why.
 *
 * @module scoring/grade
 */

import { DIMENSIONS, DIMENSION_LABELS } from '../util/model.js';
import { TIERS, GATES, tierForScore, tierRank } from './rubric.js';

/**
 * @typedef {Object} DimensionScore
 * @property {string} dimension
 * @property {string} label
 * @property {number} earned
 * @property {number} max          Applicable max (skipped checks excluded).
 * @property {number} percent      0..100, or null when nothing applied.
 * @property {number} checks       Checks that applied (non-skip).
 * @property {number} skipped
 */

/**
 * @typedef {Object} Grade
 * @property {number} score                 Overall 0..100.
 * @property {string} tier                  Tier id after gates.
 * @property {string} tierLabel
 * @property {string} scoreTier             Tier id the score alone would grant.
 * @property {boolean} gated                True if a gate lowered the tier.
 * @property {string | null} gateReason
 * @property {boolean} certified            True if tier is Bronze or better.
 * @property {DimensionScore[]} dimensions
 * @property {{ critical: number, high: number, medium: number, low: number }} failures
 */

/**
 * @param {import('../util/model.js').CheckResult[]} results
 * @returns {Grade}
 */
export function grade(results) {
  const applicable = results.filter((r) => r.status !== 'skip' && r.status !== 'error');

  let earned = 0;
  let max = 0;
  for (const r of applicable) {
    earned += r.earned;
    max += r.max;
  }
  const score = max > 0 ? round(100 * (earned / max)) : 0;

  const dimensions = DIMENSIONS.map((dim) => scoreDimension(dim, results));

  const failures = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of results) {
    if (r.status === 'fail') {
      if (r.severity === 'critical') failures.critical++;
      else if (r.severity === 'high') failures.high++;
      else if (r.severity === 'medium') failures.medium++;
      else if (r.severity === 'low') failures.low++;
    }
  }

  const scoreTier = tierForScore(score);
  let cappedTierId = scoreTier.id;
  let gateReason = null;

  for (const gate of GATES) {
    const triggered =
      (gate.id === 'critical-failure' && failures.critical > 0) ||
      (gate.id === 'high-failure' && failures.high > 0);
    if (triggered && tierRank(gate.capTier) > tierRank(cappedTierId)) {
      cappedTierId = gate.capTier;
      gateReason = gate.reason;
    }
  }

  const finalTier = TIERS.find((t) => t.id === cappedTierId) ?? TIERS[TIERS.length - 1];
  const gated = cappedTierId !== scoreTier.id;

  return {
    score,
    tier: finalTier.id,
    tierLabel: finalTier.label,
    scoreTier: scoreTier.id,
    gated,
    gateReason: gated ? gateReason : null,
    certified: finalTier.id !== 'uncertified',
    dimensions,
    failures,
  };
}

/**
 * @param {string} dimension
 * @param {import('../util/model.js').CheckResult[]} results
 * @returns {DimensionScore}
 */
function scoreDimension(dimension, results) {
  const inDim = results.filter((r) => r.dimension === dimension);
  const applied = inDim.filter((r) => r.status !== 'skip' && r.status !== 'error');
  let earned = 0;
  let max = 0;
  for (const r of applied) {
    earned += r.earned;
    max += r.max;
  }
  return {
    dimension,
    label: DIMENSION_LABELS[dimension] ?? dimension,
    earned,
    max,
    percent: max > 0 ? round(100 * (earned / max)) : null,
    checks: applied.length,
    skipped: inDim.length - applied.length,
  };
}

/**
 * Roll several per-asset grades into one company-level grade. The organisation's tier
 * is the *weakest* of its assets, not the average -- an attacker targets the softest
 * host, so certifying the company at its mean would certify a fiction. The reported
 * score is the mean, for trend, but the tier follows the floor.
 *
 * @param {{ host: string, grade: Grade }[]} assetGrades
 * @returns {{ score: number, tier: string, tierLabel: string, weakest: string | null, certified: boolean }}
 */
export function rollUp(assetGrades) {
  const graded = assetGrades.filter((a) => a.grade);
  if (graded.length === 0) {
    return { score: 0, tier: 'uncertified', tierLabel: 'Not certified', weakest: null, certified: false };
  }
  const meanScore = round(graded.reduce((s, a) => s + a.grade.score, 0) / graded.length);

  let worst = graded[0];
  for (const a of graded) {
    if (tierRank(a.grade.tier) > tierRank(worst.grade.tier)) worst = a;
    else if (
      tierRank(a.grade.tier) === tierRank(worst.grade.tier) &&
      a.grade.score < worst.grade.score
    ) {
      worst = a;
    }
  }
  const tier = TIERS.find((t) => t.id === worst.grade.tier) ?? TIERS[TIERS.length - 1];
  return {
    score: meanScore,
    tier: tier.id,
    tierLabel: tier.label,
    weakest: worst.host,
    certified: tier.id !== 'uncertified',
  };
}

/** @param {number} n @returns {number} */
function round(n) {
  return Math.round(n * 10) / 10;
}
