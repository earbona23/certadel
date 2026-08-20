/**
 * The vocabulary every part of certadel speaks.
 *
 * A whole assessment reduces to a list of {@link Check} results, each carrying a
 * {@link Status}, a {@link Severity}, the evidence it judged, and the remediation to
 * act on. Fixing the shape here is what lets the scorer, the certificate and the
 * badge stay simple and honest: none of them has to guess what a check meant.
 *
 * @module util/model
 */

/**
 * Outcome of a single check.
 *
 * `skip` is deliberately distinct from `pass`. A check that could not run -- no MX
 * record, so email authentication does not apply; a host that would not complete a
 * TLS handshake, so header checks have nothing to read -- must never be scored as if
 * it succeeded. Conflating "not applicable" with "fine" is how a posture tool ends up
 * certifying a wall it never looked at.
 *
 * @typedef {'pass' | 'warn' | 'fail' | 'skip' | 'error'} Status
 */

/**
 * How much a failing check matters, independent of how many points it is worth.
 *
 * Severity drives the certification gates: a single `critical` failure caps the whole
 * grade regardless of the numeric score, because a broken front door is a broken front
 * door even if everything behind it is immaculate.
 *
 * @typedef {'critical' | 'high' | 'medium' | 'low' | 'info'} Severity
 */

/** Ordered worst-first, so a sort by rank surfaces the things that matter. */
export const SEVERITY_RANK = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
});

/** The dimensions a posture is graded across. Order is the report's reading order. */
export const DIMENSIONS = Object.freeze([
  'transport',
  'headers',
  'cookies',
  'dns',
  'email',
  'exposure',
]);

/** Human-facing labels for each dimension. */
export const DIMENSION_LABELS = Object.freeze({
  transport: 'Transport security (TLS)',
  headers: 'HTTP security headers',
  cookies: 'Cookie flags',
  dns: 'DNS & domain hygiene',
  email: 'Email authentication',
  exposure: 'Exposure & hygiene',
});

/**
 * @typedef {Object} CheckResult
 * @property {string} id               Stable identifier, e.g. 'tls-protocol-versions'.
 * @property {string} title            One line naming what was checked.
 * @property {string} dimension        One of {@link DIMENSIONS}.
 * @property {Status} status
 * @property {Severity} severity       The severity if this check is failing.
 * @property {number} earned           Points earned (0..max).
 * @property {number} max              Points this check can contribute.
 * @property {string} [detail]         What was found, in plain language.
 * @property {string} [remediation]    What to do about it.
 * @property {string} [reference]      A URL backing the recommendation.
 * @property {Object} [evidence]       The raw values the judgement was made from.
 */

/**
 * Build a {@link CheckResult}. Checks call this and nothing else, so every result is
 * shaped identically no matter which check produced it.
 *
 * `earned` defaults sensibly from `status` when omitted: a pass earns the maximum, a
 * warn earns half, a fail or skip earns nothing. A check with partial credit passes
 * `earned` explicitly.
 *
 * @param {Partial<CheckResult> & { id: string, title: string, dimension: string, status: Status }} spec
 * @returns {CheckResult}
 */
export function result(spec) {
  const max = spec.max ?? 0;
  let earned = spec.earned;
  if (earned === undefined) {
    if (spec.status === 'pass') earned = max;
    else if (spec.status === 'warn') earned = Math.round(max / 2);
    else earned = 0;
  }
  return {
    id: spec.id,
    title: spec.title,
    dimension: spec.dimension,
    status: spec.status,
    severity: spec.severity ?? 'info',
    earned: clamp(earned, 0, max),
    max,
    detail: spec.detail,
    remediation: spec.remediation,
    reference: spec.reference,
    evidence: spec.evidence ?? {},
  };
}

/**
 * A check whose prerequisite is absent. Scored as `skip`: zero points earned, but its
 * `max` is also removed from the denominator by the scorer, so "not applicable" neither
 * rewards nor penalises. The reason is preserved for the report.
 *
 * @param {{ id: string, title: string, dimension: string, reason: string, max?: number }} spec
 * @returns {CheckResult}
 */
export function skipped(spec) {
  return result({
    id: spec.id,
    title: spec.title,
    dimension: spec.dimension,
    status: 'skip',
    severity: 'info',
    max: spec.max ?? 0,
    earned: 0,
    detail: spec.reason,
  });
}

/** @param {number} n @param {number} lo @param {number} hi @returns {number} */
export function clamp(n, lo, hi) {
  if (Number.isNaN(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}
