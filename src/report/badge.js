/**
 * A self-contained SVG badge, in the shields.io house style, for a README or dashboard.
 * No network, no external font -- the label text is rendered as paths-free <text> using
 * the viewer's sans-serif, which every SVG renderer has.
 *
 * @module report/badge
 */

import { TIERS } from '../scoring/rubric.js';

/**
 * @param {Object} options
 * @param {string} options.tier          Tier id.
 * @param {number} [options.score]
 * @param {string} [options.label]       Left-hand label. Default 'security posture'.
 * @returns {string} SVG markup.
 */
export function renderBadge(options) {
  const tier = TIERS.find((t) => t.id === options.tier) ?? TIERS[TIERS.length - 1];
  const label = options.label ?? 'security posture';
  const value =
    options.score !== undefined ? `${tier.label} · ${options.score}` : tier.label;

  const labelW = textWidth(label) + 12;
  const valueW = textWidth(value) + 14;
  const total = labelW + valueW;
  const color = tier.badgeColor;

  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}">
  <title>${esc(label)}: ${esc(value)}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="#444"/>
    <rect x="${labelW}" width="${valueW}" height="20" fill="${color}"/>
    <rect width="${total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelW / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(label)}</text>
    <text x="${labelW / 2}" y="14">${esc(label)}</text>
    <text x="${labelW + valueW / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(value)}</text>
    <text x="${labelW + valueW / 2}" y="14">${esc(value)}</text>
  </g>
</svg>`;
}

/** Rough proportional width for 11px Verdana, good enough for badge geometry. */
function textWidth(text) {
  let w = 0;
  for (const ch of String(text)) {
    if ('iIl.,:;|!\''.includes(ch)) w += 3;
    else if ('mwMW'.includes(ch)) w += 9;
    else if (ch === ' ') w += 4;
    else w += 6.5;
  }
  return Math.ceil(w);
}
