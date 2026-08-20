/**
 * Renders the assessment as one self-contained HTML file: a certificate at the top, a
 * per-asset and per-dimension breakdown, and every finding with its evidence and
 * remediation below.
 *
 * The certificate leads, but it never overstates. It shows the tier, and when a gate
 * capped that tier it says so in plain language right under the grade, because a
 * certificate that hides why it is not Gold is a certificate that misleads. Every value
 * that reaches this file comes from the assessed host and is escaped, so a hostile
 * Server banner or certificate field is shown as text, never run as markup.
 *
 * @module report/html
 */

import { reportStyle, reportScript } from './assets.js';
import { SEVERITY_RANK } from '../util/model.js';

/**
 * @param {Object} report Serialized report from serialize.js.
 * @returns {string}
 */
export function renderHtml(report) {
  const roll = report.rollup;
  const org = esc(report.organization);
  const generated = esc(report.generatedAt.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC'));

  const out = [];
  out.push('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">');
  out.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
  out.push(`<title>Security posture certificate — ${org}</title>`);
  out.push(`<style>${reportStyle()}</style></head><body><main class="wrap">`);

  // --- Certificate ---------------------------------------------------------
  out.push('<div class="cert">');
  out.push('<p class="eyebrow">certadel · external security posture certificate</p>');
  out.push(`<h1>${org}</h1>`);
  out.push(
    `<p class="sub">${report.assets.length} asset${report.assets.length === 1 ? '' : 's'} assessed · ${generated}</p>`,
  );
  out.push('<div class="tierline">');
  out.push(`<span class="tier ${roll.tier}">${esc(roll.tierLabel)}</span>`);
  out.push(`<span class="scorebig">mean score ${roll.score}/100</span>`);
  out.push('</div>');

  if (roll.tier === 'uncertified') {
    out.push(
      `<div class="gatebanner" style="margin-top:20px"><strong>Not certified.</strong> ` +
        `At least one asset has a critical control failing. See the breakdown below.</div>`,
    );
  } else if (report.assets.length > 1 && roll.weakest) {
    out.push(
      `<p class="sub" style="margin-top:16px">The organisation tier is set by its weakest ` +
        `asset, <span class="mono">${esc(roll.weakest)}</span> — an attacker targets the softest host, ` +
        `so the grade follows the floor, not the average.</p>`,
    );
  }

  out.push('<dl>');
  out.push(`<div><dt>Verification code</dt><dd class="mono">${esc(report.verificationCode)}</dd></div>`);
  if (report.authorizedBy) out.push(`<div><dt>Authorized by</dt><dd>${esc(report.authorizedBy)}</dd></div>`);
  if (report.reference) out.push(`<div><dt>Engagement</dt><dd>${esc(report.reference)}</dd></div>`);
  out.push(`<div><dt>Tool</dt><dd>certadel ${esc(report.toolVersion)}</dd></div>`);
  out.push('</dl>');

  out.push(
    '<p class="disclaimer">This is a <strong>self-assessment</strong> of publicly observable ' +
      'configuration (TLS, HTTP headers, DNS and email-authentication records). It is not an ' +
      'accredited audit and does not test application logic, authorisation or code. The ' +
      'verification code is derived from the posture itself: re-run certadel on the same assets ' +
      'and it will match until something material changes.</p>',
  );
  out.push('</div>');

  // --- Per-asset breakdown -------------------------------------------------
  out.push('<section><h2>Assets</h2><div class="assetgrid">');
  for (const a of report.assets) {
    out.push(`<div class="assetcard ${a.tier}">`);
    out.push(`<div class="host">${esc(a.host)}</div>`);
    out.push(
      `<div><span class="at" style="color:var(--${a.tier})">${esc(a.tierLabel)}</span> ` +
        `<span class="sc">${a.score}/100</span></div>`,
    );
    out.push('<div class="dims">');
    for (const d of a.dimensions) {
      const pct = d.percent === null ? null : d.percent;
      out.push('<div class="dim">');
      out.push(
        `<div class="dim-top"><span class="dim-label">${esc(d.label)}</span>` +
          `<span class="pct">${pct === null ? 'n/a' : pct}</span></div>`,
      );
      out.push(`<span class="bar"><span style="width:${pct === null ? 0 : pct}%"></span></span>`);
      out.push('</div>');
    }
    out.push('</div></div>');
  }
  out.push('</div></section>');

  // --- Findings ------------------------------------------------------------
  const allFindings = [];
  for (const a of report.assets) {
    for (const f of a.findings) allFindings.push({ ...f, host: a.host });
  }
  const actionable = allFindings.filter((f) => f.status === 'fail' || f.status === 'warn');

  out.push('<section><h2>Findings</h2>');
  out.push('<div class="filters no-print">');
  out.push('<input type="search" id="q" placeholder="filter by host, control, detail…" autocomplete="off">');
  out.push('<div id="sev" style="display:flex;gap:8px;flex-wrap:wrap">');
  for (const [val, label] of [['fail', 'Fail'], ['warn', 'Warn'], ['pass', 'Pass'], ['skip', 'N/A']]) {
    const checked = val === 'fail' || val === 'warn' ? ' checked' : '';
    out.push(`<label class="chip"><input type="checkbox" value="${val}"${checked}> ${label}</label>`);
  }
  out.push('</div><span id="shown" class="mono" style="margin-left:auto;color:var(--muted)"></span></div>');

  // Group by host, then severity.
  for (const a of report.assets) {
    out.push(`<h3 data-group>${esc(a.host)}</h3>`);
    const sorted = [...a.findings].sort(
      (x, y) =>
        statusOrder(x.status) - statusOrder(y.status) ||
        (SEVERITY_RANK[x.severity] ?? 9) - (SEVERITY_RANK[y.severity] ?? 9),
    );
    for (const f of sorted) {
      const hay = esc(`${a.host} ${f.title} ${f.detail ?? ''} ${f.dimension}`).toLowerCase();
      out.push(
        `<details class="finding sev-${esc(f.severity)}" data-status="${esc(f.status)}" data-search="${hay}">`,
      );
      out.push('<summary>');
      out.push(`<span class="status st-${esc(f.status)}">${esc(f.status)}</span>`);
      out.push(`<span class="ftitle">${esc(f.title)}</span>`);
      if (f.status === 'fail') out.push(`<span class="pill st-${sevClass(f.severity)}">${esc(f.severity)}</span>`);
      out.push('</summary><div class="body">');
      if (f.detail) out.push(`<p class="detail">${esc(f.detail)}</p>`);
      if (f.remediation) out.push(`<p class="rec"><strong>What to do</strong> ${esc(f.remediation)}</p>`);
      if (f.evidence && Object.keys(f.evidence).length) {
        out.push(`<pre class="evidence">${esc(safeJson(f.evidence))}</pre>`);
      }
      if (f.reference) {
        out.push(`<p style="margin:10px 0 0"><a href="${escAttr(f.reference)}" target="_blank" rel="noreferrer noopener">Reference</a></p>`);
      }
      out.push('</div></details>');
    }
  }
  out.push('</section>');

  out.push(
    '<footer>Produced by <strong>certadel</strong>, a passive external posture assessor. ' +
      'It inspected only public configuration of the authorized assets and changed nothing. ' +
      `${actionable.length} actionable finding${actionable.length === 1 ? '' : 's'} across ` +
      `${report.assets.length} asset${report.assets.length === 1 ? '' : 's'}.</footer>`,
  );
  out.push(`<script>${reportScript()}</script>`);
  out.push('</main></body></html>');
  return out.join('\n');
}

/** @param {string} status */
function statusOrder(status) {
  return { fail: 0, warn: 1, pass: 2, skip: 3, error: 4 }[status] ?? 5;
}
/** @param {string} sev */
function sevClass(sev) {
  return sev === 'critical' || sev === 'high' ? 'fail' : sev === 'medium' ? 'warn' : 'skip';
}
/** @param {unknown} v */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
/** @param {unknown} v */
function escAttr(v) {
  return esc(v);
}
/** @param {unknown} obj */
function safeJson(obj) {
  try {
    const ordered = {};
    for (const k of Object.keys(obj).sort()) ordered[k] = obj[k];
    return JSON.stringify(ordered, null, 2);
  } catch {
    return String(obj);
  }
}
