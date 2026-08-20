/**
 * The terminal summary: what you see the moment a run finishes. It leads with coverage
 * and the gate, not just a number, so a capped grade never reads as a passing one.
 *
 * @module report/terminal
 */

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

const TIER_COLOR = {
  platinum: COLORS.cyan,
  gold: COLORS.yellow,
  silver: COLORS.blue,
  bronze: COLORS.yellow,
  uncertified: COLORS.red,
};

const STATUS_MARK = {
  pass: (c) => `${c.green}pass${c.reset}`,
  warn: (c) => `${c.yellow}warn${c.reset}`,
  fail: (c) => `${c.red}fail${c.reset}`,
  skip: (c) => `${c.gray}skip${c.reset}`,
  error: (c) => `${c.red}err ${c.reset}`,
};

/**
 * @param {Object} report          Serialized report from serialize.js.
 * @param {Object} [options]
 * @param {boolean} [options.color]
 * @param {boolean} [options.verbose] Show every check, not just failures/warnings.
 * @returns {string}
 */
export function renderTerminal(report, options = {}) {
  const c = options.color === false ? blankColors() : COLORS;
  const lines = [];

  lines.push('');
  lines.push(`${c.bold}certadel${c.reset} ${c.dim}· external security posture${c.reset}`);
  lines.push(`${c.bold}${report.organization}${c.reset}`);
  lines.push('');

  const roll = report.rollup;
  const tierC = TIER_COLOR[roll.tier] ?? c.reset;
  lines.push(
    `  Organisation grade: ${c.bold}${tierC}${roll.tierLabel}${c.reset}` +
      `  ${c.dim}(mean score ${roll.score})${c.reset}`,
  );
  if (roll.weakest && report.assets.length > 1) {
    lines.push(`  ${c.dim}Set by the weakest asset: ${roll.weakest}${c.reset}`);
  }
  lines.push('');

  for (const asset of report.assets) {
    const at = TIER_COLOR[asset.tier] ?? c.reset;
    lines.push(
      `  ${c.bold}${asset.host}${c.reset}  ${at}${asset.tierLabel}${c.reset} ` +
        `${c.dim}${asset.score}/100${c.reset}`,
    );
    if (asset.gated) {
      lines.push(`    ${c.red}⚑ capped:${c.reset} ${wrap(asset.gateReason ?? '', 74, '      ')}`);
    }

    const shown = report.assetsVerbose || options.verbose
      ? asset.findings
      : asset.findings.filter((f) => f.status === 'fail' || f.status === 'warn');

    for (const f of shown) {
      const mark = (STATUS_MARK[f.status] ?? STATUS_MARK.skip)(c);
      const sev =
        f.status === 'fail' ? ` ${c.dim}[${f.severity}]${c.reset}` : '';
      lines.push(`    ${mark} ${f.title}${sev}`);
      if ((f.status === 'fail' || f.status === 'warn') && f.detail) {
        lines.push(`         ${c.dim}${wrap(f.detail, 70, '         ')}${c.reset}`);
      }
    }
    const passed = asset.findings.filter((f) => f.status === 'pass').length;
    const skipped = asset.findings.filter((f) => f.status === 'skip').length;
    lines.push(
      `    ${c.dim}${passed} passed · ${asset.failures.critical + asset.failures.high + asset.failures.medium + asset.failures.low} failed · ${skipped} not applicable${c.reset}`,
    );
    lines.push('');
  }

  lines.push(`  ${c.dim}Verification code: ${report.verificationCode}${c.reset}`);
  lines.push(
    `  ${c.dim}Self-assessment of public configuration. Not an accredited audit.${c.reset}`,
  );
  lines.push('');
  return lines.join('\n');
}

/** @param {string} text @param {number} width @param {string} indent */
function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const out = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      out.push(line.trim());
      line = w;
    } else {
      line += ' ' + w;
    }
  }
  if (line.trim()) out.push(line.trim());
  return out.join('\n' + indent);
}

function blankColors() {
  /** @type {Record<string, string>} */
  const b = {};
  for (const k of Object.keys(COLORS)) b[k] = '';
  return b;
}
