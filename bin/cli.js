#!/usr/bin/env node
/**
 * certadel command-line interface.
 *
 * Usage:
 *   certadel assess --scope scope.json [--out ./report] [--format all]
 *                   [--min-tier silver] [--concurrency 1] [--verbose] [--no-color]
 *   certadel init [--out scope.json]
 *   certadel checks
 *   certadel --help
 *
 * The `--min-tier` flag turns the tool into a CI gate: the process exits non-zero if the
 * organisation does not reach the required tier, so a pipeline can block a deploy on a
 * regression in posture.
 *
 * @module bin/cli
 */

import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadScope, ScopeError } from '../src/scope.js';
import { assessScope } from '../src/assess.js';
import { serializeReport } from '../src/report/serialize.js';
import { renderHtml } from '../src/report/html.js';
import { renderBadge } from '../src/report/badge.js';
import { renderTerminal } from '../src/report/terminal.js';
import { CHECK_GROUPS } from '../src/checks/index.js';
import { TIERS, tierRank } from '../src/scoring/rubric.js';
import { renderSarif } from '../src/report/sarif.js';
import { entitlement, activate } from '../src/license/store.js';
import { PRO_FEATURES } from '../src/license/keys.js';

const HERE = dirname(fileURLToPath(import.meta.url));

async function toolVersion() {
  try {
    const pkg = JSON.parse(await readFile(join(HERE, '..', 'package.json'), 'utf8'));
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (key.startsWith('no-')) {
        args[key.slice(3)] = false;
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        args[key] = argv[++i];
      } else {
        args[key] = true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

const HELP = `certadel — passive external security-posture assessment & certification

USAGE
  certadel assess --scope <file>   Assess the authorized assets and grade them
  certadel init                    Write a starter scope file you then edit
  certadel checks                  List every check, its dimension and points
  certadel activate <key>          Activate a Pro license (verified offline)
  certadel license                 Show the current entitlement
  certadel --help                  Show this help

ASSESS OPTIONS
  --scope <file>        Authorized-scope JSON file (required). See 'certadel init'.
  --out <dir>           Directory for the HTML/JSON/SVG artefacts (default: none)
  --format <list>       Comma list of html,json,badge,all (default: all when --out set)
                        'sarif' is a Pro output (GitHub Security tab / SIEM)
  --min-tier <tier>     Exit non-zero if the org tier is below this (CI gate)
                        One of: platinum, gold, silver, bronze
  --concurrency <n>     Assets assessed in parallel (default: 1, a polite guest)
  --timeout <ms>        Per-connection timeout (default: 10000)
  --no-legacy-tls       Skip probing for TLS 1.0/1.1 (faster, less complete)
  --no-dnssec           Skip the DNS-over-HTTPS DNSSEC check
  --verbose             Show passing and not-applicable checks too
  --no-color            Disable ANSI colour

certadel only inspects PUBLIC configuration of hosts you list in the scope file, over
GET/HEAD and DNS. It never exploits, never authenticates, and never writes. Run it only
against assets you are authorized to assess.

Free: every assessment, terminal + HTML certificate + badge + JSON, and the CI gate.
Pro (a license unlocks): SARIF export and baseline comparison — see #pro. Sponsor:
https://github.com/sponsors/earbona23  ·  https://www.patreon.com/EduardArbona`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (args.help || args.h || command === 'help' || !command) {
    console.log(HELP);
    return 0;
  }
  if (args.version || args.v || command === 'version') {
    console.log(await toolVersion());
    return 0;
  }
  if (command === 'activate') return cmdActivate(args);
  if (command === 'license') return cmdLicense();
  if (command === 'checks') return cmdChecks();
  if (command === 'init') return cmdInit(args);
  if (command === 'assess') return cmdAssess(args);

  console.error(`Unknown command '${command}'. Run 'certadel --help'.`);
  return 2;
}

function cmdChecks() {
  const evidence = emptyEvidence();
  console.log('\ncertadel checks\n');
  for (const group of CHECK_GROUPS) {
    const results = group(evidence);
    for (const r of results) {
      console.log(
        `  ${r.dimension.padEnd(10)} ${String(r.max).padStart(3)}pt  ${r.id.padEnd(28)} ${r.title}`,
      );
    }
  }
  console.log('\nSkipped rows above reflect an empty sample; real runs populate them.\n');
  return 0;
}

async function cmdInit(args) {
  const out = typeof args.out === 'string' ? args.out : 'scope.json';
  const template = {
    organization: 'Example Corp',
    authorizedBy: 'you@example.com',
    reference: 'engagement or ticket id (optional)',
    assets: ['example.com', 'www.example.com'],
  };
  await writeFile(out, JSON.stringify(template, null, 2) + '\n', { flag: 'wx' }).catch((e) => {
    if (e.code === 'EEXIST') {
      throw new CliError(`'${out}' already exists; refusing to overwrite it.`);
    }
    throw e;
  });
  console.log(
    `Wrote ${out}. Edit it to name your organisation and the hosts you are authorized to assess,\n` +
      `then run:  certadel assess --scope ${out} --out ./report`,
  );
  return 0;
}

async function cmdAssess(args) {
  if (!args.scope || typeof args.scope !== 'string') {
    throw new CliError("Missing --scope <file>. Run 'certadel init' to create one.");
  }

  const scope = await loadScope(args.scope);
  const color = args.color !== false && process.stdout.isTTY;
  const version = await toolVersion();

  process.stderr.write(
    `Assessing ${scope.assets.length} asset(s) for ${scope.organization} — passive, public config only.\n`,
  );

  const assessments = await assessScope(scope, {
    concurrency: args.concurrency ? Number(args.concurrency) : 1,
    timeout: args.timeout ? Number(args.timeout) : undefined,
    probeLegacyTls: args['legacy-tls'] !== false,
    checkDnssec: args.dnssec !== false,
    onAssetStart: (host, i, total) =>
      process.stderr.write(`  [${i + 1}/${total}] ${host}\n`),
  });

  const report = serializeReport(scope, assessments, { toolVersion: version });
  console.log(renderTerminal(report, { color, verbose: Boolean(args.verbose) }));

  if (typeof args.out === 'string') {
    await writeArtefacts(report, args.out, args.format);
  }

  if (typeof args['min-tier'] === 'string') {
    const required = args['min-tier'].toLowerCase();
    if (!TIERS.some((t) => t.id === required)) {
      throw new CliError(`--min-tier must be one of: ${TIERS.map((t) => t.id).join(', ')}`);
    }
    const meets = tierRank(report.rollup.tier) <= tierRank(required);
    if (!meets) {
      process.stderr.write(
        `\nGate failed: ${report.organization} is ${report.rollup.tierLabel}, below the required ${required}.\n`,
      );
      return 1;
    }
    process.stderr.write(`\nGate passed: ${report.rollup.tierLabel} meets the required ${required}.\n`);
  }

  return 0;
}

async function writeArtefacts(report, dir, format) {
  await mkdir(dir, { recursive: true });
  const want = typeof format === 'string' ? format.split(',').map((s) => s.trim()) : ['all'];
  const all = want.includes('all');
  const written = [];

  if (all || want.includes('json')) {
    const p = join(dir, 'certadel-report.json');
    await writeFile(p, JSON.stringify(report, null, 2) + '\n');
    written.push(p);
  }
  if (all || want.includes('html')) {
    const p = join(dir, 'certadel-certificate.html');
    await writeFile(p, renderHtml(report));
    written.push(p);
  }
  if (all || want.includes('badge')) {
    const p = join(dir, 'certadel-badge.svg');
    await writeFile(p, renderBadge({ tier: report.rollup.tier, score: report.rollup.score }));
    written.push(p);
  }
  // SARIF is a Pro output. 'all' does not silently include it; you ask for it by name.
  if (want.includes('sarif')) {
    if (await ensurePro('sarif')) {
      const p = join(dir, 'certadel.sarif');
      await writeFile(p, renderSarif(report, { version: await toolVersion() }));
      written.push(p);
    }
  }
  for (const p of written) process.stderr.write(`  wrote ${p}\n`);
}

/** True if the current session is entitled to a Pro feature; prints how to unlock otherwise. */
async function ensurePro(feature) {
  const ent = await entitlement();
  if (ent.pro && ent.features.includes(feature)) return true;
  process.stderr.write(
    `\nThe '${feature}' export needs a certadel Pro license.\n` +
      `  Activate:  certadel activate <key>\n` +
      `  Get one / sponsor:  https://github.com/earbona23/certadel#pro\n` +
      `Every assessment, plus the HTML certificate, badge and JSON, is free.\n`,
  );
  return false;
}

async function cmdActivate(args) {
  const key = args._[1];
  if (!key) {
    process.stderr.write('Usage: certadel activate <license-key>\n');
    return 2;
  }
  try {
    const payload = await activate(key);
    process.stdout.write(`Activated ${payload.plan} license for ${payload.sub}. Thank you for supporting certadel.\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`Activation failed: ${e.message}\n`);
    return 1;
  }
}

async function cmdLicense() {
  const ent = await entitlement();
  if (ent.pro) {
    process.stdout.write(`Pro (${ent.plan}) — ${ent.sub}\nUnlocked: ${ent.features.join(', ')}\n`);
  } else {
    process.stdout.write(
      `Free tier. ${ent.reason ?? ''}\nPro unlocks: ${PRO_FEATURES.join(', ')} — https://github.com/earbona23/certadel#pro\n`,
    );
  }
  return 0;
}

function emptyEvidence() {
  return {
    host: 'example.com',
    https: null,
    httpsError: null,
    http: null,
    tls: null,
    dns: null,
    dmarcTxt: [],
    mtaSts: { txt: [], policyMode: null },
    tlsRpt: [],
    dkim: [],
    securityTxt: null,
    dnssec: null,
  };
}

class CliError extends Error {}

main()
  .then((code) => process.exit(code ?? 0))
  .catch((err) => {
    if (err instanceof ScopeError || err instanceof CliError) {
      process.stderr.write(`\nerror: ${err.message}\n`);
    } else {
      process.stderr.write(`\nunexpected error: ${err && err.stack ? err.stack : err}\n`);
    }
    process.exit(2);
  });
