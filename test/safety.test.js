/**
 * certadel is passive by construction, and this is where that claim is enforced rather
 * than asserted. It fails the build if the code grows a way to write to a target, to
 * choose an arbitrary HTTP method, or to reach the network outside the one guarded
 * client. The equivalent of a read-only test for an offensive-adjacent tool.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Normalise to forward slashes so path matching works identically on Windows.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..').replace(/\\/g, '/');

function sources(dir, acc = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'test') continue;
    const p = join(dir, entry);
    const norm = p.replace(/\\/g, '/');
    if (statSync(p).isDirectory()) sources(p, acc);
    else if (norm.endsWith('.js')) acc.push(norm);
  }
  return acc;
}

const files = sources(ROOT);
const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

test('there are source files to inspect', () => {
  assert.ok(files.length > 15);
});

test('the HTTP request agents are imported by exactly one module', () => {
  // The structural invariant behind "passive": only the guarded client may import the
  // node:http / node:https request agents. Any other module reaching for them would be
  // a second, unguarded way onto the network. Detecting the import is robust to how the
  // call is written (agent.request(), https.get(), destructured, aliased).
  const importers = files.filter((f) => {
    const code = stripComments(readFileSync(f, 'utf8'));
    return /from\s+['"]node:https?['"]/.test(code) || /require\(\s*['"]node:https?['"]\s*\)/.test(code);
  });
  assert.deepEqual(
    importers.map((f) => f.replace(ROOT + '/', '')).sort(),
    ['src/net/http.js'],
    'all HTTP traffic must funnel through the single guarded client',
  );
});

test('the guarded client only ever issues GET or HEAD', () => {
  const http = readFileSync(join(ROOT, 'src/net/http.js'), 'utf8');
  // The method is normalised to HEAD only when explicitly requested, else GET.
  assert.match(http, /method === 'HEAD' \? 'HEAD' : 'GET'/);
  // No source may name a mutating HTTP method as a request method.
  for (const f of files) {
    const code = stripComments(readFileSync(f, 'utf8'));
    assert.doesNotMatch(
      code,
      /method\s*[:=]\s*['"`](POST|PUT|PATCH|DELETE)['"`]/i,
      `${f.replace(ROOT + '/', '')} must not issue a write method`,
    );
  }
});

test('no source opens a socket or shells out behind the client', () => {
  for (const f of files) {
    const code = stripComments(readFileSync(f, 'utf8'));
    assert.doesNotMatch(code, /child_process/, `${f} must not spawn processes`);
    assert.doesNotMatch(code, /net\.(connect|createConnection)/, `${f} must not open raw sockets`);
    assert.doesNotMatch(code, /dgram/, `${f} must not open UDP sockets`);
  }
});

test('nothing writes to a target: no fs writes reach outside report output', () => {
  // The tool writes reports to disk, but only from the CLI's artefact writer and never
  // from the assessment engine. The engine (src/, excluding report/) must not import fs.
  // Scope this to the assessment engine itself: everything under src/ except the report
  // renderers (which return strings; the CLI, not the engine, writes them) and scope.js
  // (which only reads). The CLI and the dev-only sample generator legitimately write.
  const engine = files.filter(
    (f) =>
      f.includes('/src/') &&
      !f.includes('/src/report/') &&
      !f.includes('/src/license/') && // the license store legitimately persists an activation
      !f.endsWith('/scope.js'),
  );
  assert.ok(engine.length > 8, 'the engine has files to inspect');
  for (const f of engine) {
    const code = stripComments(readFileSync(f, 'utf8'));
    assert.doesNotMatch(
      code,
      /writeFile|createWriteStream|appendFile/,
      `${f.replace(ROOT + '/', '')} in the assessment engine must not write files`,
    );
  }
});
