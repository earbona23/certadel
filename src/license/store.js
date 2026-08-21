/**
 * Where an activated certadel license lives on disk, and the single question the CLI
 * asks: is this a Pro session? Verified afresh from disk on every run, so an expired or
 * tampered file simply stops being Pro. No network, ever.
 *
 * @module license/store
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import path from 'node:path';
import { verifyLicenseKey } from './verify.js';
import { PRO_FEATURES } from './keys.js';

/** @returns {string} */
export function licensePath() {
  const home = homedir();
  let base;
  if (process.env.CERTADEL_CONFIG_DIR) base = process.env.CERTADEL_CONFIG_DIR;
  else if (platform() === 'win32') base = process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
  else if (platform() === 'darwin') base = path.join(home, 'Library', 'Application Support');
  else base = process.env.XDG_CONFIG_HOME ?? path.join(home, '.config');
  return path.join(base, 'certadel', 'license.json');
}

/**
 * @param {string} key
 * @returns {Promise<import('./verify.js').LicensePayload>}
 */
export async function activate(key) {
  const result = verifyLicenseKey(key);
  if (!result.valid) throw new Error(result.reason ?? 'Invalid license key.');
  const file = licensePath();
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify({ key }, null, 2) + '\n', { mode: 0o600 });
  return /** @type {import('./verify.js').LicensePayload} */ (result.payload);
}

/**
 * @param {Object} [options]
 * @param {string} [options.key]
 * @returns {Promise<{ pro: boolean, plan: string | null, features: string[], sub: string | null, reason: string | null }>}
 */
export async function entitlement(options = {}) {
  let key = options.key ?? process.env.CERTADEL_LICENSE_KEY ?? null;
  if (!key) {
    try {
      key = JSON.parse(await readFile(licensePath(), 'utf8')).key;
    } catch {
      return { pro: false, plan: null, features: [], sub: null, reason: 'No license activated.' };
    }
  }
  const result = verifyLicenseKey(key);
  if (!result.valid) return { pro: false, plan: null, features: [], sub: null, reason: result.reason };
  const payload = /** @type {import('./verify.js').LicensePayload} */ (result.payload);
  const features = payload.features && payload.features.length ? payload.features : [...PRO_FEATURES];
  return { pro: true, plan: payload.plan ?? 'pro', features, sub: payload.sub ?? null, reason: null };
}
