/**
 * Offline verification of a certadel Pro license key.
 *
 * A key is `CERTADEL-<base64url(payload)>.<base64url(signature)>`, the payload JSON and
 * the signature Ed25519 over the payload bytes. Verification is entirely local: no
 * network, no telemetry. The tool confirms a key was issued by the owner and has not
 * expired, and nothing else.
 *
 * @module license/verify
 */

import { verify as edVerify, createPublicKey } from 'node:crypto';
import { LICENSE_PUBLIC_KEY_PEM, KEY_PREFIX } from './keys.js';

/**
 * @typedef {Object} LicensePayload
 * @property {string} sub
 * @property {string} plan
 * @property {number} iat
 * @property {number} [exp]
 * @property {string[]} [features]
 */

/**
 * @param {string} key
 * @param {Object} [options]
 * @param {string} [options.publicKeyPem]  Override, for tests.
 * @param {number} [options.now]           Epoch seconds, for deterministic tests.
 * @returns {{ valid: boolean, payload: LicensePayload | null, reason: string | null }}
 */
export function verifyLicenseKey(key, options = {}) {
  if (typeof key !== 'string' || !key.startsWith(KEY_PREFIX)) {
    return fail('The key is not a certadel license key.');
  }
  const body = key.slice(KEY_PREFIX.length);
  const dot = body.indexOf('.');
  if (dot === -1) return fail('The key is malformed (missing signature).');

  let payloadBytes;
  let signature;
  try {
    payloadBytes = Buffer.from(body.slice(0, dot), 'base64url');
    signature = Buffer.from(body.slice(dot + 1), 'base64url');
  } catch {
    return fail('The key is not valid base64url.');
  }

  let publicKey;
  try {
    publicKey = createPublicKey(options.publicKeyPem ?? LICENSE_PUBLIC_KEY_PEM);
  } catch {
    return fail('The embedded public key could not be loaded.');
  }

  let ok = false;
  try {
    ok = edVerify(null, payloadBytes, publicKey, signature);
  } catch {
    ok = false;
  }
  if (!ok) return fail('The signature does not verify. This key was not issued for certadel.');

  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString('utf8'));
  } catch {
    return fail('The signed payload is not valid JSON.');
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now > payload.exp) {
    return { valid: false, payload, reason: 'The license expired.' };
  }
  return { valid: true, payload, reason: null };
}

/** @param {string} reason */
function fail(reason) {
  return { valid: false, payload: null, reason };
}
