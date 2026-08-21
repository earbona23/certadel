/**
 * The embedded Ed25519 public key that certadel Pro license keys are verified against.
 *
 * Public by design: it can only *verify* a signature, never create one. The matching
 * private key stays with the project owner and never ships. Every assessment, and the
 * full HTML certificate, badge and JSON, are free and unlocked for everyone; a license
 * only flips on the additive Pro exports. Signing lets the owner issue keys the tool
 * trusts entirely offline — no account, no phone-home.
 *
 * @module license/keys
 */

export const LICENSE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhYsX2KG3vKjSZhkO5s5P6fyq/pdyUEUGgyK0WePR+8s=
-----END PUBLIC KEY-----`;

/** Feature flags a license may unlock. Additive only. */
export const PRO_FEATURES = Object.freeze(['sarif', 'baseline']);

export const KEY_PREFIX = 'CERTADEL-';
