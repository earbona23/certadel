/**
 * Inspects the TLS a host actually serves, by completing real handshakes and reading
 * what came back. It never sends application data -- it opens a connection, records the
 * negotiated protocol, cipher and certificate, and closes.
 *
 * Two things are measured that a single connection cannot show. First, the certificate
 * and the strongest protocol, from one ordinary handshake. Second, whether the host is
 * still willing to speak the obsolete protocols (TLS 1.0 and 1.1), which is answered by
 * *trying* to negotiate each one and seeing whether the server agrees. Offering an
 * obsolete protocol is a real finding, so the tool has to ask the question directly.
 *
 * @module net/tls
 */

import tls from 'node:tls';

/**
 * @typedef {Object} TlsEvidence
 * @property {boolean} connected
 * @property {string} [error]
 * @property {string | null} protocol            Strongest protocol negotiated.
 * @property {string | null} cipherName
 * @property {boolean} authorized                Did the chain validate against system roots?
 * @property {string | null} authorizationError
 * @property {Object | null} certificate         Flattened certificate facts.
 * @property {string[]} legacyProtocols          Obsolete protocols the host still accepts.
 * @property {boolean} legacyProbed              Whether the legacy probes ran.
 */

const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * Gather TLS evidence for a host on the given port.
 *
 * @param {string} host
 * @param {Object} [options]
 * @param {number} [options.port]
 * @param {number} [options.timeout]
 * @param {boolean} [options.probeLegacy] Attempt TLS 1.0/1.1 handshakes. Default true.
 * @returns {Promise<TlsEvidence>}
 */
export async function inspectTls(host, options = {}) {
  const port = options.port ?? 443;
  const timeout = options.timeout ?? HANDSHAKE_TIMEOUT_MS;

  const main = await handshake(host, port, timeout, {});
  if (!main.connected) {
    return {
      connected: false,
      error: main.error,
      protocol: null,
      cipherName: null,
      authorized: false,
      authorizationError: main.error ?? null,
      certificate: null,
      legacyProtocols: [],
      legacyProbed: false,
    };
  }

  const legacyProtocols = [];
  let legacyProbed = false;
  if (options.probeLegacy !== false) {
    legacyProbed = true;
    for (const version of ['TLSv1', 'TLSv1.1']) {
      const probe = await handshake(host, port, timeout, {
        minVersion: version,
        maxVersion: version,
      });
      if (probe.connected && probe.protocol) legacyProtocols.push(probe.protocol);
    }
  }

  return {
    connected: true,
    protocol: main.protocol,
    cipherName: main.cipherName,
    authorized: main.authorized,
    authorizationError: main.authorizationError,
    certificate: main.certificate,
    legacyProtocols,
    legacyProbed,
  };
}

/**
 * One handshake with a specific protocol constraint.
 *
 * @param {string} host
 * @param {number} port
 * @param {number} timeout
 * @param {{ minVersion?: string, maxVersion?: string }} versions
 */
function handshake(host, port, timeout, versions) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve(value);
    };

    const socket = tls.connect({
      host,
      port,
      servername: host,
      // We validate the chain ourselves from the reported result; connecting with
      // rejectUnauthorized:false lets us also inspect hosts whose chain is broken,
      // which is precisely a finding worth reporting rather than an error to abort on.
      rejectUnauthorized: false,
      timeout,
      ...(versions.minVersion ? { minVersion: /** @type {any} */ (versions.minVersion) } : {}),
      ...(versions.maxVersion ? { maxVersion: /** @type {any} */ (versions.maxVersion) } : {}),
    });

    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      done({
        connected: true,
        protocol: socket.getProtocol(),
        cipherName: cipher ? cipher.name : null,
        authorized: socket.authorized,
        authorizationError: socket.authorized
          ? null
          : String(socket.authorizationError ?? 'unknown'),
        certificate: cert && Object.keys(cert).length ? flattenCertificate(cert) : null,
      });
    });

    socket.on('timeout', () => done({ connected: false, error: 'handshake timed out' }));
    socket.on('error', (err) => done({ connected: false, error: err.message }));
  });
}

/**
 * Reduce Node's peer-certificate object to the facts the checks reason about.
 *
 * @param {import('node:tls').DetailedPeerCertificate} cert
 */
export function flattenCertificate(cert) {
  const altNames =
    typeof cert.subjectaltname === 'string'
      ? cert.subjectaltname
          .split(',')
          .map((s) => s.trim().replace(/^DNS:/i, ''))
          .filter(Boolean)
      : [];

  return {
    subjectCommonName: cert.subject && cert.subject.CN ? cert.subject.CN : null,
    issuer:
      cert.issuer && (cert.issuer.O || cert.issuer.CN)
        ? cert.issuer.O || cert.issuer.CN
        : null,
    validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
    validTo: cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
    altNames,
    keyType: cert.asn1Curve ? 'EC' : cert.modulus ? 'RSA' : cert.pubkey ? 'unknown' : null,
    keyBits: typeof cert.bits === 'number' ? cert.bits : null,
    curve: cert.asn1Curve ?? null,
    serialNumber: cert.serialNumber ?? null,
    signatureAlgorithm: /** @type {any} */ (cert).sigalg ?? null,
  };
}
