/**
 * The only way certadel speaks HTTP, and the reason it can call itself passive.
 *
 * This client can do exactly one thing: fetch a resource. The method is restricted to
 * GET and HEAD, the response body is capped, redirects are bounded and never leave the
 * authorized scope, and every request is checked against the scope guard before a
 * socket opens. There is no request-body parameter and no way to choose an arbitrary
 * method, so no check -- present or future -- can be coaxed into writing to a target.
 *
 * @module net/http
 */

import https from 'node:https';
import http from 'node:http';

/**
 * @typedef {Object} FetchResult
 * @property {number} status
 * @property {string} url                Final URL after redirects.
 * @property {Record<string, string | string[]>} headers  Lower-cased header names.
 * @property {string[]} setCookie        Raw Set-Cookie values, unmerged.
 * @property {string} body               Response body, truncated to the byte cap.
 * @property {boolean} truncated         True if the body hit the cap.
 * @property {{ url: string, status: number, location: string }[]} redirects
 * @property {import('node:tls').PeerCertificate | null} peerCertificate
 * @property {string | null} tlsProtocol Negotiated TLS protocol on the final hop.
 */

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 512 * 1024;
const USER_AGENT =
  'certadel/1.0 (+https://github.com/earbona23/certadel; passive posture assessment)';

/**
 * Fetch a URL passively.
 *
 * @param {string} url
 * @param {Object} [options]
 * @param {'GET' | 'HEAD'} [options.method]
 * @param {(host: string) => boolean} [options.inScope]  Scope guard; every hop is checked.
 * @param {number} [options.timeout]
 * @param {number} [options.maxRedirects]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<FetchResult>}
 */
export async function fetchResource(url, options = {}) {
  const method = options.method === 'HEAD' ? 'HEAD' : 'GET';
  const inScope = options.inScope ?? (() => true);
  const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;

  /** @type {{ url: string, status: number, location: string }[]} */
  const redirects = [];
  let current = url;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch {
      throw new HttpError(`Malformed URL: ${current}`);
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new HttpError(`Refusing non-HTTP(S) URL: ${current}`);
    }
    if (!inScope(parsed.hostname)) {
      throw new HttpError(
        `Refusing to follow '${parsed.hostname}': it is outside the authorized scope. ` +
          'A redirect tried to send the assessment off-scope and was stopped.',
      );
    }

    const res = await once(parsed, method, timeout, options.signal);

    const location = firstHeader(res.headers, 'location');
    if (res.statusCode >= 300 && res.statusCode < 400 && location && hop < maxRedirects) {
      const next = new URL(location, parsed).toString();
      redirects.push({ url: current, status: res.statusCode, location: next });
      current = next;
      continue;
    }

    return {
      status: res.statusCode,
      url: current,
      headers: res.headers,
      setCookie: res.setCookie,
      body: res.body,
      truncated: res.truncated,
      redirects,
      peerCertificate: res.peerCertificate,
      tlsProtocol: res.tlsProtocol,
    };
  }

  throw new HttpError(`Too many redirects (>${maxRedirects}) starting from ${url}`);
}

/**
 * A single request/response, no redirect handling.
 *
 * @param {URL} parsed
 * @param {'GET' | 'HEAD'} method
 * @param {number} timeout
 * @param {AbortSignal} [signal]
 */
function once(parsed, method, timeout, signal) {
  const isHttps = parsed.protocol === 'https:';
  const agent = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const req = agent.request(
      {
        method,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        signal,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: '*/*',
          Connection: 'close',
        },
        // The TLS inspector judges the certificate itself. Here we must still connect
        // to hosts whose chain is broken -- that is exactly the finding we want to
        // report -- so certificate errors do not abort the fetch. This client never
        // sends credentials or data, so it has nothing to leak to a bad certificate.
        rejectUnauthorized: false,
        timeout,
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        let total = 0;
        let truncated = false;

        if (method === 'HEAD') {
          res.resume();
        } else {
          res.on('data', (chunk) => {
            if (truncated) return;
            total += chunk.length;
            if (total > MAX_BODY_BYTES) {
              truncated = true;
              chunks.push(chunk.subarray(0, chunk.length - (total - MAX_BODY_BYTES)));
              res.destroy();
            } else {
              chunks.push(chunk);
            }
          });
        }

        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          const socket = /** @type {import('node:tls').TLSSocket} */ (res.socket);
          const peerCertificate =
            isHttps && socket && typeof socket.getPeerCertificate === 'function'
              ? socket.getPeerCertificate(true)
              : null;
          const tlsProtocol =
            isHttps && socket && typeof socket.getProtocol === 'function'
              ? socket.getProtocol()
              : null;
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: lowerCaseHeaders(res.headers),
            setCookie: Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [],
            body: Buffer.concat(chunks).toString('utf8'),
            truncated,
            peerCertificate:
              peerCertificate && Object.keys(peerCertificate).length ? peerCertificate : null,
            tlsProtocol,
          });
        };

        res.on('end', finish);
        res.on('close', finish);
        res.on('error', reject);
      },
    );

    req.on('timeout', () => req.destroy(new HttpError(`Request to ${parsed.host} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

/** @param {import('node:http').IncomingHttpHeaders} headers */
function lowerCaseHeaders(headers) {
  /** @type {Record<string, string | string[]>} */
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) out[k.toLowerCase()] = v;
  }
  return out;
}

/** @param {Record<string, string | string[]>} headers @param {string} name */
function firstHeader(headers, name) {
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

export class HttpError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'HttpError';
  }
}
