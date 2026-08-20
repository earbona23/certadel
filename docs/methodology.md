# Methodology: what certadel does on the wire

certadel is **passive**. It assesses the security posture a host presents to any
ordinary visitor, using only the interactions a browser or a mail server would already
make. It never attempts to exploit, authenticate, enumerate, fuzz, or overwhelm. This
page is the exact, auditable account of every network interaction it performs, so you
can hand it to whoever authorizes the assessment.

## The authorization gate

certadel refuses to touch a host that is not written in the scope file. There is no flag
to bypass this, no wildcard that expands to "the internet", and the scope guard is
consulted before every single connection, including before following any redirect. This
is enforced in [`src/scope.js`](../src/scope.js) and covered by
[`test/scope.test.js`](../test/scope.test.js).

## Exactly what it sends

Per authorized host, certadel performs:

**TLS handshakes** ([`src/net/tls.js`](../src/net/tls.js))
- One handshake to port 443 to read the negotiated protocol, cipher and certificate.
- Two further handshakes that *offer* TLS 1.0 and TLS 1.1, to learn whether the server
  still accepts them. These complete the handshake and immediately close; no application
  data is ever sent. (Disable with `--no-legacy-tls`.)

**HTTP GET requests** ([`src/net/http.js`](../src/net/http.js)) — GET or HEAD only, no
request body, capped response size, bounded redirects that never leave scope:
- `https://<host>/` — the main response, for headers and cookies.
- `http://<host>/` — to observe whether plain HTTP redirects to HTTPS.
- `https://<host>/.well-known/security.txt` — RFC 9116 contact information.
- `https://mta-sts.<host>/.well-known/mta-sts.txt` — only if an MTA-STS DNS record exists.

**DNS queries** ([`src/net/dns.js`](../src/net/dns.js)) via the system resolver:
- `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA` at the host.
- `TXT` at `_dmarc.<host>`, `_mta-sts.<host>`, `_smtp._tls.<host>`.
- `TXT` at `<selector>._domainkey.<host>` for a short list of common DKIM selectors.

**One DNS-over-HTTPS query** for DNSSEC status, to a validating resolver
(`cloudflare-dns.com` by default), reading the Authenticated Data flag. This is the only
call to third-party infrastructure; it queries *about* your domain, it does not touch
your host. Disable with `--no-dnssec`.

## What it never does

- No POST, PUT, PATCH, DELETE — the HTTP client cannot issue them (enforced by
  [`test/safety.test.js`](../test/safety.test.js)).
- No authentication, no credentials, no session establishment.
- No port scanning, no path or subdomain enumeration, no directory brute-forcing.
- No payloads, no injection, no fuzzing, no attempt to trigger a fault.
- No rate that resembles a stress test — assets are assessed one at a time by default.
- No writes, anywhere, ever. The only files written are the report artefacts you ask for.

## Separation of collection and judgement

Everything that touches the network lives in `src/net/` and `src/assess.js`. Everything
that decides a grade is a pure function over the collected evidence
(`src/checks/`, `src/scoring/`). That separation is why the entire grading surface is
tested deterministically against synthetic evidence, and why a host that cannot be
reached degrades into honest *skip* / *fail* results instead of crashing the run.
