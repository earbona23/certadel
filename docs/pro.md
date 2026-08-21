# certadel Pro

**Everything that produces the certificate is free** — the full assessment across all six
dimensions, the terminal summary, the self-contained HTML certificate, the SVG badge, the
JSON report, and the `--min-tier` CI gate. certadel is MIT-licensed and its whole engine is
open. Pro exists so teams and consultants who rely on it can fund its upkeep, and it unlocks
*additive* outputs — never the certificate itself.

## What Pro unlocks

| Feature | How |
|---|---|
| **SARIF export** — findings in GitHub's Security tab, or any SARIF-aware SIEM/dashboard | `certadel assess … --out ./r --format sarif` |
| **Baseline comparison** — score a tenant against a stored earlier run to catch regressions | `--baseline` *(rolling out)* |

## How activation works

A license key is an Ed25519-signed token, verified **entirely offline** against a public
key embedded in the tool. No account, no telemetry, nothing leaves your machine.

```sh
certadel activate CERTADEL-xxxxx.yyyyy
certadel license
```

The key can also be supplied per-run via the `CERTADEL_LICENSE_KEY` environment variable,
handy for CI secrets.

## Support the project

- **GitHub Sponsors:** https://github.com/sponsors/earbona23
- **Patreon:** https://www.patreon.com/EduardArbona

Sponsoring is never required to produce a certificate — Pro is additive outputs only.
