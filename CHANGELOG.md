# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-20

First release.

### Added
- Passive external posture assessment across six dimensions — transport security (TLS),
  HTTP security headers, cookie flags, DNS hygiene, email authentication, and exposure —
  covering roughly two dozen individual controls.
- A transparent, weighted certification rubric with gates: a critical failure means Not
  Certified regardless of score, a high failure caps the tier at Bronze.
- Company-level roll-up graded by the weakest asset, not the average.
- Self-contained HTML certificate (light/dark, printable), SVG badge, and machine-readable
  JSON. A verification code derived from the posture makes a self-issued certificate
  re-checkable.
- `--min-tier` CI gate: exit non-zero when the organisation falls below a required tier.
- An authorization scope file the tool refuses to exceed, and a safe HTTP client
  restricted to GET/HEAD with bounded redirects that never leave scope.
- Zero runtime dependencies; zero test dependencies (Node's built-in test runner).

### Security
- Passive by construction. All network access funnels through one guarded client that
  cannot issue a write method, and `test/safety.test.js` fails the build if a second
  network path, a write method, or a raw socket is ever introduced.
- Report output escapes all host-controlled text, so a hostile Server banner or
  certificate field renders as text rather than executing.

[1.0.0]: https://github.com/earbona23/certadel/releases/tag/v1.0.0
