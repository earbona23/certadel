# The certadel rubric

How a posture becomes a grade, in full. Everything here is enforced by
[`src/scoring/rubric.js`](../src/scoring/rubric.js) and covered by
[`test/scoring.test.js`](../test/scoring.test.js). The point of writing it down is that
a grade you cannot argue with is a grade nobody trusts.

## Two ideas

**A weighted score.** Every check contributes points toward its dimension. The
dimensions are weighted by blast radius, so a failure of transport security costs far
more than a missing `Permissions-Policy` header. The score is the share of *applicable*
points earned:

```
score = 100 × (points earned) / (points possible, excluding not-applicable checks)
```

Checks that do not apply — email authentication on a domain that sends no mail, cookie
flags on a site that sets no cookies — are marked **not applicable** and leave the
denominator entirely. A domain is never rewarded or punished for something it does not
do.

**Gates.** A high score cannot paper over a hole. After the score is computed, gates can
lower the tier — never raise it:

| Gate | Condition | Effect |
|---|---|---|
| Critical failure | any check fails at **critical** severity | Not certified, whatever the score |
| High failure | any check fails at **high** severity | Capped at **Bronze** |

A certificate that let you reach Gold with an expired certificate or TLS 1.0 still
enabled would be worse than no certificate, because someone would rely on it.

## Tiers

| Tier | Score floor | Also requires |
|---|---|---|
| **Platinum** | 95 | no high or critical failures |
| **Gold** | 85 | no critical failures; no high failures (else Bronze) |
| **Silver** | 70 | no critical failures; no high failures (else Bronze) |
| **Bronze** | 50 | no critical failures |
| **Not certified** | below 50, **or** any critical failure | — |

## Dimensions and weights

Points are the maximum each dimension can contribute when every check applies. Because
the score is a percentage of *applicable* points, these are effectively relative weights.

| Dimension | Points | What it covers |
|---|---:|---|
| Transport security (TLS) | 40 | HTTPS availability, protocol versions, certificate validity and expiry, key strength, forward secrecy, HSTS |
| HTTP security headers | 23 | CSP, X-Content-Type-Options, framing protection, Referrer-Policy, Permissions-Policy, version disclosure |
| Cookie flags | 22 | Secure, HttpOnly, SameSite on Set-Cookie |
| Email authentication | 25 | SPF, DKIM, DMARC policy strength, MTA-STS, TLS-RPT |
| DNS & domain hygiene | 12 | CAA, nameserver redundancy, DNSSEC |
| Exposure & hygiene | 10 | HTTP→HTTPS redirect, security.txt (RFC 9116), mixed content |

Transport is the heaviest because it is the control everything else rides on: if the
certificate is invalid or the connection can be downgraded, no header protects anyone.

## Company roll-up

An organisation with several assets is graded by its **weakest** asset, not its average.
An attacker targets the softest host, so certifying a company at the mean would certify a
fiction. The reported score is the mean, for trend; the tier follows the floor.

## What a passing grade does and does not mean

A high certadel grade means the *publicly observable configuration* of the assessed
hosts follows current best practice. It does **not** mean the application is free of
vulnerabilities: certadel never tests authentication, authorization, business logic,
injection, or anything requiring interaction beyond reading public configuration. It is
a strong, cheap, continuous check on the layer that is most often neglected and most
easily verified — not a penetration test, and not a compliance certification. See
[Limitations](../README.md#limitations).
