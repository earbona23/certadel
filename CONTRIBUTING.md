# Contributing

Contributions are welcome. A few rules follow from what certadel is.

## The passive rule

certadel must never be able to attack or alter a target. People run it against
production because of that, and against infrastructure they are authorized to assess but
not to disrupt.

- All network access goes through the clients in `src/net/`. The HTTP client
  (`src/net/http.js`) is the only module permitted to import `node:http`/`node:https`,
  and it issues **GET or HEAD only**.
- No new module may open raw sockets, spawn processes, or send a request body.
- The scope guard in `src/scope.js` is not optional and has no bypass.

[`test/safety.test.js`](test/safety.test.js) enforces all of the above and will fail the
build. If a change requires weakening that test, the change is out of scope for this
project.

## Adding a check

1. Write it as a **pure function over the evidence object** in the relevant
   `src/checks/*.js`, returning `result(...)` or `skipped(...)` from `src/util/model.js`.
2. **Handle the absent case explicitly.** If the evidence a check needs is missing,
   return `skipped(...)` with a reason — never a silent pass. Reporting "fine" when you
   could not look is the one failure mode an assessment tool must not have.
3. If it needs new evidence, collect it in `src/assess.js` (passively, within scope) and
   catch every failure into an absence the check can read.
4. Add tests to `test/checks/` covering the pass, the fail, and the not-applicable paths.
5. Keep the dimension weights in `src/scoring/rubric.js` and `docs/rubric.md` in sync.

## Severity

- **critical** — the asset cannot be trusted at all (no HTTPS, invalid/expired
  certificate, obsolete TLS). Gates the whole grade.
- **high** — a serious, exploitable gap (no CSP, no DMARC, weak key). Caps at Bronze.
- **medium / low** — real but bounded hygiene issues.
- **info** — passing controls and inventory.

## Before a pull request

```sh
npm test          # node --test, zero dependencies
npm run typecheck # tsc --checkJs, types via JSDoc
```

Both must be clean, on Node 18, 20 and 22. Never include real assessment output,
hostnames, or scope files in a commit or an issue.
