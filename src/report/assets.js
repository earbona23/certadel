/**
 * The inlined CSS and JS for the HTML report. Kept out of the renderer so that file is
 * about structure and this one is about appearance. Nothing here is fetched at view
 * time: the report is one self-contained file that opens from an email attachment or an
 * air-gapped machine, in light or dark, months from now.
 *
 * @module report/assets
 */

export function reportStyle() {
  return String.raw`
:root {
  color-scheme: light dark;
  --bg: #eef1f5; --surface: #fff; --surface-2: #f6f8fa; --ink: #12161c;
  --muted: #5a6675; --line: #e0e5eb; --accent: #146b63;
  --platinum: #2a8f9c; --gold: #b8901f; --silver: #64748b; --bronze: #a0682d; --uncertified: #b02a1f;
  --pass: #1f7a44; --warn: #9a6a00; --fail: #b02a1f; --skip: #7a8797;
  --radius: 12px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0c1016; --surface: #141a22; --surface-2: #1a212b; --ink: #e6edf5;
    --muted: #94a2b4; --line: #232c38; --accent: #35c9bb;
    --platinum: #43d2e0; --gold: #e5bd43; --silver: #9aa8ba; --bronze: #cf8a4a; --uncertified: #ff6a5c;
    --pass: #46c07a; --warn: #e5b93f; --fail: #ff6a5c; --skip: #7f8ea0;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

/* Certificate hero */
.cert { background:
    radial-gradient(120% 120% at 100% 0%, color-mix(in srgb, var(--accent) 10%, transparent), transparent 60%),
    var(--surface);
  border: 1px solid var(--line); border-radius: var(--radius); margin: 32px 0;
  padding: 40px 44px; position: relative; overflow: hidden; }
.cert::before { content: ""; position: absolute; inset: 0; border-radius: var(--radius);
  padding: 1px; background: linear-gradient(135deg, color-mix(in srgb, var(--accent) 50%, transparent), transparent 40%);
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none; }
.cert .eyebrow { font-size: 12px; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); font-weight: 700; margin: 0; }
.cert h1 { margin: 6px 0 2px; font-size: 30px; letter-spacing: -.02em; }
.cert .sub { color: var(--muted); margin: 0 0 24px; }
.tierline { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }
.tier { font-size: 40px; font-weight: 800; letter-spacing: -.02em; line-height: 1; }
.tier.platinum { color: var(--platinum); } .tier.gold { color: var(--gold); }
.tier.silver { color: var(--silver); } .tier.bronze { color: var(--bronze); }
.tier.uncertified { color: var(--uncertified); }
.scorebig { font-size: 20px; color: var(--muted); font-variant-numeric: tabular-nums; }
.cert dl { display: flex; flex-wrap: wrap; gap: 6px 40px; margin: 26px 0 0; }
.cert dt { font-size: 11px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.cert dd { margin: 2px 0 0; font-size: 14px; }
.disclaimer { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--line);
  color: var(--muted); font-size: 12.5px; }

.gatebanner { margin: 0 0 24px; padding: 14px 18px; border-radius: 10px;
  background: color-mix(in srgb, var(--fail) 12%, var(--surface)); border: 1px solid color-mix(in srgb, var(--fail) 35%, var(--line));
  color: var(--ink); }
.gatebanner strong { color: var(--fail); }

section { margin: 36px 0; }
h2 { font-size: 19px; margin: 0 0 14px; letter-spacing: -.01em; }
h3 { font-size: 15px; margin: 26px 0 10px; }

.assetgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(258px, 1fr)); gap: 12px; }
.assetcard { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px;
  border-top: 3px solid var(--skip); }
.assetcard.platinum { border-top-color: var(--platinum); } .assetcard.gold { border-top-color: var(--gold); }
.assetcard.silver { border-top-color: var(--silver); } .assetcard.bronze { border-top-color: var(--bronze); }
.assetcard.uncertified { border-top-color: var(--uncertified); }
.assetcard .host { font-weight: 650; overflow-wrap: anywhere; }
.assetcard .at { font-size: 13px; font-weight: 700; }
.assetcard .sc { color: var(--muted); font-size: 13px; font-variant-numeric: tabular-nums; }

.dims { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }
.dim-top { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; font-size: 12.5px; }
.dim-label { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dim .pct { color: var(--ink); font-variant-numeric: tabular-nums; font-weight: 600; flex: none; }
.bar { height: 6px; background: var(--surface-2); border-radius: 999px; overflow: hidden; margin-top: 4px; }
.bar > span { display: block; height: 100%; border-radius: 999px; background: var(--accent); }

table.grid { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--line);
  border-radius: 10px; overflow: hidden; }
table.grid th, table.grid td { padding: 9px 13px; text-align: left; border-bottom: 1px solid var(--line); font-size: 13.5px; vertical-align: top; }
table.grid thead th { background: var(--surface-2); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
table.grid tbody tr:last-child td { border-bottom: 0; }

.status { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; padding: 2px 7px; border-radius: 999px; border: 1px solid currentColor; white-space: nowrap; }
.st-pass { color: var(--pass); } .st-warn { color: var(--warn); } .st-fail { color: var(--fail); } .st-skip { color: var(--skip); }

.finding { background: var(--surface); border: 1px solid var(--line); border-left: 3px solid var(--skip);
  border-radius: 10px; margin-bottom: 8px; }
.finding.sev-critical, .finding.sev-high { border-left-color: var(--fail); }
.finding.sev-medium { border-left-color: var(--warn); }
.finding[hidden] { display: none; }
.finding > summary { cursor: pointer; padding: 11px 15px; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; list-style: none; }
.finding > summary::-webkit-details-marker { display: none; }
.pill { font-size: 10px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; padding: 3px 7px; border-radius: 4px; border: 1px solid currentColor; }
.finding .host-chip { font-size: 11px; color: var(--muted); font-family: ui-monospace, monospace; }
.finding .ftitle { font-weight: 600; }
.finding .body { padding: 0 15px 15px; border-top: 1px solid var(--line); }
.finding .detail { margin: 13px 0 0; }
.finding .rec { margin: 11px 0 0; padding: 11px 13px; background: var(--surface-2); border-radius: 8px; font-size: 14px; }
.finding .rec strong { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--accent); margin-bottom: 3px; }
pre.evidence { margin: 12px 0 0; padding: 11px 13px; overflow-x: auto; background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; font-family: ui-monospace, monospace; font-size: 12px; }
.filters { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 10px; }
.filters input[type=search] { min-width: 240px; padding: 8px 12px; font: inherit; font-size: 14px; color: var(--ink); background: var(--surface); border: 1px solid var(--line); border-radius: 8px; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 999px; cursor: pointer; font-size: 12px; font-weight: 600; border: 1px solid var(--line); background: var(--surface); color: var(--muted); }
footer { margin: 44px 0; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }

@media print {
  :root { --bg:#fff; --surface:#fff; --surface-2:#fff; --line:#bbb; --ink:#000; --muted:#333; }
  .no-print { display: none !important; }
  .finding { break-inside: avoid; } .finding > .body { display: block !important; }
  .cert { break-inside: avoid; }
}
`;
}

export function reportScript() {
  return String.raw`
(function () {
  "use strict";
  var findings = [].slice.call(document.querySelectorAll(".finding"));
  if (!findings.length) return;
  var q = document.getElementById("q");
  var chips = [].slice.call(document.querySelectorAll("#sev input"));
  var counter = document.getElementById("shown");
  function apply() {
    var term = (q && q.value || "").trim().toLowerCase();
    var allow = {}; chips.forEach(function (c) { allow[c.value] = c.checked; });
    var n = 0;
    findings.forEach(function (el) {
      var okS = allow[el.getAttribute("data-status")] !== false;
      var okT = !term || (el.getAttribute("data-search") || "").indexOf(term) !== -1;
      el.hidden = !(okS && okT); if (okS && okT) n++;
    });
    [].slice.call(document.querySelectorAll("[data-group]")).forEach(function (h) {
      var any = false, node = h.nextElementSibling;
      while (node && node.classList && node.classList.contains("finding")) {
        if (!node.hidden) { any = true; break; } node = node.nextElementSibling;
      }
      h.hidden = !any;
    });
    if (counter) counter.textContent = n === findings.length ? findings.length + " findings" : n + " of " + findings.length + " findings";
  }
  if (q) q.addEventListener("input", apply);
  chips.forEach(function (c) { c.addEventListener("change", apply); });
  window.addEventListener("beforeprint", function () { findings.forEach(function (el) { if (!el.hidden) el.open = true; }); });
  apply();
})();
`;
}
