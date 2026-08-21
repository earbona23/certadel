/**
 * SARIF 2.1.0 export of a certadel assessment (a Pro output).
 *
 * Turns each failing or warning finding into a SARIF result so a certadel run drops
 * straight into GitHub's code-scanning / Security tab, or any SARIF-aware dashboard or
 * SIEM. The file location is the assessed host (SARIF needs a URI), and the rule id is
 * the check id, so findings group and trend the way a security team expects.
 *
 * @module report/sarif
 */

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

/**
 * @param {Object} report  Serialized report from serialize.js.
 * @param {Object} [meta]
 * @param {string} [meta.version]
 * @returns {string}
 */
export function renderSarif(report, meta = {}) {
  /** @type {Map<string, Object>} */
  const rules = new Map();
  const results = [];

  for (const asset of report.assets) {
    for (const f of asset.findings) {
      if (f.status !== 'fail' && f.status !== 'warn') continue;
      if (!rules.has(f.id)) {
        rules.set(f.id, {
          id: f.id,
          name: pascal(f.id),
          shortDescription: { text: f.title },
          fullDescription: { text: f.remediation ?? f.title },
          helpUri: f.reference ?? 'https://github.com/earbona23/certadel#readme',
          defaultConfiguration: { level: LEVEL[f.severity] ?? 'warning' },
          properties: { category: f.dimension },
        });
      }
      results.push({
        ruleId: f.id,
        level: f.status === 'warn' ? 'note' : LEVEL[f.severity] ?? 'warning',
        message: {
          text: `${asset.host}: ${f.detail ?? f.title}${f.remediation ? ` — ${f.remediation}` : ''}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: `https://${asset.host}/` },
              region: { startLine: 1 },
            },
          },
        ],
        properties: { host: asset.host, severity: f.severity, dimension: f.dimension },
      });
    }
  }

  return (
    JSON.stringify(
      {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'certadel',
                informationUri: 'https://github.com/earbona23/certadel',
                version: meta.version ?? '1.0.0',
                rules: [...rules.values()],
              },
            },
            results,
          },
        ],
      },
      null,
      2,
    ) + '\n'
  );
}

/** @param {string} id */
function pascal(id) {
  return id
    .split(/[-_]/)
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join('');
}
