// SARIF 2.1.0, the format GitHub code scanning and most enterprise and
// government security tooling ingest.
import { ALL_RULES } from '../rules/index.js';

const LEVEL = { critical: 'error', high: 'error', warning: 'warning' };
const SECURITY_SEVERITY = { critical: '9.0', high: '7.5', warning: '4.0' };

export function renderSarif(report) {
  const rules = ALL_RULES.map((r) => ({
    id: r.id,
    name: r.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().replace(/ (\w)/g, (_, c) => c.toUpperCase()).replace(/^\w/, (c) => c.toUpperCase()),
    shortDescription: { text: r.title },
    fullDescription: { text: r.summary },
    help: { text: r.summary },
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: {
      tags: ['security', r.target, ...r.standards.cwe, ...r.standards.nist80053.map((c) => `NIST-800-53:${c}`), ...r.standards.cis.map((c) => `CIS:${c}`)],
      'security-severity': SECURITY_SEVERITY[r.severity],
    },
  }));

  const results = report.findings.map((f) => ({
    ruleId: f.rule,
    level: LEVEL[f.severity],
    message: { text: `${f.plain} ${f.todo}` },
    ...(f.file
      ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.file.split('\\').join('/') }, ...(f.line ? { region: { startLine: f.line } } : {}) } }] }
      : {}),
    partialFingerprints: { rattlecheckObject: `${f.rule}:${f.object}${f.detail ? `:${f.detail}` : ''}` },
    properties: { severity: f.severity, object: f.name, technical: f.message, fix: f.fix, 'security-severity': SECURITY_SEVERITY[f.severity] },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'rattlecheck', version: report.tool.version, semanticVersion: report.tool.version, rules } },
        results,
        properties: { grade: report.grade.letter, doors: report.doors, coverage: report.coverage, live: report.live },
      },
    ],
  };
}
