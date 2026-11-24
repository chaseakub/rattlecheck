import assert from 'node:assert/strict';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanStatic } from '../src/core.js';
import { VERSION } from '../src/version.js';

const output = process.argv[2];
if (!output) throw new Error('Usage: node scripts/build-review-demo.mjs <output-directory>');

const project = fileURLToPath(new URL('../', import.meta.url));
const migrations = await Promise.all(['001_setup.sql', '002_audit.sql', '003_fix.sql'].map(async file => ({
  file,
  sql: (await readFile(path.join(project, 'examples/order-audit', file), 'utf8')).trimEnd(),
})));

// The fixture explicitly grants the privileges it needs. No project-specific
// Supabase default privileges are assumed when recording the two reports.
const options = { config: { defaults: { functions: 'clean', tables: 'clean' } } };
const before = scanStatic({ ...options, migrations: migrations.slice(0, 2) });
const after = scanStatic({ ...options, migrations });
assert.deepEqual(before.findings.map(f => f.rule), ['RC004']);
assert.equal(after.findings.length, 0);
assert.ok(before.doors.checked > 0 && after.doors.checked > 0);

function summary(report) {
  return { grade: report.grade.letter, checked: report.doors.checked, high: report.counts.high };
}

const [setup, proposal, fix] = migrations;
const data = {
  version: VERSION, setup, proposal, fix,
  before: { ...summary(before), rule: before.findings[0].rule },
  after: summary(after),
  sourceUrl: 'https://github.com/chaseakub/rattlecheck/tree/main/examples/order-audit',
};
await mkdir(output, { recursive: true });
await cp(path.join(project, 'public/review'), output, { recursive: true });
await writeFile(path.join(output, 'case.json'), JSON.stringify(data, null, 2) + '\n');
console.log(`RattleCheck ${VERSION}: ${before.findings[0].rule} / grade ${data.before.grade}, then grade ${data.after.grade}.`);
