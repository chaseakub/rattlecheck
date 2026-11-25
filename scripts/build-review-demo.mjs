import assert from 'node:assert/strict';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanStatic } from '../src/core.js';
import { VERSION } from '../src/version.js';
import { tableSelectScope } from '../src/model.js';

const output = process.argv[2];
if (!output) throw new Error('Usage: node scripts/build-review-demo.mjs <output-directory>');

const project = fileURLToPath(new URL('../', import.meta.url));
async function readFixture(folder, files) {
  return Promise.all(files.map(async file => ({
    file,
    sql: (await readFile(path.join(project, 'examples', folder, file), 'utf8')).trimEnd(),
  })));
}

const migrations = await readFixture('order-audit', ['001_setup.sql', '002_audit.sql', '003_fix.sql']);

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

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

const directory = await readFixture('public-directory', ['001_directory.sql', '002_narrow_reads.sql']);
const broad = scanStatic({ ...options, migrations: directory.slice(0, 1) });
const narrow = scanStatic({ ...options, migrations: directory });
const privateField = broad.findings.find(f => f.rule === 'RC006' && f.detail === 'private_email');
assert.equal(privateField?.severity, 'high');
assert.ok(!narrow.findings.some(f => f.rule === 'RC006'));
assert.ok([broad, narrow].every(report => report.findings.some(f => f.rule === 'RC005' && f.detail === 'browse')));

function anonymousColumns(report) {
  const table = report.model.tables.get('public.directory');
  const scope = tableSelectScope(table, 'anon');
  return scope.all ? table.columns : scope.columns;
}

const beforeColumns = anonymousColumns(broad);
const afterColumns = anonymousColumns(narrow);
assert.deepEqual(beforeColumns, new Set(['id', 'display_name', 'private_email']));
assert.deepEqual(afterColumns, new Set(['id', 'display_name']));

function readCell(stage, columns, name) {
  const risk = name === privateField.detail && columns.has(name);
  return `<td id="${stage}-${escapeHtml(name)}"${risk ? ' class="risk"' : ''}>${columns.has(name) ? 'Readable' : 'Blocked'}</td>`;
}

const accessRows = [...broad.model.tables.get('public.directory').columns].map(name =>
  `<tr${name === privateField.detail ? ' class="private"' : ''}><th scope="row">${escapeHtml(name)}</th>` +
  readCell('before', beforeColumns, name) + readCell('after', afterColumns, name) + '</tr>').join('\n');

function renderReport(id, title, report, migration) {
  const finding = report.findings.find(f => f.rule === 'RC006');
  return `<article id="${id}-result" class="report" aria-labelledby="${id}-title">
    <div class="report-head"><h2 id="${id}-title">${title}</h2><span class="grade">Grade ${escapeHtml(report.grade.letter)}</span></div>
    <p class="finding">${finding ? escapeHtml(finding.rule + ' · ' + finding.severity + ' · ' + finding.plain) : 'RC006 cleared. The narrowed grant keeps the private email out of signed-out reads.'}</p>
    <details id="${id}-sql"><summary>Inspect the SQL</summary><p class="filename">${escapeHtml(migration.file)}</p>
      <pre class="sql"><code>${escapeHtml(migration.sql)}</code></pre></details>
  </article>`;
}

const comparison = `<table class="access" id="access-matrix">
    <caption>What a signed-out visitor can read</caption>
    <thead><tr><th scope="col">Column</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
    <tbody>${accessRows}</tbody>
  </table>
  <div class="reports">
    ${renderReport('before', 'Table-wide grant', broad, directory[0])}
    ${renderReport('after', 'Column grant', narrow, directory[1])}
  </div>
  <p class="policy-note">Both scans include the RC005 warning because the directory deliberately allows public reads of every row.</p>`;
const columnPage = path.join(output, 'column-permissions/index.html');
const template = await readFile(columnPage, 'utf8');
const slot = '<!-- Insert the two scanner reports and column access matrix at build time. -->';
assert.ok(template.includes(slot));
await writeFile(columnPage, template.replace(slot, () => comparison));
console.log(`Column permissions: ${privateField.rule} / grade ${broad.grade.letter}, then grade ${narrow.grade.letter}.`);
