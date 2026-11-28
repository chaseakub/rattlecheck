import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { scanSql } from './helpers.js';
import { scanStatic } from '../src/core.js';
import { parseConfig } from '../src/config.js';

const fixture = file => readFileSync(new URL('../examples/public-directory/' + file, import.meta.url), 'utf8');
const wide = fixture('001_directory.sql');
const narrow = fixture('002_narrow_reads.sql');
const config = { defaults: 'clean', allow: [{ rule: 'RC005', object: 'public.directory', reason: 'Directory entries are publicly listed.' }] };
const columns = report => report.findings.filter(f => f.rule === 'RC006' && f.detail).map(f => f.name);

test('a public directory read policy gets read guidance without executable changes', async () => {
  const report = await scanSql(wide + narrow, { config: { defaults: 'clean' } });
  assert.deepEqual(report.findings.map(f => f.rule), ['RC005']);
  const [read] = report.findings;
  assert.equal(read.severity, 'warning');
  assert.match(read.title, /signed-out reads/i);
  assert.match(read.plain, /display_name, id/);
  assert.match(read.todo, /no migration is needed/i);
  assert.ok(read.fix.trim().split('\n').every(line => line.startsWith('-- ')));
});

test('public row exception cannot hide a table-wide grant on private_email', async () => {
  const before = await scanSql(wide, { config });
  assert.deepEqual(columns(before), ['public.directory.private_email']);
  assert.equal(before.findings[0].severity, 'high');
  assert.match(before.findings[0].message, /table-wide SELECT/);
  const after = await scanSql(wide + narrow, { config });
  assert.equal(after.grade.letter, 'A');
  assert.deepEqual(columns(after), []);
  assert.match(after.allowed[0].plain, /display_name, id/);
});

test('PostgreSQL adds grants together, independently for PUBLIC and anon', async () => {
  for (const suffix of [
    'grant select (display_name) on public.directory to anon;',
    'revoke select (private_email) on public.directory from anon;',
    'grant select on public.directory to public; revoke select on public.directory from anon;',
    'grant select (private_email) on public.directory to public; revoke select on public.directory from anon;',
    'revoke grant option for select on public.directory from anon;',
  ]) assert.deepEqual(columns(await scanSql(wide + suffix, { config })), ['public.directory.private_email'], suffix);
  const limited = wide + narrow + 'grant select(private_email) on public.directory to anon; revoke select(private_email) on public.directory from anon;';
  assert.deepEqual(columns(await scanSql(limited, { config })), []);
  assert.deepEqual(columns(await scanSql(wide + narrow + 'grant select on public.directory to authenticated;', { config })), []);
});

test('column grants survive rename, track PUBLIC defaults, and disappear on drop', async () => {
  const rn = wide + narrow + 'alter table public.directory rename display_name to "private Display";';
  const extra = 'alter table public.directory add column "InternalNote" text;';
  assert.deepEqual(columns(await scanSql(rn + extra, { config })), []);
  const designated = { ...config, privateColumns: { 'public.directory': ['private Display'] } };
  assert.deepEqual(columns(await scanSql(rn + extra, { config: designated })), ['public.directory."private Display"']);
  assert.deepEqual(columns(await scanSql(rn + 'alter table public.directory drop column "private Display";', { config: designated })), []);
  const defaults = 'alter default privileges in schema public grant select on tables to public;';
  const sql = defaults + wide.replace('grant select on public.directory to anon;', '') + extra;
  assert.deepEqual(columns(await scanSql(sql, { config })).sort(), ['public.directory."InternalNote"', 'public.directory.private_email'].sort());
});

test('RC006 follows exposed schemas, SELECT-capable roles and policies', async () => {
  for (const sql of [
    wide.replace('for select to anon', 'for select to authenticated'),
    wide.replace('for select to anon using (true)', 'for delete to anon using (true)'),
    wide.replace('using (true)', 'using (false)'),
    wide + 'create policy deny on public.directory as restrictive for select to public using (false);',
    wide.replace('grant select', 'grant update'),
  ]) assert.deepEqual(columns(await scanSql(sql, { config })), []);
  assert.deepEqual(columns(await scanSql(wide, {config:{...config,exposedSchemas:['api']}})), []);
  assert.deepEqual(columns(await scanSql(wide.replace('using (true)', 'using (id > 0)'), { config })), ['public.directory.private_email']);
});

test('unknown business names can be marked private and a wide grant still gets its own review warning', async () => {
  const sql = wide.replace('private_email', 'draft_budget');
  const any = await scanSql(sql, { config });
  assert.deepEqual(any.findings.map(f => f.name), ['public.directory']);
  assert.match(any.findings[0].plain, /whole table/);
  const custom = { ...config, privateColumns: { 'public.directory': ['draft_budget'] } };
  const report = scanStatic({ migrations:[{file:'01.sql', sql}],config:custom });
  assert.deepEqual(columns(report), ['public.directory.draft_budget']);
  assert.equal(report.counts.high, 1);
  assert.deepEqual(columns(await scanSql(sql + narrow, {config: custom})), []);
  assert.throws(() => parseConfig('{"privateColumns":{"public.directory":"draft_budget"}}'), /privateColumns/);
});

test('a named grant on just a sensitive field is also caught and a benign public contact email is reviewable', async () => {
  const sql = wide.replace('grant select on', 'grant select (private_email) on');
  const report = await scanSql(sql, { config });
  assert.deepEqual(columns(report), ['public.directory.private_email']);
  assert.match(report.findings[0].message, /column-level SELECT/);
  const email = await scanSql(sql.replaceAll('private_email', 'email'), { config });
  assert.equal(email.findings[0].severity, 'warning');
});

test('the annotation points to the migration that exposed the field', async () => {
  const baseline = wide.replace('grant select on public.directory to anon;', '');
  const result = await scanSql({
    '01_schema.sql': baseline,
    '02_grants.sql': 'grant select (display_name) on public.directory to anon;\ngrant select (private_email) on public.directory to public;',
  }, { config });
  assert.deepEqual(columns(result), ['public.directory.private_email']);
  assert.equal(result.findings[0].file, 'supabase/migrations/02_grants.sql');
  assert.equal(result.findings[0].line, 2);
  const added = await scanSql({
    '01_schema.sql': wide,
    '03_fields.sql': 'alter table public.directory add internal_note text;',
  }, { config });
  const finding = added.findings.find(f => f.name === 'public.directory.internal_note');
  assert.equal(finding.file, 'supabase/migrations/03_fields.sql');
  assert.equal(finding.line, 1);
});

test('quoted uppercase roles do not grant a policy to the actual anon role', async () => {
  assert.deepEqual(columns(await scanSql(wide.replace('for select to anon', 'for select to "ANON"'), { config })), []);
  assert.deepEqual(columns(await scanSql(wide.replace('for select to anon', 'for select to "anon"'), { config })), ['public.directory.private_email']);
});

test('allowing one field does not approve table-wide access for future fields', async () => {
  const allow = [...config.allow, { rule: 'RC006', object: 'public.directory.email', reason: 'Public business contact email.' }];
  const sql = wide.replace('private_email', 'email');
  const result = await scanSql(sql, { config: { ...config, allow } });
  assert.deepEqual(result.findings.map(f => [f.rule, f.name]), [['RC006', 'public.directory']]);
});
