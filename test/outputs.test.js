import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanSql } from './helpers.js';
import { renderCard } from '../src/report/card-svg.js';
import { renderBadge } from '../src/report/badge-svg.js';
import { renderSarif } from '../src/report/sarif.js';
import { renderTerminal } from '../src/report/terminal.js';
import { main } from '../src/cli.js';
import { gradeFor } from '../src/report/grade.js';

const BAD = `
create table public.patient_records (id uuid primary key, ssn text);
create function public.secret_lookup(uid uuid) returns int language sql security definer as $$ select 1 $$;`;

test('share card never names tables, functions, or the project', async () => {
  const r = await scanSql(BAD);
  const svg = renderCard(r);
  assert.doesNotMatch(svg, /patient_records|secret_lookup|ssn|supabase\.co/);
  assert.match(svg, /2 doors open\./);
  assert.match(svg, />F</);
});

test('share card for a clean project', async () => {
  const r = await scanSql(`create table public.a (id int); alter table public.a enable row level security;`);
  const svg = renderCard(r);
  assert.match(svg, /Every door locked\./);
  assert.match(svg, />A</);
});

test('badge shows the grade only', async () => {
  const r = await scanSql(BAD);
  const svg = renderBadge(r);
  assert.match(svg, /rattlecheck: F/);
  assert.doesNotMatch(svg, /patient_records/);
});

test('SARIF has every rule, a result per finding, and locations', async () => {
  const r = await scanSql(BAD);
  const s = renderSarif(r);
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.deepEqual(run.tool.driver.rules.map(r => r.id), ['RC001', 'RC002', 'RC003', 'RC004', 'RC005', 'RC006', 'RC101']);
  assert.equal(run.results.length, r.findings.length);
  for (const res of run.results) {
    assert.ok(run.tool.driver.rules.some((x) => x.id === res.ruleId));
    assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, 'supabase/migrations/0001_init.sql');
    assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
  }
  const rc001 = run.tool.driver.rules.find((x) => x.id === 'RC001');
  assert.ok(rc001.properties.tags.includes('NIST-800-53:AC-3'));
  assert.ok(rc001.properties.tags.includes('CWE-284'));
});

test('grade thresholds', () => {
  assert.equal(gradeFor({ critical: 1, high: 0, warning: 0 }), 'F');
  assert.equal(gradeFor({ critical: 0, high: 2, warning: 0 }), 'D');
  assert.equal(gradeFor({ critical: 0, high: 1, warning: 5 }), 'C');
  assert.equal(gradeFor({ critical: 0, high: 0, warning: 1 }), 'B');
  assert.equal(gradeFor({ critical: 0, high: 0, warning: 0 }), 'A');
});

test('plain terminal output has no SQL; technical has the fix and location', async () => {
  const r = await scanSql(BAD);
  const plain = renderTerminal(r);
  const tech = renderTerminal(r, { technical: true });
  assert.doesNotMatch(plain, /alter table/);
  assert.match(plain, /GRADE {2}F/);
  assert.match(tech, /alter table public\.patient_records enable row level security;/);
  assert.match(tech, /supabase\/migrations\/0001_init\.sql:2/);
  assert.match(tech, /NIST 800-53/);
});

function project(sql) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-cli-'));
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '0001.sql'), sql);
  return root;
}

function sink() {
  const s = { text: '', isTTY: false, write: (x) => { s.text += x; return true; } };
  return s;
}

test('CLI exit codes: 1 for open doors, 0 for clean, 2 for no migrations', async () => {
  const bad = project(BAD);
  const good = project(`create table public.a (id int); alter table public.a enable row level security;`);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-empty-'));
  try {
    assert.equal(await main([bad], { stdout: sink(), stderr: sink(), env: {} }), 1);
    assert.equal(await main([good], { stdout: sink(), stderr: sink(), env: {} }), 0);
    const err = sink();
    assert.equal(await main([empty], { stdout: sink(), stderr: err, env: {} }), 2);
    assert.match(err.text, /No Supabase migrations found/);
  } finally {
    for (const d of [bad, good, empty]) fs.rmSync(d, { recursive: true, force: true });
  }
});

test('comment-only migrations return a coverage error and never display a passing grade', async () => {
  const sql = '-- First note\n; /* Another note */';
  const root = project(sql);
  try {
    const out = sink();
    assert.equal(await main([root, '--json'], { stdout: out, stderr: sink(), env: {} }), 3);
    const report = JSON.parse(out.text);
    assert.equal(report.coverage.statements, 0);
    assert.equal(report.coverage.ok, false);
    assert.equal(report.grade.letter, 'N/A');
    assert.doesNotMatch(renderTerminal(report), /Locked tight|Nothing open/);
    assert.match(renderCard(report), /No objects checked/);
    assert.match(renderBadge(report), /N\/A/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('SQL without objects has no grade and comments do not affect valid scans', async () => {
  const noObjects = await scanSql('SELECT 1;');
  assert.equal(noObjects.coverage.ok, true);
  assert.equal(noObjects.grade.letter, 'N/A');
  const rated = await scanSql('-- intro\nCREATE TABLE public.example (id integer); ALTER TABLE public.example ENABLE ROW LEVEL SECURITY; -- trailing note');
  assert.equal(rated.coverage.statements, 2);
  assert.equal(rated.grade.letter, 'A');
});

test('CLI --json emits the versioned report schema', async () => {
  const root = project(BAD);
  try {
    const out = sink();
    await main([root, '--json'], { stdout: out, stderr: sink(), env: {} });
    const report = JSON.parse(out.text);
    assert.equal(report.schema, 'rattlecheck.report/v1');
    assert.equal(report.grade.letter, 'F');
    assert.ok(report.findings.every((f) => f.plain && f.todo && f.fix && f.standards));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('CLI --fix-sql writes a reviewable file and never claims to apply it', async () => {
  const root = project(BAD);
  const out = path.join(root, 'fixes.sql');
  try {
    await main([root, '--fix-sql', out], { stdout: sink(), stderr: sink(), env: {} });
    const sql = fs.readFileSync(out, 'utf8');
    assert.match(sql, /never runs these/);
    assert.match(sql, /revoke execute on function public\.secret_lookup\(uuid\) from public, anon;/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('CLI rejects unknown options', async () => {
  const err = sink();
  assert.equal(await main(['--frobnicate'], { stdout: sink(), stderr: err, env: {} }), 2);
  assert.match(err.text, /Unknown option/);
});
