// Live check tests use a fake network. Nothing here touches a real project.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { parseEnvFile, readProjectEnv } from '../src/live/env.js';
import { projectRefFromUrl } from '../src/live/ownership.js';

const REF = 'abcdefghijklmnopqrst';
const URL_ = `https://${REF}.supabase.co`;

function project(sql, envText) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-live-'));
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '0001.sql'), sql);
  if (envText) fs.writeFileSync(path.join(root, '.env.local'), envText);
  return root;
}

// A tiny fake Supabase: Management API + Auth admin + PostgREST counts.
function fakeSupabase({ ownerToken = 'tok', serviceKey = 'svc', counts = {}, openapi = [] } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const h = init.headers ?? {};
    calls.push({ url, method: init.method ?? 'GET', headers: h });
    const resp = (status, headers = {}, body = '') => new Response(init.method === 'HEAD' ? null : body, { status, headers });
    if (url === `https://api.supabase.com/v1/projects/${REF}`) return resp(h.Authorization === `Bearer ${ownerToken}` ? 200 : 403, {}, '{}');
    if (url === `${URL_}/auth/v1/admin/users/00000000-0000-0000-0000-000000000000`) {
      return h.apikey === serviceKey ? resp(404, {}, '{"code":404,"error_code":"user_not_found","msg":"User not found"}') : resp(403, {}, '{"msg":"User not allowed"}');
    }
    if (url === `${URL_}/rest/v1/`) {
      return resp(200, { 'content-type': 'application/openapi+json' }, JSON.stringify({ paths: Object.fromEntries([['/', {}], ...openapi.map((t) => [`/${t}`, {}]), ['/rpc/x', {}]]) }));
    }
    const m = /\/rest\/v1\/([^?]+)\?select=\*$/.exec(url);
    if (m) {
      const t = decodeURIComponent(m[1]);
      if (!(t in counts)) return resp(404);
      const c = counts[t];
      if (c === 'denied') return resp(401);
      return resp(200, { 'content-range': c === 0 ? '*/0' : `0-0/${c}` });
    }
    return resp(500);
  };
  return { fetchImpl, calls };
}

const SQL = `
create table public.orders (id int); alter table public.orders enable row level security;
create table public.menu (id int); alter table public.menu enable row level security;`;

test('live: refuses without proof of ownership, and sends nothing to the tables', async () => {
  const root = project(SQL, `NEXT_PUBLIC_SUPABASE_URL=${URL_}\nNEXT_PUBLIC_SUPABASE_ANON_KEY=anon\n`);
  const fake = fakeSupabase();
  try {
    await assert.rejects(scan({ root, live: true, env: {}, fetchImpl: fake.fetchImpl }), (e) => e.code === 4 && /prove are yours/.test(e.message));
    assert.equal(fake.calls.filter((c) => c.url.includes('/rest/v1/')).length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: a wrong access token is refused', async () => {
  const root = project(SQL, `SUPABASE_URL=${URL_}\nSUPABASE_ANON_KEY=anon\n`);
  const fake = fakeSupabase();
  try {
    await assert.rejects(scan({ root, live: true, env: { SUPABASE_ACCESS_TOKEN: 'stolen' }, fetchImpl: fake.fetchImpl }), (e) => e.code === 4);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: with ownership proven, open tables are critical and drift is explained', async () => {
  const root = project(SQL, `VITE_SUPABASE_URL=${URL_}\nVITE_SUPABASE_ANON_KEY=anon\n`);
  const fake = fakeSupabase({ counts: { orders: 1204, menu: 0, dashboard_only: 'denied' }, openapi: ['dashboard_only'] });
  try {
    const r = await scan({ root, live: true, env: { SUPABASE_ACCESS_TOKEN: 'tok' }, fetchImpl: fake.fetchImpl });
    const live = r.findings.filter((f) => f.rule === 'RC101');
    assert.deepEqual(live.map((f) => f.name), ['public.orders']);
    assert.match(live[0].plain, /1,204 rows/);
    assert.match(live[0].plain, /did not read or keep any of the data/);
    assert.match(live[0].plain, /migrations turn row-level security on/);
    assert.equal(r.live.ownership, 'access-token');
    assert.equal(r.live.open, 1);
    assert.equal(r.live.lockedOrEmpty, 1);
    assert.equal(r.live.locked, 1);
    assert.equal(r.grade.letter, 'F');

    // Read-only: every table request is a HEAD asking for a count.
    const tableCalls = fake.calls.filter((c) => /\/rest\/v1\/[^?]+\?select/.test(c.url));
    assert.ok(tableCalls.length === 3);
    assert.ok(tableCalls.every((c) => c.method === 'HEAD' && c.headers.Prefer === 'count=exact'));
    assert.ok(fake.calls.every((c) => /^rattlecheck\//.test(c.headers['User-Agent'])));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: service key proves ownership but is never used to probe tables', async () => {
  const root = project(SQL, `SUPABASE_URL=${URL_}\nSUPABASE_ANON_KEY=anon\nSUPABASE_SERVICE_ROLE_KEY=svc\n`);
  const fake = fakeSupabase({ counts: { orders: 0, menu: 0 } });
  try {
    const r = await scan({ root, live: true, env: {}, fetchImpl: fake.fetchImpl });
    assert.equal(r.live.ownership, 'service-key');
    const tableCalls = fake.calls.filter((c) => c.url.includes('/rest/v1/'));
    assert.ok(tableCalls.every((c) => c.headers.apikey === 'anon'));
    assert.deepEqual(r.findings, []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: allowlisted public table is not graded', async () => {
  const root = project(SQL, `SUPABASE_URL=${URL_}\nSUPABASE_ANON_KEY=anon\n`);
  fs.writeFileSync(path.join(root, 'rattlecheck.config.json'), JSON.stringify({ allow: [{ rule: 'RC101', object: 'public.menu', reason: 'The menu is public on the website.' }] }));
  const fake = fakeSupabase({ counts: { orders: 0, menu: 40 } });
  try {
    const r = await scan({ root, live: true, env: { SUPABASE_ACCESS_TOKEN: 'tok' }, fetchImpl: fake.fetchImpl });
    assert.deepEqual(r.findings, []);
    assert.equal(r.allowed.length, 1);
    assert.equal(r.grade.letter, 'A');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('env parsing handles quotes, export, and comments', () => {
  const v = parseEnvFile(`# c\nexport SUPABASE_URL="https://x.supabase.co"\nSUPABASE_ANON_KEY='k' \nFOO=bar # note\n`);
  assert.equal(v.SUPABASE_URL, 'https://x.supabase.co');
  assert.equal(v.SUPABASE_ANON_KEY, 'k');
  assert.equal(v.FOO, 'bar');
});

test('project ref only comes from a real supabase.co URL', () => {
  assert.equal(projectRefFromUrl(URL_), REF);
  assert.equal(projectRefFromUrl(`${URL_}/`), REF);
  assert.equal(projectRefFromUrl('https://evil.com/abcdefghijklmnopqrst.supabase.co'), null);
  assert.equal(projectRefFromUrl('http://abcdefghijklmnopqrst.supabase.co'), null);
});

test('readProjectEnv: URL and keys come from one source, never mixed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-env-'));
  fs.writeFileSync(path.join(root, '.env'), 'VITE_SUPABASE_URL=https://file.supabase.co\nSUPABASE_ANON_KEY=filekey\n');
  try {
    const e = readProjectEnv(root, { SUPABASE_URL: 'https://proc.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'svc' });
    assert.equal(e.source, 'environment');
    assert.equal(e.url, 'https://proc.supabase.co');
    assert.equal(e.anonKey, null); // not borrowed from the repo's file
    const f = readProjectEnv(root, { SUPABASE_SERVICE_ROLE_KEY: 'svc' });
    assert.equal(f.source, 'env files');
    assert.equal(f.serviceKey, null); // the shell's key is not paired with the repo's URL
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
