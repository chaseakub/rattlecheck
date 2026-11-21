// The live check must ask about every table the project serves, and must say
// so when it couldn't. Fake network only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { renderTerminal } from '../src/report/terminal.js';
import { callTool } from '../src/mcp/server.js';

const REF = 'abcdefghijklmnopqrst';
const BASE = `https://${REF}.supabase.co`;

function project(envText) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-cov-'));
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '0001.sql'), 'create table public.orders (id int); alter table public.orders enable row level security;');
  fs.writeFileSync(path.join(root, '.env'), envText);
  return root;
}

// API table list refused to the public key (as on many real projects).
// The catalog knows about a hand-made backup copy that is wide open.
function fake({ catalog = true } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? 'GET', body: init.body });
    if (url === `https://api.supabase.com/v1/projects/${REF}`) return new Response('{}', { status: 200 });
    if (url === `${BASE}/auth/v1/admin/users/00000000-0000-0000-0000-000000000000`) {
      return new Response('{"error_code":"user_not_found"}', { status: 404 });
    }
    if (url === `https://api.supabase.com/v1/projects/${REF}/database/query/read-only`) {
      if (!catalog) return new Response('{}', { status: 404 });
      return new Response(JSON.stringify([
        { schema: 'public', name: 'orders', kind: 'r' },
        { schema: 'public', name: 'orders_backup', kind: 'r' },
        { schema: 'public', name: 'orders_summary_v', kind: 'v' },
      ]), { status: 201 });
    }
    if (url === `${BASE}/rest/v1/`) return new Response('{"message":"forbidden"}', { status: 401 });
    const m = /\/rest\/v1\/([^?]+)\?select=\*$/.exec(url);
    if (m) {
      const counts = { orders: '*/0', orders_backup: '0-0/950', orders_summary_v: '*/0' };
      return new Response(null, { status: 200, headers: { 'content-range': counts[decodeURIComponent(m[1])] ?? '*/0' } });
    }
    return new Response(null, { status: 500 });
  };
  return { fetchImpl, calls };
}

test('live: tables created outside migrations come from the catalog and get checked', async () => {
  const root = project(`SUPABASE_URL=${BASE}\nSUPABASE_ANON_KEY=anon\n`);
  const f = fake();
  try {
    const r = await scan({ root, live: true, env: { SUPABASE_ACCESS_TOKEN: 'tok' }, fetchImpl: f.fetchImpl });
    assert.deepEqual(r.findings.map((x) => `${x.rule} ${x.name}`), ['RC101 public.orders_backup']);
    assert.equal(r.live.coverage.complete, true);
    assert.equal(r.live.coverage.source, 'project catalog (read-only)');
    assert.equal(r.live.coverage.fromMigrations, 1);
    assert.equal(r.live.coverage.outsideMigrations, 2);
    assert.equal(r.live.probed, 3);
    // Only the read-only endpoint, never the general one that can write.
    assert.ok(f.calls.some((c) => c.url.endsWith('/database/query/read-only')));
    assert.ok(!f.calls.some((c) => c.url.endsWith('/database/query')));
    const q = JSON.parse(f.calls.find((c) => c.url.endsWith('/read-only')).body).query;
    assert.match(q, /^select /);
    assert.doesNotMatch(q, /\b(insert|update|delete|drop|alter|create|grant|revoke)\b/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: when no full list is available, the report says the check was partial', async () => {
  const root = project(`SUPABASE_URL=${BASE}\nSUPABASE_ANON_KEY=anon\nSUPABASE_SERVICE_ROLE_KEY=svc\n`);
  const f = fake();
  try {
    const r = await scan({ root, live: true, env: {}, fetchImpl: f.fetchImpl });
    assert.equal(r.live.ownership, 'service-key');
    assert.equal(r.live.coverage.complete, false);
    assert.equal(r.live.coverage.source, 'migrations only');
    assert.match(r.live.coverage.reason, /SUPABASE_ACCESS_TOKEN/);
    assert.equal(r.live.probed, 1);
    assert.match(renderTerminal(r), /only covered the 1 tables in your migrations/);
    assert.match(renderTerminal(r), /was NOT checked/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('live: a refused catalog query is reported, and the MCP summary warns the agent', async () => {
  const root = project(`SUPABASE_URL=${BASE}\nSUPABASE_ANON_KEY=anon\n`);
  const f = fake({ catalog: false });
  try {
    const res = await callTool('scan', { path: root, live: true }, { env: { SUPABASE_ACCESS_TOKEN: 'tok' }, fetchImpl: f.fetchImpl });
    assert.equal(res.structuredContent.live.coverage.complete, false);
    assert.match(res.structuredContent.live.coverage.reason, /HTTP 404/);
    assert.match(res.content[0].text, /do not report this as a full all-clear/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
