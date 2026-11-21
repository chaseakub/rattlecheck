// One test per failing input from the first independent review.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanSql, ids } from './helpers.js';
import { scan } from '../src/scan.js';
import { buildModel, readExposedSchemas } from '../src/model.js';
import { splitStatements } from '../src/sql/statements.js';
import { handleMessage } from '../src/mcp/server.js';
import { checkTarget } from '../src/live/env.js';

const DEF = (name = 'f', args = 'uid uuid') =>
  `create function public.${name}(${args}) returns int language sql security definer set search_path = '' as $$ select 1 $$;`;

// ── C1: schema-level grants ─────────────────────────────────────────────

test('C1: REVOKE CREATE ON SCHEMA public does not hide RC002', async () => {
  const r = await scanSql(`revoke create on schema public from public;\n${DEF()}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('C1: REVOKE ALL ON SCHEMA FROM PUBLIC leaves anon\'s own USAGE, so RC002 stays', async () => {
  const r = await scanSql(`revoke all on schema public from public;\ngrant usage on schema public to anon, authenticated;\n${DEF()}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('C1: revoking USAGE from PUBLIC and the API roles really closes the schema', async () => {
  const r = await scanSql(`revoke usage on schema public from public, anon, authenticated;\n${DEF()}\ncreate table public.t (id int);`);
  assert.deepEqual(ids(r), []);
});

test('C1: a schema created in migrations starts closed until USAGE is granted', async () => {
  const closed = await scanSql(`create schema api;\ncreate table api.t (id int);\ngrant all on api.t to anon;`, { config: { exposedSchemas: ['api'] } });
  assert.deepEqual(ids(closed), []);
  const open = await scanSql(`create schema api;\ngrant usage on schema api to anon;\ncreate table api.t (id int);\ngrant all on api.t to anon;`, { config: { exposedSchemas: ['api'] } });
  assert.deepEqual(ids(open), ['RC001 api.t']);
});

// ── H2: E-strings ───────────────────────────────────────────────────────

test('H2: an E-string with a backslash-escaped quote does not swallow the file', async () => {
  const r = await scanSql(`insert into x values (E'don\\'t'); create table public.secrets(id int); select 'x';`);
  assert.deepEqual(ids(r), ['RC001 public.secrets']);
});

// ── H3 / M4: function bodies ────────────────────────────────────────────

test('H3: attributes after a single-quoted body are read', async () => {
  const r = await scanSql(`create function public.f() returns int as 'select 1' language sql security definer;`);
  assert.deepEqual(ids(r), ['RC002 public.f()', 'RC003 public.f()']);
});

test('M4: dollar tags with digits keep the body out of the attributes', async () => {
  const r = await scanSql(`
    create table public.audit (id int); alter table public.audit enable row level security;
    create function public.t1() returns trigger language plpgsql as $fn1$ begin insert into public.audit values (1); return new; end $fn1$;`);
  assert.deepEqual(ids(r), ['RC004 public.t1()']);
});

// ── H4 / H5: table privileges ───────────────────────────────────────────

test('H4: a column-level REVOKE does not remove table-level SELECT', async () => {
  const r = await scanSql(`create table public.profiles (id int, email text);
    revoke select (email) on public.profiles from anon, authenticated;
    revoke insert, update, delete on public.profiles from anon, authenticated;`);
  assert.deepEqual(ids(r), ['RC001 public.profiles']);
  assert.match(r.findings[0].plain, /can read every row/);
});

test('H5: REVOKE GRANT OPTION FOR leaves the privilege in place', async () => {
  const r = await scanSql(`create table public.t (id int);
    revoke insert, update, delete on public.t from anon, authenticated;
    revoke grant option for select on public.t from anon, authenticated;`);
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

// ── M1: FOR ROLE ────────────────────────────────────────────────────────

test('M1: default privileges FOR ROLE another role do not affect migration tables', async () => {
  const r = await scanSql(`alter default privileges for role supabase_admin in schema public revoke all on tables from anon, authenticated;
    create table public.t (id int);`);
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

test('M1: default privileges FOR ROLE postgres do apply', async () => {
  const r = await scanSql(`alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated;
    create table public.t (id int);`);
  assert.deepEqual(ids(r), []);
});

test('M1: a global FOR ROLE revoke for another role keeps PUBLIC EXECUTE', async () => {
  const r = await scanSql(`alter default privileges for role supabase_admin revoke execute on functions from public;
    alter default privileges in schema public revoke execute on functions from anon, authenticated;
    ${DEF()}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

// ── M2 / M3: function renames and lists ─────────────────────────────────

test('M2: ALTER FUNCTION ... SET SCHEMA moves it into the exposed schema', async () => {
  const r = await scanSql(`create schema priv;
    create function priv.f() returns int language sql security definer set search_path = '' as $$ select 1 $$;
    alter function priv.f() set schema public;`);
  assert.deepEqual(ids(r), ['RC002 public.f()']);
});

test('M2: ALTER FUNCTION ... RENAME TO keeps tracking it', async () => {
  const r = await scanSql(`${DEF('old')}\nalter function public.old(uuid) rename to new_name;\nrevoke execute on function public.new_name(uuid) from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('M3: a GRANT naming several functions applies to all of them', async () => {
  const r = await scanSql(`${DEF('a', '')}\n${DEF('b', '')}
    revoke execute on function public.a(), public.b() from public, anon;
    grant execute on function public.a(), public.b() to anon;`);
  assert.deepEqual(ids(r), ['RC002 public.a()', 'RC002 public.b()']);
});

// ── M5 / M6: config.toml and schema lists ───────────────────────────────

test('M5: [api] schemas is read when [api] is the last section or a Z appears before it', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-toml-'));
  fs.mkdirSync(path.join(root, 'supabase'));
  try {
    fs.writeFileSync(path.join(root, 'supabase', 'config.toml'), `[db]\nport = 1\n[api]\n# Zones\nschemas = ["public", "api"]\n`);
    assert.deepEqual(readExposedSchemas(root), ['public', 'api']);
    fs.writeFileSync(path.join(root, 'supabase', 'config.toml'), `[api]\nschemas = [\n  "public",\n  "graphql_public",\n  "api",\n]\n[db]\nport = 1\n`);
    assert.deepEqual(readExposedSchemas(root), ['public', 'graphql_public', 'api']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('M6: ON ALL TABLES IN SCHEMA a, b applies to both schemas', async () => {
  const r = await scanSql(`create schema api; grant usage on schema api to anon;
    create table api.t (id int);
    grant all on all tables in schema public, api to anon;`, { config: { exposedSchemas: ['public', 'api'] } });
  assert.deepEqual(ids(r), ['RC001 api.t']);
});

// ── M7: SELECT INTO ─────────────────────────────────────────────────────

test('M7: SELECT ... INTO a new table is a copy with no security', async () => {
  const r = await scanSql(`create table public.orders (id int); alter table public.orders enable row level security;
    select * into public.orders_backup from public.orders;`);
  assert.deepEqual(ids(r), ['RC001 public.orders_backup']);
  assert.match(r.findings[0].plain, /copy of another table/);
});

test('M7: WITH ... INSERT INTO is not a new table', async () => {
  const r = await scanSql(`create table public.t (id int); alter table public.t enable row level security;
    with x as (select 1 as id) insert into public.t select id from x;`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.coverage.tables, 1);
});

// ── M8 / L3: signatures ─────────────────────────────────────────────────

test('M8: an argument named after a type still matches its REVOKE', async () => {
  const r = await scanSql(`${DEF('find', 'name text')}\nrevoke execute on function public.find(text) from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('M8: DROP FUNCTION with a type-named argument leaves no ghost', async () => {
  const r = await scanSql(`${DEF('d', 'date date')}\ndrop function public.d(date);`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.coverage.functions, 0);
});

test('L3: timestamp(3) with time zone keeps its zone', async () => {
  const r = await scanSql(`${DEF('f', 'ts timestamp(3) with time zone')}\n${DEF('f', 'ts timestamp')}
    revoke execute on function public.f(timestamptz) from public, anon;`);
  assert.deepEqual(ids(r), ['RC002 public.f(timestamp without time zone)']);
});

// ── M9: performance ─────────────────────────────────────────────────────

test('M9: a 24,000-statement baseline parses in well under a few seconds', () => {
  const sql = Array.from({ length: 24000 }, (_, i) => `insert into public.big values (${i}, 'row ${i}');`).join('\n');
  const t0 = Date.now();
  const m = buildModel([{ file: 'big.sql', sql }]);
  assert.equal(m.coverage.statements, 24000);
  assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms`);
});

// ── L1 / L2 / L4 / L5 / L6 ──────────────────────────────────────────────

test('L1: RLS keywords inside a string literal do not turn RLS on', async () => {
  const r = await scanSql(`create table public.t (id int, note text);
    alter table public.t alter column note set default 'enable row level security';`);
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

test('L2: a global default-privilege GRANT on tables to anon is applied', async () => {
  const r = await scanSql(`alter default privileges grant select on tables to anon;\ncreate table public.t (id int);`, { config: { defaults: 'clean' } });
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

test('L4: SET search_path FROM CURRENT counts as pinned', async () => {
  const r = await scanSql(`create function public.f() returns int language sql security definer set search_path from current as $$ select 1 $$;
    revoke execute on function public.f() from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('L5: USING (owner) WITH CHECK (true) is a "claim" warning, not "change every row"', async () => {
  const r = await scanSql(`create table public.notes (id int, user_id uuid); alter table public.notes enable row level security;
    create policy "edit own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (true);`);
  assert.deepEqual(ids(r), ['RC005 public.notes']);
  assert.equal(r.findings[0].severity, 'warning');
  assert.match(r.findings[0].plain, /claim to belong to someone else/);
});

test('L6: unqualified CREATE after SET search_path lands in that schema', async () => {
  const r = await scanSql(`create schema private; set search_path to private; create table secrets (id int);`);
  assert.deepEqual(ids(r), []);
});

test('L6: search_path resets at the start of each migration file', async () => {
  const r = await scanSql({ '0001.sql': `create schema private; set search_path to private;`, '0002.sql': `create table t (id int);` });
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

// ── C2 / H1 / L7 / L8: live probe safety ────────────────────────────────

const REF = 'abcdefghijklmnopqrst';

function liveProject(envText) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-live2-'));
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '0001.sql'), 'create table public.t (id int); alter table public.t enable row level security;');
  if (envText) fs.writeFileSync(path.join(root, '.env'), envText);
  return root;
}

test('C2: a repo .env URL is never paired with the shell\'s keys', async () => {
  const root = liveProject('VITE_SUPABASE_URL=https://attacker.example\nVITE_SUPABASE_ANON_KEY=x\n');
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return new Response('{}', { status: 200 });
  };
  try {
    await assert.rejects(
      scan({ root, live: true, env: { SUPABASE_SERVICE_ROLE_KEY: 'REAL_SECRET' }, fetchImpl }),
      (e) => e.code === 4 && /only sends your keys to https:\/\/<project-ref>\.supabase\.co/.test(e.message),
    );
    assert.equal(calls.length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('C2: only hosted supabase.co over https or localhost are accepted targets', () => {
  assert.equal(checkTarget(`https://${REF}.supabase.co`).ok, true);
  assert.equal(checkTarget('http://127.0.0.1:54321').ok, true);
  assert.equal(checkTarget(`http://${REF}.supabase.co`).ok, false);
  assert.equal(checkTarget(`https://${REF}.supabase.co.attacker.example`).ok, false);
  assert.equal(checkTarget(`https://user:pw@${REF}.supabase.co`).ok, false);
  assert.equal(checkTarget(`https://${REF}.supabase.co/rest`).ok, false);
  assert.equal(checkTarget('https://attacker.example').ok, false);
});

test('H1/L7: no request follows redirects, and the ownership proof asks for a user that does not exist', async () => {
  const root = liveProject(`SUPABASE_URL=https://${REF}.supabase.co\nSUPABASE_ANON_KEY=anon\nSUPABASE_SERVICE_ROLE_KEY=svc\n`);
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.includes('/auth/v1/admin/users/')) return new Response('{"error_code":"user_not_found"}', { status: 404 });
    return new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/' } });
  };
  try {
    const r = await scan({ root, live: true, env: {}, fetchImpl });
    assert.ok(calls.every((c) => c.init.redirect === 'manual'));
    assert.ok(calls.every((c) => c.url.startsWith(`https://${REF}.supabase.co/`)));
    assert.ok(calls.some((c) => c.url.endsWith('/auth/v1/admin/users/00000000-0000-0000-0000-000000000000')));
    assert.ok(!calls.some((c) => /admin\/users\?/.test(c.url)));
    assert.equal(r.live.open, 0);
    assert.equal(r.live.errors, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('L8: a secret key in the public slot is refused', async () => {
  const fake = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')}.sig`;
  for (const key of ['sb_secret_abc', fake]) {
    const root = liveProject(`SUPABASE_URL=https://${REF}.supabase.co\nSUPABASE_ANON_KEY=${key}\n`);
    try {
      await assert.rejects(scan({ root, live: true, env: { SUPABASE_ACCESS_TOKEN: 't' }, fetchImpl: async () => new Response('{}') }), /is a secret key/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

// ── L9 to L12: MCP protocol ─────────────────────────────────────────────

test('L9: a null message gets an Invalid request error instead of crashing', async () => {
  const res = await handleMessage(null);
  assert.equal(res.error.code, -32600);
});

test('L10: initialize sent as a notification gets no reply', async () => {
  assert.equal(await handleMessage({ jsonrpc: '2.0', method: 'initialize', params: {} }), null);
});

test('L11: a response-shaped message gets no reply; a method-less request is invalid', async () => {
  assert.equal(await handleMessage({ jsonrpc: '2.0', id: 7, result: {} }), null);
  assert.equal((await handleMessage({ jsonrpc: '2.0', id: 8 })).error.code, -32600);
});

test('L12: bad tool arguments come back as a tool error', async () => {
  const res = await handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'scan', arguments: { path: 5 } } });
  assert.equal(res.result.isError, true);
});

test('lexer sanity: statements are split exactly once each', () => {
  const s = splitStatements(`select 1; select E'a\\\\'; select 'b';`);
  assert.equal(s.length, 3);
});

// ── Second review: schema resolution ────────────────────────────────────

test('N1: SET search_path TO DEFAULT puts tables in public', async () => {
  const r = await scanSql(`set search_path to default; create table secrets(id int);`);
  assert.deepEqual(ids(r), ['RC001 public.secrets']);
});

test('N2: SET LOCAL and set_config(..., true) end with the transaction', async () => {
  const a = await scanSql(`create schema private; begin; set local search_path = private; commit; create table secrets(id int);`);
  assert.deepEqual(ids(a), ['RC001 public.secrets']);
  const b = await scanSql(`create schema private; begin; select set_config('search_path', 'private', true); rollback; create table secrets(id int);`);
  assert.deepEqual(ids(b), ['RC001 public.secrets']);
  const c = await scanSql(`create schema private; begin; set local search_path = private; create table inside(id int); commit;`);
  assert.deepEqual(ids(c), []);
});

test('N3: RESET ALL restores the default path', async () => {
  const r = await scanSql(`create schema private; set search_path = private; reset all; create table secrets(id int);`);
  assert.deepEqual(ids(r), ['RC001 public.secrets']);
});

test('N4: a schema that does not exist is skipped in the path', async () => {
  const r = await scanSql(`set search_path = nonexistent, public; create table secrets(id int);`);
  assert.deepEqual(ids(r), ['RC001 public.secrets']);
});

test('N5: CREATE SCHEMA IF NOT EXISTS does not close a schema it may not have created', async () => {
  const r = await scanSql(`create schema if not exists api; create table api.t(id int); grant all on api.t to anon;`, { config: { exposedSchemas: ['api'] } });
  assert.deepEqual(ids(r), ['RC001 api.t']);
});

test('L-a: an argument named time with type time with time zone still matches its revoke', async () => {
  const r = await scanSql(`create function public.k(time time with time zone) returns int language sql security definer set search_path = '' as $$ select 1 $$;
    revoke execute on function public.k(time with time zone) from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('L-b: migrationRoles from the config scopes FOR ROLE', async () => {
  const sql = `alter default privileges for role deployer in schema public revoke all on tables from anon, authenticated; create table public.t (id int);`;
  assert.deepEqual(ids(await scanSql(sql)), ['RC001 public.t']);
  assert.deepEqual(ids(await scanSql(sql, { config: { migrationRoles: ['deployer'] } })), []);
});
