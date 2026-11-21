import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSql, ids } from './helpers.js';

const LOCKED_TABLE = `
create table public.orders (id uuid primary key default gen_random_uuid(), user_id uuid not null, total numeric(10,2));
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select to authenticated using ((select auth.uid()) = user_id);
`;

// ── RC001 ────────────────────────────────────────────────────────────────

test('RC001: table without RLS in public is critical', async () => {
  const r = await scanSql(`create table public.customers (id uuid primary key, email text);`);
  assert.deepEqual(ids(r), ['RC001 public.customers']);
  assert.equal(r.findings[0].severity, 'critical');
  assert.match(r.findings[0].plain, /Anyone on the internet/);
  assert.match(r.findings[0].fix, /alter table public\.customers enable row level security;/);
  assert.equal(r.grade.letter, 'F');
});

test('RC001: CREATE TABLE AS copy is caught and the fix also revokes', async () => {
  const r = await scanSql(`${LOCKED_TABLE}\ncreate table public._snapshot_orders as select * from public.orders;`);
  assert.deepEqual(ids(r), ['RC001 public._snapshot_orders']);
  assert.match(r.findings[0].plain, /copy of another table/);
  assert.match(r.findings[0].fix, /revoke all on public\._snapshot_orders from anon, authenticated;/);
});

test('RC001: RLS enabled later in another migration closes it', async () => {
  const r = await scanSql({
    '0001.sql': `create table public.customers (id uuid primary key);`,
    '0002.sql': `alter table only public.customers enable row level security;`,
  });
  assert.deepEqual(ids(r), []);
});

test('RC001: RLS disabled later reopens it', async () => {
  const r = await scanSql({
    '0001.sql': `create table public.customers (id uuid primary key); alter table public.customers enable row level security;`,
    '0002.sql': `alter table public.customers disable row level security;`,
  });
  assert.deepEqual(ids(r), ['RC001 public.customers']);
});

test('RC001: no RLS but all API grants revoked is not a door', async () => {
  const r = await scanSql(`create table public.internal_jobs (id int); revoke all on table public.internal_jobs from anon, authenticated;`);
  assert.deepEqual(ids(r), []);
});

test('RC001: revoking only from anon leaves signed-in users with access', async () => {
  const r = await scanSql(`create table public.notes (id int); revoke all on public.notes from anon;`);
  assert.deepEqual(ids(r), ['RC001 public.notes']);
  assert.match(r.findings[0].plain, /Anyone who signs up/);
});

test('RC001: tables outside exposed schemas are ignored', async () => {
  const r = await scanSql(`create schema private; create table private.secrets (id int);`);
  assert.deepEqual(ids(r), []);
});

test('RC001: dropped and renamed tables are tracked', async () => {
  const r = await scanSql(`
    create table public.a (id int);
    drop table public.a;
    create table public.b (id int);
    alter table public.b rename to c;
    alter table public.c enable row level security;
  `);
  assert.deepEqual(ids(r), []);
});

test('pg_dump style quoted identifiers are parsed', async () => {
  const r = await scanSql(`
    CREATE TABLE IF NOT EXISTS "public"."Profiles" ("id" "uuid" NOT NULL);
    GRANT ALL ON TABLE "public"."Profiles" TO "anon";
  `);
  assert.deepEqual(ids(r), ['RC001 public.Profiles']);
  assert.match(r.findings[0].fix, /alter table public\."Profiles"/);
});

test('commented-out DDL is not counted', async () => {
  const r = await scanSql(`-- create table public.ghost (id int);\n/* create table public.ghost2 (id int); */\nselect 1;`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.coverage.tables, 0);
});

// ── RC002 ────────────────────────────────────────────────────────────────

const DEFINER = (name = 'get_orders') => `
create function public.${name}(uid uuid) returns setof public.orders
language sql security definer set search_path = '' as $$ select * from public.orders where user_id = uid $$;`;

test('RC002: definer with default grants is callable by anyone', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${DEFINER()}`);
  assert.deepEqual(ids(r), ['RC002 public.get_orders(uuid)']);
  assert.match(r.findings[0].fix, /revoke execute on function public\.get_orders\(uuid\) from public, anon;/);
});

test('RC002: revoking from public and anon closes it', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${DEFINER()}\nrevoke execute on function public.get_orders(uuid) from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('RC002: dropping and re-creating after a revoke reopens it', async () => {
  const r = await scanSql({
    '0001.sql': `${LOCKED_TABLE}${DEFINER()}\nrevoke execute on function public.get_orders(uuid) from public, anon;`,
    '0002.sql': `drop function public.get_orders(uuid);${DEFINER()}`,
  });
  assert.deepEqual(ids(r), ['RC002 public.get_orders(uuid)']);
});

test('RC002: CREATE OR REPLACE keeps an earlier revoke', async () => {
  const r = await scanSql({
    '0001.sql': `${LOCKED_TABLE}${DEFINER()}\nrevoke execute on function public.get_orders(uuid) from public, anon;`,
    '0002.sql': DEFINER().replace('create function', 'create or replace function'),
  });
  assert.deepEqual(ids(r), []);
});

test('RC002: a revoke on one overload does not cover another', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create function public.f(a uuid) returns int language sql security definer set search_path = '' as $$ select 1 $$;
    create function public.f(a uuid, b text) returns int language sql security definer set search_path = '' as $$ select 2 $$;
    revoke execute on function public.f(uuid) from public, anon;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid, text)']);
});

test('RC002: global default-privilege revoke means new functions are born closed', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    alter default privileges revoke execute on functions from public;
    alter default privileges in schema public revoke execute on functions from anon, authenticated;
    ${DEFINER()}`);
  assert.deepEqual(ids(r), []);
});

test('RC002: config defaults "clean" models a baseline that revoked grants dynamically', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${DEFINER()}`, { config: { defaults: { functions: 'clean' } } });
  assert.deepEqual(ids(r), []);
});

// ── RC003 ────────────────────────────────────────────────────────────────

test('RC003: definer without search_path is high', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create function public.touch() returns void language plpgsql security definer as $$ begin update orders set total = total; end $$;
    revoke execute on function public.touch() from public, anon;`);
  assert.deepEqual(ids(r), ['RC003 public.touch()']);
  assert.equal(r.findings[0].severity, 'high');
  assert.equal(r.grade.letter, 'C');
});

test('RC003: attributes after the body are read', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create function public.touch() returns void as $$ begin null; end $$ language plpgsql security definer set search_path = public;
    revoke execute on function public.touch() from public, anon;`);
  assert.deepEqual(ids(r), []);
});

test('RC003: ALTER FUNCTION ... SET search_path fixes it', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create function public.touch() returns void language plpgsql security definer as $$ begin null; end $$;
    revoke execute on function public.touch() from public, anon;
    alter function public.touch() set search_path = '';`);
  assert.deepEqual(ids(r), []);
});

// ── RC004 ────────────────────────────────────────────────────────────────

const AUDIT = `
create table public.order_events (id bigint generated always as identity, order_id uuid, actor uuid);
alter table public.order_events enable row level security;
`;

test('RC004: invoker trigger writing to a deny-all table is high', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${AUDIT}
    create function public.log_order() returns trigger language plpgsql as $$
    begin insert into public.order_events (order_id, actor) values (new.id, auth.uid()); return new; end $$;
    create trigger log_order after update on public.orders for each row execute function public.log_order();`);
  assert.deepEqual(ids(r), ['RC004 public.log_order()']);
  assert.match(r.findings[0].plain, /When a user changes orders/);
  assert.match(r.findings[0].fix, /alter function public\.log_order\(\) security definer;/);
});

test('RC004: SECURITY DEFINER trigger is fine', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${AUDIT}
    create function public.log_order() returns trigger language plpgsql security definer set search_path = '' as $$
    begin insert into public.order_events (order_id) values (new.id); return new; end $$;`);
  assert.deepEqual(ids(r), []);
});

test('RC004: a table with a policy is not deny-all', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${AUDIT}
    create policy "insert own" on public.order_events for insert to authenticated with check (actor = auth.uid());
    create function public.log_order() returns trigger language plpgsql as $$
    begin insert into order_events (order_id) values (new.id); return new; end $$;`);
  assert.deepEqual(ids(r), []);
});

test('RC004: name prefix does not match a different table', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${AUDIT}
    create table public.order_events_archive (id int); alter table public.order_events_archive enable row level security;
    create policy p on public.order_events_archive for all to authenticated using (true) with check (true);
    drop table public.order_events;
    create function public.log_order() returns trigger language plpgsql as $$
    begin insert into public.order_events_archive (id) values (1); return new; end $$;`);
  assert.equal(ids(r).filter((x) => x.startsWith('RC004')).length, 0);
});

// ── RC005 ────────────────────────────────────────────────────────────────

test('RC005: permissive UPDATE using (true) for everyone is high', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create policy "anyone can edit" on public.orders for update using (true);`);
  assert.deepEqual(ids(r), ['RC005 public.orders']);
  assert.equal(r.findings[0].detail, 'anyone can edit');
  assert.equal(r.findings[0].severity, 'high');
  assert.match(r.findings[0].plain, /Anyone on the internet can change any row/);
});

test('RC005: SELECT using (true) for anon is only a warning', async () => {
  const r = await scanSql(`
    create table public.menu_items (id int, name text);
    alter table public.menu_items enable row level security;
    create policy "public menu" on public.menu_items for select to anon using (true);`);
  assert.deepEqual(ids(r), ['RC005 public.menu_items']);
  assert.equal(r.findings[0].severity, 'warning');
  assert.equal(r.grade.letter, 'B');
});

test('RC005: "to" inside a USING expression is not read as a role list', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create policy "mine" on public.orders for update using (status = 'to ship' and user_id = auth.uid());`);
  assert.deepEqual(ids(r), []);
});

test('RC005: dropped policy no longer counts', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create policy "anyone can edit" on public.orders for update using (true);
    drop policy if exists "anyone can edit" on public.orders;`);
  assert.deepEqual(ids(r), []);
});

test('RC005: restrictive policies are not flagged', async () => {
  const r = await scanSql(`${LOCKED_TABLE}
    create policy "gate" on public.orders as restrictive for update using (true);`);
  assert.deepEqual(ids(r), []);
});

// ── Allowlist, coverage, doors ───────────────────────────────────────────

test('allow entry with a reason moves the finding to allowed', async () => {
  const sql = `create table public.menu_items (id int); alter table public.menu_items enable row level security;
    create policy "public menu" on public.menu_items for select to anon using (true);`;
  const r = await scanSql(sql, { config: { allow: [{ rule: 'RC005', object: 'public.menu_items', reason: 'The menu is published on the website.' }] } });
  assert.deepEqual(ids(r), []);
  assert.equal(r.allowed.length, 1);
  assert.equal(r.grade.letter, 'A');
});

test('allow entry without a real reason is rejected', async () => {
  await assert.rejects(scanSql(`select 1;`, { config: { allow: [{ rule: 'RC001', object: 'public.x', reason: 'ok' }] } }), /needs a "reason"/);
});

test('stale allow entries are reported', async () => {
  const r = await scanSql(`select 1;`, { config: { allow: [{ rule: 'RC001', object: 'public.gone', reason: 'Was a public lookup table.' }] } });
  assert.equal(r.configWarnings.length, 1);
  assert.match(r.configWarnings[0], /matches nothing/);
});

test('doors open and grade come from the same findings', async () => {
  const r = await scanSql(`
    create table public.a (id int);
    create table public.b (id int);
    create table public.c (id int); alter table public.c enable row level security;`);
  assert.equal(r.doors.checked, 3);
  assert.equal(r.doors.open, 2);
  assert.equal(r.counts.critical, 2);
});

test('coverage reports what was parsed', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${DEFINER()}`);
  assert.equal(r.coverage.ok, true);
  assert.equal(r.coverage.files, 1);
  assert.equal(r.coverage.tables, 1);
  assert.equal(r.coverage.functions, 1);
  assert.ok(r.coverage.statements >= 4);
});

test('a clean project grades A', async () => {
  const r = await scanSql(`${LOCKED_TABLE}${AUDIT}${DEFINER()}
    revoke execute on function public.get_orders(uuid) from public, anon;
    create function public.log_order() returns trigger language plpgsql security definer set search_path = '' as $$
    begin insert into public.order_events (order_id) values (new.id); return new; end $$;`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.grade.letter, 'A');
  assert.equal(r.doors.open, 0);
});

test('RC005: INSERT with check (true) is a warning (often a public form)', async () => {
  const r = await scanSql(`
    create table public.waitlist (email text);
    alter table public.waitlist enable row level security;
    create policy "anyone can join" on public.waitlist for insert to anon with check (true);`);
  assert.deepEqual(ids(r), ['RC005 public.waitlist']);
  assert.equal(r.findings[0].severity, 'warning');
  assert.match(r.findings[0].plain, /signup or contact form/);
  assert.match(r.findings[0].fix, /for insert to authenticated with check \(\(select auth\.uid\(\)\) = user_id\);/);
});
