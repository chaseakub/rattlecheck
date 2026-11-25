// DO blocks: the replay applies what is certain to run, and nothing else.
// Found on a real project whose baseline closes Supabase's default grants
// inside `DO $$ ... EXECUTE format(...) $$`; skipping the block reported 100
// locked functions as open to the public.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSql, ids } from './helpers.js';
import { replayableFromDo } from '../src/sql/doblock.js';

const DEF = (name = 'f') =>
  `create function public.${name}(uid uuid) returns int language sql security definer set search_path = '' as $$ select 1 $$;`;
// What pg_dump writes for a function only the server may call.
const DUMP_ACL = (name = 'f') => `revoke all on function public.${name}(uuid) from public;\ngrant all on function public.${name}(uuid) to service_role;`;

const PRELUDE = `
DO $$
DECLARE
  v_creator text := current_user;
BEGIN
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA "public" '
    'REVOKE ALL ON FUNCTIONS FROM "anon", "authenticated", "service_role"', v_creator);
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA "public" '
    'REVOKE ALL ON TABLES FROM "anon", "authenticated", "service_role"', v_creator);
END $$;`;

test('control: without the prelude, a dumped server-only function is still open to anon', async () => {
  const r = await scanSql(`${DEF()}\n${DUMP_ACL()}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('a default-privilege revoke run through EXECUTE format() in a DO block is replayed', async () => {
  const r = await scanSql(`${PRELUDE}\n${DEF()}\n${DUMP_ACL()}\ncreate table public.t (id int);`);
  assert.deepEqual(ids(r), []);
  assert.deepEqual(r.coverage.doBlocks, { seen: 1, replayed: 2, skipped: 0 });
});

test('the prelude only covers what is created after it', async () => {
  const r = await scanSql(`${DEF()}\n${DUMP_ACL()}\n${PRELUDE}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('a revoke inside IF may not run, so it is not counted', async () => {
  const r = await scanSql(`${DEF()}
    DO $$ BEGIN
      IF current_setting('app.env', true) = 'prod' THEN
        REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, anon;
        EXECUTE 'revoke execute on function public.f(uuid) from public, anon';
      END IF;
    END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
  assert.equal(r.coverage.doBlocks.skipped, 2);
});

test('a revoke inside a loop, a CASE or a nested block is not counted', async () => {
  for (const wrap of [
    (s) => `FOR i IN 1..n LOOP ${s} END LOOP;`,
    (s) => `WHILE false LOOP ${s} END LOOP;`,
    (s) => `CASE WHEN false THEN ${s} ELSE NULL; END CASE;`,
    (s) => `BEGIN ${s} EXCEPTION WHEN others THEN NULL; END;`,
    (s) => `DECLARE x int; BEGIN ${s} END;`,
  ]) {
    const r = await scanSql(`${DEF()}\nDO $$ DECLARE n int := 0; BEGIN ${wrap('REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, anon;')} END $$;`);
    assert.deepEqual(ids(r), ['RC002 public.f(uuid)'], wrap('...'));
  }
});

test('an exception handler on the block means none of it is certain', async () => {
  const r = await scanSql(`${DEF()}
    DO $$ BEGIN
      REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, anon;
    EXCEPTION WHEN others THEN
      RAISE NOTICE 'skipped';
    END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('nothing after an unconditional RETURN is counted', async () => {
  const r = await scanSql(`${DEF()}\nDO $$ BEGIN RETURN; REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, anon; END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('dynamic SQL built from data is not guessed at', async () => {
  const r = await scanSql(`${DEF()}
    DO $$ DECLARE r record; v text; BEGIN
      SELECT 'public.f(uuid)' INTO v;
      EXECUTE 'revoke execute on function ' || v || ' from public, anon';
      EXECUTE format('revoke execute on function %s from public, anon', (select 'public.f(uuid)'));
    END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
  assert.equal(r.coverage.doBlocks.skipped, 2);
});

test('a variable is only trusted while its value is known', async () => {
  const known = await scanSql(`${DEF()}\nDO $$ DECLARE v text := 'public.f(uuid)'; BEGIN EXECUTE 'revoke execute on function ' || v || ' from public, anon'; END $$;`);
  assert.deepEqual(ids(known), []);
  const reassigned = await scanSql(`${DEF()}\nDO $$ DECLARE v text := 'public.f(uuid)'; BEGIN
    IF now() > 'yesterday' THEN v := 'public.g(uuid)'; END IF;
    EXECUTE 'revoke execute on function ' || v || ' from public, anon'; END $$;`);
  assert.deepEqual(ids(reassigned), ['RC002 public.f(uuid)']);
});

test('ALTER DEFAULT PRIVILEGES for a role migrations do not run as changes nothing', async () => {
  const r = await scanSql(`DO $$ BEGIN
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated', 'supabase_admin');
    END $$;\n${DEF()}\n${DUMP_ACL()}`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('current_user resolves to the configured migration role', async () => {
  const sql = `DO $$ BEGIN
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated', current_user);
    END $$;\n${DEF()}\n${DUMP_ACL()}`;
  assert.deepEqual(ids(await scanSql(sql)), []);
  assert.deepEqual(ids(await scanSql(sql, { config: { migrationRoles: ['deployer'] } })), []);
});

test('quote_ident, quote_literal and || are followed', () => {
  const r = replayableFromDo(`DO $$ BEGIN
      EXECUTE 'grant select on ' || quote_ident('My Table') || ' to anon';
      EXECUTE format('create table %I (c text default %L)', 'x', 'it''s') USING 1;
      EXECUTE format('create table p (c text default ''100%%'', d %1$s, e %1$s)', 'int') INTO v;
      EXECUTE format('comment on table p is %L', 'fine');
    END $$`);
  assert.deepEqual(r.statements, ['grant select on "My Table" to anon', `create table "x" (c text default 'it''s')`, `create table p (c text default '100%', d int, e int)`, `comment on table p is 'fine'`]);
  assert.equal(r.skipped, 0);
});

test('a table created in a DO block is seen (it used to be invisible)', async () => {
  const r = await scanSql(`DO $$ BEGIN CREATE TABLE public.secrets (id int); END $$;`);
  assert.deepEqual(ids(r), ['RC001 public.secrets']);
});

test('a grant in a DO block reopens a function that was locked', async () => {
  const r = await scanSql(`${DEF()}\nrevoke execute on function public.f(uuid) from public, anon;\nDO $$ BEGIN GRANT EXECUTE ON FUNCTION public.f(uuid) TO anon; END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
});

test('SELECT ... INTO a variable inside a DO block does not invent a table', async () => {
  const r = await scanSql(`DO $$ DECLARE v_count int; BEGIN SELECT count(*) INTO v_count FROM pg_class; ASSERT v_count > 0; END $$;`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.coverage.tables, 0);
});

test('a probe that creates and drops its own objects leaves nothing behind', async () => {
  const r = await scanSql(`DO $$ BEGIN
      CREATE TABLE public._probe (id int);
      CREATE FUNCTION public._probe_fn() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = public AS 'SELECT 1';
      DROP FUNCTION public._probe_fn();
      DROP TABLE public._probe;
    END $$;`);
  assert.deepEqual(ids(r), []);
  assert.equal(r.coverage.tables + r.coverage.functions, 0);
});

test('a DO block in another language, or one that cannot be read, contributes nothing', async () => {
  assert.equal(replayableFromDo(`DO LANGUAGE plv8 $$ plv8.execute('revoke all on t from anon') $$`), null);
  assert.equal(replayableFromDo(`select 1`), null);
  const broken = replayableFromDo(`DO $$ BEGIN REVOKE ALL ON t FROM anon; END IF; END $$`);
  assert.equal(broken.followed, false);
  assert.deepEqual(broken.statements, []);
  const r = await scanSql(`create table public.t (id int);\nDO $$ BEGIN REVOKE ALL ON public.t FROM anon, authenticated; END IF; END $$;`);
  assert.deepEqual(ids(r), ['RC001 public.t']);
});

test('comments, labels and a single-quoted body are handled', () => {
  const r = replayableFromDo(`DO 'BEGIN REVOKE ALL ON t FROM anon; END' LANGUAGE plpgsql`);
  assert.deepEqual(r.statements, ['REVOKE ALL ON t FROM anon']);
  const labelled = replayableFromDo(`DO $do$ <<outer>> DECLARE a text; BEGIN /* IF */ REVOKE ALL ON t FROM anon; -- END\n END outer $do$`);
  assert.deepEqual(labelled.statements, ['REVOKE ALL ON t FROM anon']);
});

// ── From the independent review of the first version: every one of these
// hid a real hole or crashed the scan. ─────────────────────────────────────

const T = 'create table public.t (id int);';
const REVOKE_F = 'REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, anon;';

test('R1: a conditional or nested RETURN, or EXIT to the block label, makes the rest uncertain', async () => {
  for (const body of [
    `BEGIN IF current_setting('app.env', true) IS DISTINCT FROM 'prod' THEN RETURN; END IF; ${REVOKE_F} END`,
    `BEGIN BEGIN RETURN; END; ${REVOKE_F} END`,
    `<<main>> BEGIN EXIT main; ${REVOKE_F} END main`,
    `<<m>> BEGIN EXIT m WHEN true; ${REVOKE_F} END`,
    `<<m>> BEGIN LOOP EXIT m; END LOOP; ${REVOKE_F} END`,
    `BEGIN EXIT; ${REVOKE_F} END`,
  ]) {
    const r = await scanSql(`${DEF()}\nDO $$ ${body} $$;`);
    assert.deepEqual(ids(r), ['RC002 public.f(uuid)'], body);
  }
  const rls = await scanSql(`${T}\nDO $$ BEGIN IF true THEN RETURN; END IF; ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; END $$;`);
  assert.deepEqual(ids(rls), ['RC001 public.t']);
});

test('R1: EXIT inside a loop only leaves the loop, so what follows the loop still counts', async () => {
  const r = await scanSql(`${DEF()}\nDO $$ BEGIN LOOP EXIT; END LOOP; ${REVOKE_F} END $$;`);
  assert.deepEqual(ids(r), []);
});

test('R2: a search_path change inside the block makes the rest uncertain', async () => {
  for (const change of [`SET search_path TO private;`, `PERFORM set_config('search_path', 'private', false);`, `EXECUTE 'set search_path to private';`, `IF true THEN SET LOCAL search_path = private; END IF;`]) {
    const r = await scanSql(`create schema private; ${T} create table private.t (id int);
      DO $$ BEGIN ${change} ALTER TABLE t ENABLE ROW LEVEL SECURITY; END $$;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], change);
  }
});

test('R3: after SET ROLE, current_user and a bare ALTER DEFAULT PRIVILEGES are not the migration role', async () => {
  const outside = await scanSql(`SET ROLE other_owner;
    DO $$ BEGIN EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated', current_user); END $$;
    RESET ROLE; ${T}`);
  assert.deepEqual(ids(outside), ['RC001 public.t']);
  const inside = await scanSql(`DO $$ BEGIN SET ROLE other_owner; ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated; RESET ROLE; END $$;\n${T}`);
  assert.deepEqual(ids(inside), ['RC001 public.t']);
  const topLevel = await scanSql(`SET ROLE other_owner; ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated; RESET ROLE; ${T}`);
  assert.deepEqual(ids(topLevel), ['RC001 public.t']);
  const reset = await scanSql(`SET ROLE other_owner; RESET ROLE; ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated; ${T}`);
  assert.deepEqual(ids(reset), []);
});

test('R4/R7/R8: a variable that may have been rewritten is not trusted', async () => {
  for (const rewrite of [
    `FOR r IN SELECT 'service_role' LOOP END LOOP;`,
    `FOREACH r IN ARRAY ARRAY['service_role'] LOOP END LOOP;`,
    `GET DIAGNOSTICS r = PG_CONTEXT;`,
    `CALL p(r);`,
    `SELECT 'service_role' INTO r;`,
    `EXECUTE 'select 1' INTO r;`,
  ]) {
    const r = await scanSql(`${DEF()}\nDO $$ DECLARE r text := 'anon'; BEGIN ${rewrite} EXECUTE format('REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, %I', r); END $$;`);
    assert.deepEqual(ids(r), ['RC002 public.f(uuid)'], rewrite);
  }
  const quoted = await scanSql(`${DEF()}\nDO $$ DECLARE v text := 'service_role'; "V" text := 'anon'; BEGIN EXECUTE format('REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM public, %I', v); END $$;`);
  assert.deepEqual(ids(quoted), ['RC002 public.f(uuid)']);
});

test('R5: COMMIT or ROLLBACK inside the block means nothing in it is certain', async () => {
  for (const tx of ['ROLLBACK;', 'COMMIT;', `EXECUTE 'rollback';`]) {
    const r = await scanSql(`${DEF()}\nDO $$ BEGIN ${REVOKE_F} ${tx} END $$;`);
    if (tx.startsWith('EXECUTE')) continue; // dynamic transaction control errors in Postgres; just must not crash
    assert.deepEqual(ids(r), ['RC002 public.f(uuid)'], tx);
  }
});

test('R6: absurd nesting is refused, never a crash', async () => {
  const r = await scanSql(`${T}\nDO $$ BEGIN EXECUTE ${'('.repeat(6000)}'select 1'${')'.repeat(6000)}; END $$;`);
  assert.deepEqual(ids(r), ['RC001 public.t']);
  assert.equal(r.coverage.doBlocks.skipped, 1);
});

test('R9: twenty thousand labels or nested blocks do not stall the scan', () => {
  const started = Date.now();
  replayableFromDo(`DO $$ ${'<<a>> '.repeat(20000)}BEGIN NULL; END $$`);
  replayableFromDo(`DO $$ BEGIN ${'BEGIN '.repeat(20000)}NULL; ${'END; '.repeat(20000)}END $$`);
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started}ms`);
});

test('R10/R11: %0$s, undecoded E-string escapes and joined dollar strings are refused', () => {
  const none = (body) => assert.deepEqual(replayableFromDo(`DO $do$ BEGIN ${body} END $do$`).statements, [], body);
  none(`EXECUTE format('REVOKE ALL ON t FROM %0$s', 'anon');`);
  none(`EXECUTE E'REVOKE ALL ON t FROM \\x61non';`);
  none(`EXECUTE $q$REVOKE ALL ON t $q$\n'FROM anon';`);
});

// ── Second review round. The first version replayed the certain part of a
// block and dropped the uncertain part, which hid an undo two lines later. ──

const ADP = 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;';

test('S1: THEN inside a CASE expression in a condition does not hide the RETURN behind it', async () => {
  for (const cond of [
    `IF CASE WHEN true THEN true END THEN RETURN; END IF;`,
    `IF (SELECT CASE WHEN true THEN true END) THEN RETURN; END IF;`,
    `CASE WHEN CASE WHEN true THEN true END THEN RETURN; END CASE;`,
  ]) {
    const r = await scanSql(`${DEF()}\nDO $$ BEGIN ${cond} ${REVOKE_F} END $$;`);
    assert.deepEqual(ids(r), ['RC002 public.f(uuid)'], cond);
  }
});

test('S2: a lock followed by a possible undo in the same block is not counted', async () => {
  const rls = await scanSql(`${T}\nDO $$ BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; IF true THEN ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; END IF; END $$;`);
  assert.deepEqual(ids(rls), ['RC001 public.t']);
  const grant = await scanSql(`${DEF()}\nDO $$ BEGIN ${REVOKE_F} IF true THEN GRANT EXECUTE ON FUNCTION public.f(uuid) TO anon; END IF; END $$;`);
  assert.deepEqual(ids(grant), ['RC002 public.f(uuid)']);
  const dynamic = await scanSql(`${T}\nDO $$ DECLARE x text := current_setting('app.x'); BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; EXECUTE 'ALTER TABLE public.t DISABLE ROW LEVEL SECURITY' || x; END $$;`);
  assert.deepEqual(ids(dynamic), ['RC001 public.t']);
});

test('S3: a door that might be opened in a later block is counted, even when conditional', async () => {
  const r = await scanSql(`${DEF()}\n${REVOKE_F}\nDO $$ BEGIN IF true THEN GRANT EXECUTE ON FUNCTION public.f(uuid) TO anon; END IF; END $$;`);
  assert.deepEqual(ids(r), ['RC002 public.f(uuid)']);
  const rls = await scanSql(`${T}\nalter table public.t enable row level security;\nDO $$ BEGIN FOR i IN 1..1 LOOP ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; END LOOP; END $$;`);
  assert.deepEqual(ids(rls), ['RC001 public.t']);
});

test('S4: a session change inside a DO block carries over to the statements after it', async () => {
  for (const change of [`SET ROLE other_owner;`, `EXECUTE 'SET ROLE other_owner';`, `EXECUTE 'SET ROLE ' || current_setting('app.r');`]) {
    const r = await scanSql(`DO $$ BEGIN ${change} END $$;\n${ADP}\nRESET ROLE;\n${T}`);
    assert.deepEqual(ids(r), ['RC001 public.t'], change);
  }
  for (const change of [`SET search_path TO private;`, `EXECUTE 'SET search_path TO ' || current_setting('app.s');`]) {
    const r = await scanSql(`create schema private; ${T} create table private.t (id int);\nDO $$ BEGIN ${change} END $$;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], change);
  }
  // A later explicit SET puts the reader back on solid ground.
  const back = await scanSql(`${T}\nDO $$ BEGIN SET search_path TO private; END $$;\nSET search_path TO public;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;`);
  assert.deepEqual(ids(back), []);
});

test('S5: role tracking is not fooled by RESET search_path, a quoted name, or a combined set_config', async () => {
  for (const sql of [
    `SET ROLE other_owner; RESET search_path; ${ADP} RESET ROLE; ${T}`,
    `SET "role" TO other_owner; ${ADP} RESET ROLE; ${T}`,
    `SET role = other_owner; ${ADP} RESET ROLE; ${T}`,
    `SELECT set_config('search_path','public',false), set_config('role','other_owner',false); ${ADP} RESET ROLE; ${T}`,
  ]) assert.deepEqual(ids(await scanSql(sql)), ['RC001 public.t'], sql);
  for (const sql of [`SET ROLE other_owner; SET ROLE NONE; ${ADP} ${T}`, `SET ROLE other_owner; RESET ALL; ${ADP} ${T}`, `SET role = default; ${ADP} ${T}`]) {
    assert.deepEqual(ids(await scanSql(sql)), [], sql);
  }
});

// ── Third review round: a block that looks clean can still undo its own lock
// through something the reader can't see into. ─────────────────────────────

test('T1: a block is not trusted when it runs another DO, writes data, or calls a procedure', async () => {
  for (const hidden of [
    `EXECUTE 'DO $i$ BEGIN ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; END $i$';`,
    `UPDATE public.t SET id = id;`,
    `INSERT INTO public.t VALUES (1);`,
    `CALL public.unlock();`,
    `PERFORM 1 FROM (WITH d AS (DELETE FROM public.t RETURNING 1) SELECT 1 FROM d) q;`,
    `EXECUTE 'call public.unlock()';`,
  ]) {
    const r = await scanSql(`${T}\nDO $$ BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; ${hidden} END $$;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], hidden);
  }
});

test('T1: a block that calls a function the migrations define is not trusted', async () => {
  const unlock = `create function public.unlock() returns void language sql as $$ alter table public.t disable row level security $$;`;
  for (const call of [`PERFORM public.unlock();`, `PERFORM "unlock"();`, `IF public.unlock() IS NULL THEN NULL; END IF;`, `EXECUTE 'select public.unlock()';`]) {
    const r = await scanSql(`${T}\n${unlock}\nDO $$ BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; ${call} END $$;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], call);
  }
  // Built-ins, and a function merely NAMED in a grant, do not spoil a block.
  const fine = await scanSql(`${DEF()}\nDO $$ DECLARE n int; BEGIN SELECT count(*) INTO n FROM pg_class WHERE coalesce(relname, '') <> ''; ASSERT n > 0; ${REVOKE_F} END $$;`);
  assert.deepEqual(ids(fine), []);
});

test('T1: search_path changed through a quoted set_config or pg_settings is caught', async () => {
  for (const change of [`PERFORM pg_catalog."set_config"('search_path','private',false);`, `UPDATE pg_settings SET setting = 'private' WHERE name = 'search_path';`, `PERFORM set_config(v, 'private', false);`]) {
    const r = await scanSql(`create schema private; ${T} create table private.t (id int);\nDO $$ DECLARE v text := 'search_path'; BEGIN ${change} ALTER TABLE t ENABLE ROW LEVEL SECURITY; END $$;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], change);
  }
});

test('T2: an uncertain ALTER FUNCTION that also pins search_path is not credited', async () => {
  const r = await scanSql(`create function public.g() returns int language sql security definer as $$ select 1 $$;
    revoke execute on function public.g() from public, anon, authenticated;
    DO $$ BEGIN IF false THEN ALTER FUNCTION public.g() SECURITY DEFINER SET search_path = ''; END IF; END $$;`);
  assert.deepEqual(ids(r), ['RC003 public.g()']);
});

test('T3: a harmless setting changed in a DO block does not blind the rest of the file', async () => {
  const harmless = `DO $$ BEGIN PERFORM set_config('app.x', '1', false); SET LOCAL lock_timeout = '5s'; END $$;`;
  const grant = await scanSql(`${T}\nrevoke all on public.t from anon, authenticated;\n${harmless}\nGRANT SELECT ON t TO anon;`);
  assert.deepEqual(ids(grant), ['RC001 public.t']);
  const lock = await scanSql(`${T}\n${harmless}\nALTER TABLE t ENABLE ROW LEVEL SECURITY;`);
  assert.deepEqual(ids(lock), []);
});

test('T3: with search_path unknown, statements that open something still land', async () => {
  const lost = `DO $$ BEGIN SET search_path TO private; END $$;`;
  const grant = await scanSql(`${T}\nrevoke all on public.t from anon, authenticated;\n${lost}\nGRANT SELECT ON t TO anon;`);
  assert.deepEqual(ids(grant), ['RC001 public.t']);
  const rls = await scanSql(`${T}\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n${lost}\nALTER TABLE t DISABLE ROW LEVEL SECURITY;`);
  assert.deepEqual(ids(rls), ['RC001 public.t']);
  const policy = await scanSql(`${T}\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n${lost}\nCREATE POLICY p ON t FOR ALL TO anon USING (true) WITH CHECK (true);`);
  assert.deepEqual(ids(policy), ['RC005 public.t', 'RC006 public.t']);
  // SET LOCAL does not put the session path back.
  const local = await scanSql(`create schema private; ${T} create table private.t (id int);\n${lost}\nBEGIN; SET LOCAL search_path TO public; COMMIT;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;`);
  assert.deepEqual(ids(local), ['RC001 public.t']);
});

// ── Fourth review round ─────────────────────────────────────────────────

test('U1: a block that reads a view or table of the project is not trusted (a view can call anything)', async () => {
  const setup = `${T}
    create function public.unlock() returns int language plpgsql as $f$ begin alter table public.t disable row level security; return 1; end $f$;
    create view public.v with (security_invoker = true) as select public.unlock() as x;
    revoke all on public.v from anon, authenticated;`;
  for (const read of [
    `PERFORM * FROM public.v;`,
    `PERFORM 1 FROM pg_class c, public.v;`,
    `PERFORM 1 FROM pg_class c JOIN v ON true;`,
    `IF EXISTS (SELECT 1 FROM "v") THEN NULL; END IF;`,
    `EXECUTE 'select * from public.v';`,
    `CREATE TABLE public.copy AS SELECT * FROM public.v;`,
    `PERFORM 1 FROM pg_v;`,
  ]) {
    const r = await scanSql(`${setup}\nDO $$ BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; ${read} END $$;`);
    assert.ok(ids(r).includes('RC001 public.t'), read);
  }
});

test('U1: reading the system catalogs does not spoil a block', async () => {
  const r = await scanSql(`${DEF()}\nDO $$ DECLARE v_leaked text; BEGIN
      ${REVOKE_F}
      SELECT string_agg(DISTINCT coalesce(n.nspname, '<global>'), ', ') INTO v_leaked
        FROM pg_default_acl d
        LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
       CROSS JOIN LATERAL aclexplode(d.defaclacl) a
       WHERE a.grantee = 'anon'::regrole AND extract(epoch FROM now()) > 0 AND n.nspname IS DISTINCT FROM 'x';
      PERFORM 1 FROM pg_catalog.pg_proc p JOIN information_schema.tables t ON true;
      ASSERT v_leaked IS NULL, 'leaked';
    END $$;`);
  assert.deepEqual(ids(r), []);
});

test('U2: a function the block creates and then calls is the project\'s own code too', async () => {
  for (const make of [
    `CREATE FUNCTION public.unlock() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; RETURN 1; END $f$;`,
    `EXECUTE 'CREATE FUNCTION public.unlock() RETURNS int LANGUAGE sql AS ''ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; SELECT 1''';`,
  ]) {
    const r = await scanSql(`${T}\nDO $$ BEGIN ALTER TABLE public.t ENABLE ROW LEVEL SECURITY; ${make} PERFORM public.unlock(); END $$;`);
    assert.deepEqual(ids(r), ['RC001 public.t'], make);
  }
});

// ── Fifth review round ──────────────────────────────────────────────────

test('V1: TABLE name, a cast to a project type, and a function made by an untrusted block all spoil a block', async () => {
  const unlock = `create function public.unlock() returns int language plpgsql as $f$ begin alter table public.t disable row level security; return 1; end $f$;`;
  const en = `ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;`;
  for (const sql of [
    `${T} ${unlock} create view public.v with (security_invoker = true) as select public.unlock() as x; revoke all on public.v from anon, authenticated;
     DO $$ BEGIN ${en} PERFORM (TABLE public.v LIMIT 1); END $$;`,
    `${T} ${unlock} create domain public.d as int check (public.unlock() > 0);\nDO $$ BEGIN ${en} PERFORM 1::public.d; END $$;`,
    `${T} ${unlock} create domain public.d as int check (public.unlock() > 0);\nDO $$ BEGIN ${en} PERFORM 1::d; END $$;`,
    `${T}\nDO $$ BEGIN IF true THEN CREATE FUNCTION public.unlock() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN ALTER TABLE public.t DISABLE ROW LEVEL SECURITY; RETURN 1; END $f$; END IF; END $$;
     DO $$ BEGIN ${en} PERFORM public.unlock(); END $$;`,
  ]) assert.deepEqual(ids(await scanSql(sql)).filter((x) => x.startsWith('RC001')), ['RC001 public.t'], sql);
});

test('V1: built-in casts, as pg_dump writes them, do not spoil a block', async () => {
  const r = await scanSql(`${DEF()}\nDO $$ DECLARE v text := current_user; n int; BEGIN
      SELECT count(*)::integer INTO n FROM pg_default_acl d WHERE d.defaclrole = v::regrole AND d.defaclobjtype::"text" = 'f'::text;
      ${REVOKE_F}
    END $$;`);
  assert.deepEqual(ids(r), []);
});
