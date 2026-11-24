// Replays a Supabase project's migrations, in order, statement by statement,
// and produces the CURRENT state of every table, policy, function and trigger.
//
// Order matters. A REVOKE from March does not protect a function that was
// dropped and re-created in June (re-creation resets its grants). A policy
// created and later dropped protects nothing. Checkers that pattern-match
// files instead of replaying them report holes that were closed and miss holes
// that were reopened.
//
// When the replay can't be sure, it leans toward "reachable". For a security
// tool a missed hole is worse than a question.
//
// This is a static model. Inside a DO block it replays only the statements that
// are certain to run and whose text it can work out (see sql/doblock.js); the
// rest are counted in coverage.doBlocks.skipped. It does not know what was
// changed by hand in a dashboard. The live probe exists for that; `defaults:
// "clean"` in the config exists for baselines whose revoke of the default
// grants still can't be followed.

import fs from 'node:fs';
import path from 'node:path';
import { splitStatements, stripComments, readQualifiedName, readParenGroup, lineIndex, quotedEnd, blankLiterals } from './sql/statements.js';
import { normaliseArgs, signatureKey } from './sql/signature.js';
import { replayableFromDo, reopens } from './sql/doblock.js';

const PRIVS = ['select', 'insert', 'update', 'delete'];
const API_ROLES = ['anon', 'authenticated'];

/** Find the migrations directory for a project root (or accept a directory of .sql files). */
export function findMigrationsDir(root) {
  const candidates = [path.join(root, 'supabase', 'migrations'), path.join(root, 'migrations'), root];
  for (const dir of candidates) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory() && fs.readdirSync(dir).some((f) => f.endsWith('.sql'))) {
      return dir;
    }
  }
  return null;
}

/** Exposed schemas from supabase/config.toml ([api] schemas = [...]), falling back to Supabase's default. */
export function readExposedSchemas(root) {
  const fallback = ['public', 'graphql_public'];
  const tomlPath = path.join(root, 'supabase', 'config.toml');
  if (!fs.existsSync(tomlPath)) return fallback;
  let inApi = false;
  let collecting = null;
  for (const raw of fs.readFileSync(tomlPath, 'utf8').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (collecting !== null) {
      collecting += ` ${line}`;
      if (line.includes(']')) break;
      continue;
    }
    if (/^\[.*\]$/.test(line)) {
      inApi = line === '[api]';
      continue;
    }
    if (inApi) {
      const m = /^schemas\s*=\s*(\[.*)$/.exec(line);
      if (m) {
        collecting = m[1];
        if (m[1].includes(']')) break;
      }
    }
  }
  if (collecting === null) return fallback;
  const list = [...collecting.matchAll(/"([^"]+)"|'([^']+)'/g)].map((x) => (x[1] || x[2]).toLowerCase());
  return list.length ? list : fallback;
}

export function loadMigrations(dir) {
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort() // timestamp-prefixed, so this is chronological
    .map((file) => ({ file, sql: fs.readFileSync(path.join(dir, file), 'utf8') }));
}

// Split on top-level commas (not inside parentheses or quotes).
function splitTopLevel(text) {
  const parts = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      const end = quotedEnd(text, i);
      cur += text.slice(i, end);
      i = end - 1;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

// GRANT/REVOKE privilege list -> { table, column, usage }. A column list
// (`SELECT (email)`) grants access to those columns only; revoking it does NOT
// remove a table-level grant, so the two must be kept apart.
function parsePrivs(text) {
  const table = new Set();
  const column = new Set();
  let usage = false;
  for (const item of splitTopLevel(text.toLowerCase())) {
    const hasCols = item.includes('(');
    const word = item.replace(/\(.*$/s, '').trim();
    if (/^all(\s+privileges)?$/.test(word)) {
      for (const p of PRIVS) (hasCols ? column : table).add(p);
      usage = true;
      continue;
    }
    if (word === 'usage') usage = true;
    if (PRIVS.includes(word)) (hasCols ? column : table).add(word);
  }
  return { table, column, usage };
}

function rolesIn(text) {
  return {
    public: /\bpublic\b/i.test(text),
    anon: /\banon\b/i.test(text),
    authenticated: /\bauthenticated\b/i.test(text),
  };
}

// Policy roles: absent TO clause means PUBLIC (every role, including anon).
function parsePolicyRoles(toText) {
  if (!toText) return ['public'];
  return toText
    .split(',')
    .map((r) => r.trim().replace(/"/g, '').toLowerCase())
    .filter(Boolean);
}

// Reads `a, b, "c"` starting at pos. Returns [{schema, name, end}].
function readNameList(sql, pos) {
  const out = [];
  let p = pos;
  for (;;) {
    const n = readQualifiedName(sql, p);
    if (!n) break;
    out.push(n);
    let j = n.end;
    while (j < sql.length && /\s/.test(sql[j])) j++;
    if (sql[j] !== ',') break;
    p = j + 1;
  }
  return out;
}

// Reads `f(uuid), g, public.h(text)` starting at pos. Returns [{n, args}] where
// args is the raw argument text or null when no list was given.
function readFunctionList(sql, pos) {
  const out = [];
  let p = pos;
  for (;;) {
    const n = readQualifiedName(sql, p);
    if (!n) break;
    const paren = readParenGroup(sql, n.end);
    out.push({ n, args: paren ? paren.raw : null });
    let j = paren ? paren.end : n.end;
    while (j < sql.length && /\s/.test(sql[j])) j++;
    if (sql[j] !== ',') break;
    p = j + 1;
  }
  return out;
}

// Schemas the platform creates, so they exist even though no migration made them.
const PLATFORM_SCHEMAS = ['public', 'extensions', 'auth', 'storage', 'graphql', 'graphql_public', 'realtime', 'vault', 'net', 'cron', 'pgsodium', 'supabase_functions', 'supabase_migrations'];

// The schema unqualified CREATEs land in: the first schema in the path that
// exists. Returns null for DEFAULT or a path with nothing usable (both mean public).
function firstSchema(value, exists) {
  if (/^\s*default\s*;?\s*$/i.test(value)) return null;
  for (const part of value.split(',')) {
    let t = part.trim().replace(/;$/, '').trim();
    if (!t || t === "''" || t === '""') continue;
    if (/^'.*'$/.test(t)) {
      const inner = firstSchema(t.slice(1, -1), exists);
      if (inner) return inner;
      continue;
    }
    if (/^"\$user"$|^\$user$/i.test(t)) continue;
    if (/^pg_(catalog|temp)$/i.test(t)) continue;
    t = /^".*"$/.test(t) ? t.slice(1, -1) : t.toLowerCase();
    if (exists(t)) return t;
  }
  return null;
}

const SEARCH_PATH_RE = /\bSET\s+"?search_path"?\s*(?:=|TO)\s*([^\n]*)|\bSET\s+"?search_path"?\s+FROM\s+CURRENT\b/i;

/**
 * @param {{file:string, sql:string}[]} migrations
 * @param {{defaults?: string|object, exposedSchemas?: string[], migrationRoles?: string[]}} opts
 */
export function buildModel(migrations, opts = {}) {
  // `defaults` is a string for both object kinds, or { functions, tables }.
  const d0 = opts.defaults ?? 'supabase-stock';
  const defaults = typeof d0 === 'string' ? { functions: d0, tables: d0 } : { functions: 'supabase-stock', tables: 'supabase-stock', ...d0 };
  const exposedSchemas = (opts.exposedSchemas ?? ['public', 'graphql_public']).map((s) => s.toLowerCase());
  // ALTER DEFAULT PRIVILEGES only affects objects created by the roles it names.
  // Migrations run as postgres, so FOR ROLE supabase_admin changes nothing here.
  const migrationRoles = (opts.migrationRoles ?? ['postgres']).map((r) => r.toLowerCase());

  const tables = new Map();
  const functions = new Map();
  const triggers = [];
  const coverage = { files: migrations.length, statements: 0, tablesSeen: 0, functionsSeen: 0, policiesSeen: 0, doBlocks: { seen: 0, replayed: 0, skipped: 0 } };

  // Schema USAGE per role. Without USAGE a role can't reach anything inside the
  // schema. public starts usable by everyone; a schema created in a migration
  // starts closed; a schema never created here (made by the platform) is
  // assumed usable, which is the safe direction.
  const schemaUsage = new Map([['public', { public: true, anon: true, authenticated: true }]]);
  const usageOf = (s) => schemaUsage.get(s) ?? { public: true, anon: true, authenticated: true };

  // Default privileges decide what a new object is born with. Supabase's stock
  // setup grants ALL on new tables and functions in public to anon and
  // authenticated; Postgres itself grants EXECUTE on every new function to
  // PUBLIC unless that is revoked globally.
  let globalPublicExecRevoked = defaults.functions === 'clean';
  const globalFn = { anon: false, authenticated: false };
  const globalTable = { anon: new Set(), authenticated: new Set() };
  const fnDefaults = new Map(); // schema -> {publicGrant, anon, authenticated}
  const tableDefaults = new Map(); // schema -> {anon:Set, authenticated:Set}
  if (defaults.functions === 'supabase-stock') fnDefaults.set('public', { publicGrant: false, anon: true, authenticated: true });
  if (defaults.tables === 'supabase-stock') tableDefaults.set('public', { anon: new Set(PRIVS), authenticated: new Set(PRIVS) });
  const fnDefaultsFor = (s) => {
    if (!fnDefaults.has(s)) fnDefaults.set(s, { publicGrant: false, anon: false, authenticated: false });
    return fnDefaults.get(s);
  };
  const tableDefaultsFor = (s) => {
    if (!tableDefaults.has(s)) tableDefaults.set(s, { anon: new Set(), authenticated: new Set() });
    return tableDefaults.get(s);
  };
  const fnKeysForName = (schema, name) => {
    const prefix = `${schema}.${name}(`;
    return [...functions.keys()].filter((k) => k.startsWith(prefix));
  };
  const fnKeysFor = ({ n, args }) =>
    args !== null ? [signatureKey(schemaOf(n), n.name, normaliseArgs(args))] : fnKeysForName(schemaOf(n), n.name);

  // search_path tracking. SET LOCAL and set_config(..., true) last until the
  // transaction ends; a plain SET lasts for the session (one migration file).
  const knownSchemas = new Set(PLATFORM_SCHEMAS);
  const exists = (s) => knownSchemas.has(s);
  let sessionSchema = 'public';
  let localSchema = null;
  // SET ROLE / SET SESSION AUTHORIZATION: statements now run as some other
  // role, so "the migration role's" default privileges are not the ones changing.
  let roleChanged = false;
  // Set when a DO block may have changed search_path in a way that can't be
  // read. While it is set, an unqualified name in a statement that LOCKS
  // something matches nothing, so a lock aimed at "t" is not credited to
  // public.t. Statements that create or open something still resolve the usual
  // way, because a missed door is worse than a question.
  let unknownPath = false;
  let pathSentinel = false; // decided per statement
  const schemaOf = (n) => (n.schema ?? (pathSentinel ? '\u0000unknown' : (localSchema ?? sessionSchema))).toLowerCase();
  const tkey = (n) => `${schemaOf(n)}.${n.name}`;

  function addTable(n, file, line, kind) {
    const schema = schemaOf(n);
    const td = tableDefaultsFor(schema);
    const k = `${schema}.${n.name}`;
    tables.set(k, {
      key: k,
      schema,
      name: n.name,
      file,
      line,
      kind,
      rls: false,
      privs: {
        anon: new Set([...td.anon, ...globalTable.anon]),
        authenticated: new Set([...td.authenticated, ...globalTable.authenticated]),
      },
      policies: new Map(),
    });
    coverage.tablesSeen++;
  }

  // Every top-level statement, followed by whatever a DO block is certain to
  // run. The DO statement itself is yielded too; nothing below matches it.
  const everCreated = new Set();
  function* replayOrder(source) {
    for (const st of splitStatements(source)) {
      // Every function or procedure any statement creates, wherever the CREATE
      // sits: in a block that was not trusted, or in text built at run time.
      for (const m of st.sql.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+((?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*))?)/gi)) {
        const last = m[1].split('.').pop().trim();
        everCreated.add(last.startsWith('"') ? last.slice(1, -1) : last.toLowerCase());
      }
      yield st;
      let inner;
      try {
        // After SET ROLE the session role is not the migration role any more.
        const own = new Set([...functions.values()].map((f) => f.name));
        for (const name of everCreated) own.add(name);
        inner = replayableFromDo(stripComments(st.sql).trimStart(), { currentUser: roleChanged ? null : migrationRoles[0], isUserFunction: (name) => own.has(name) });
      } catch {
        inner = { statements: [], skipped: 1, followed: false, sessionChanged: true }; // never let one odd block stop the scan
      }
      if (!inner) continue;
      coverage.doBlocks.seen++;
      coverage.doBlocks.replayed += inner.statements.length;
      coverage.doBlocks.skipped += inner.skipped;
      for (const sql of inner.statements) yield { sql, index: st.index };
      // The block may have left the session on another role or search_path.
      if (inner.sessionChanged) {
        roleChanged = true;
        unknownPath = true;
      }
    }
  }

  for (const { file, sql: source } of migrations) {
    const lineAt = lineIndex(source);
    sessionSchema = 'public'; // each migration file runs in its own session
    localSchema = null;
    roleChanged = false;
    unknownPath = false;
    for (const { sql: rawStmt, index } of replayOrder(source)) {
      const head = stripComments(rawStmt).trimStart();
      if (!head) continue;
      coverage.statements++;
      const line = lineAt(index);
      const flat = blankLiterals(head); // for keyword tests that must not see string contents
      pathSentinel = unknownPath && !/^CREATE\b/i.test(head) && !reopens(head);

      // ── SET ROLE (decides whose default privileges a bare ALTER DEFAULT PRIVILEGES changes) ──
      // Checked before search_path, so one SELECT that sets both is not missed.
      if (/set_config\(\s*'(role|session_authorization)'/i.test(head)) roleChanged = true;
      const sr = /^SET\s+(?:SESSION\s+|LOCAL\s+)?(?:"?ROLE"?|SESSION\s+AUTHORIZATION)\s*(?:=|\bTO\b)?\s*([^\s;]+)/i.exec(head);
      if (sr) {
        roleChanged = !/^["']?(NONE|DEFAULT)["']?$/i.test(sr[1]);
        continue;
      }
      if (/^RESET\s+("?ROLE"?|SESSION\s+AUTHORIZATION)\b/i.test(head)) {
        roleChanged = false;
        continue;
      }

      // ── SET search_path (decides where unqualified names land) ───────────
      const sp = /^SET\s+(SESSION\s+|LOCAL\s+)?"?search_path"?\s*(?:=|TO)\s*([\s\S]*)$/i.exec(head);
      if (sp) {
        const s = firstSchema(sp[2], exists) ?? 'public';
        // SET LOCAL ends with the transaction; the unknown session path is still underneath.
        if (/^LOCAL/i.test(sp[1] ?? '')) localSchema = s;
        else {
          sessionSchema = s;
          unknownPath = false;
        }
        continue;
      }
      const sc = /set_config\(\s*'search_path'\s*,\s*'([^']*)'\s*,\s*(true|false)\s*\)/i.exec(head);
      if (/^SELECT\b/i.test(head) && sc) {
        const s = firstSchema(sc[1], exists) ?? 'public';
        if (sc[2].toLowerCase() === 'true') localSchema = s;
        else {
          sessionSchema = s;
          unknownPath = false;
        }
        continue;
      }
      if (/^RESET\s+("?search_path"?|ALL)\b/i.test(head)) {
        sessionSchema = 'public';
        localSchema = null;
        unknownPath = false;
        if (/^RESET\s+ALL\b/i.test(head)) roleChanged = false;
        continue;
      }
      if (/^(COMMIT|END|ABORT)\b/i.test(head) || (/^ROLLBACK\b/i.test(head) && !/^ROLLBACK\s+(?:WORK\s+|TRANSACTION\s+)?TO\b/i.test(head))) {
        localSchema = null;
        continue;
      }

      // ── CREATE SCHEMA ────────────────────────────────────────────────────
      const cs = /^CREATE\s+SCHEMA\s+(IF\s+NOT\s+EXISTS\s+)?/i.exec(head);
      if (cs) {
        const n = readQualifiedName(head, cs[0].length);
        if (!n) continue;
        const name = n.name.toLowerCase();
        // A plain CREATE SCHEMA proves the schema is new, so it starts closed.
        // IF NOT EXISTS proves nothing: it may already exist (made in the
        // dashboard, with USAGE granted there), so leave it as it was.
        if (!cs[1] && !knownSchemas.has(name)) schemaUsage.set(name, { public: false, anon: false, authenticated: false });
        knownSchemas.add(name);
        continue;
      }

      // ── CREATE TABLE (including CREATE TABLE AS) ──────────────────────────
      const ct = /^CREATE\s+(?:(GLOBAL|LOCAL)\s+)?(?:(TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\s+(IF\s+NOT\s+EXISTS\s+)?/i.exec(head);
      if (ct) {
        if (ct[2] && /^TEMP/i.test(ct[2])) continue;
        const n = readQualifiedName(head, ct[0].length);
        if (!n) continue;
        if (ct[3] && tables.has(tkey(n))) continue;
        // `AS` right after the name (or after a bare column-name list) is CREATE TABLE AS.
        const isCtas = /^\s*(?:\([^()]*\)\s*)?(?:WITH\s*\([^()]*\)\s*)?(?:TABLESPACE\s+\S+\s*)?AS\b/i.test(head.slice(n.end));
        addTable(n, file, line, isCtas ? 'ctas' : 'table');
        continue;
      }

      // ── SELECT ... INTO new_table (another way to copy a table) ──────────
      if (/^(?:WITH\b|SELECT\b)/i.test(head)) {
        // INSERT INTO / MERGE INTO inside a WITH are writes, not new tables.
        const into = /(?<!\b(?:INSERT|MERGE)\s+)\bINTO\s+(?:(TEMP|TEMPORARY)\s+|UNLOGGED\s+)?(?:TABLE\s+)?/i.exec(flat);
        if (into && !into[1]) {
          const n = readQualifiedName(head, into.index + into[0].length);
          if (n && !/^(strict)$/i.test(n.name)) addTable(n, file, line, 'ctas');
        }
        continue;
      }

      // ── DROP TABLE ───────────────────────────────────────────────────────
      const dt = /^DROP\s+TABLE\s+(IF\s+EXISTS\s+)?/i.exec(head);
      if (dt) {
        for (const n of readNameList(head, dt[0].length)) tables.delete(tkey(n));
        continue;
      }

      // ── ALTER TABLE ... RLS / RENAME / SET SCHEMA ────────────────────────
      const at = /^ALTER\s+TABLE\s+(IF\s+EXISTS\s+)?(ONLY\s+)?/i.exec(head);
      if (at) {
        const n = readQualifiedName(head, at[0].length);
        if (!n) continue;
        const k = tkey(n);
        const t = tables.get(k);
        if (!t) continue;
        const rest = head.slice(n.end);
        const restFlat = flat.slice(n.end);
        // Multiple actions can be comma-separated; the last word on RLS wins.
        const rlsActions = [...restFlat.matchAll(/\b(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY\b/gi)];
        if (rlsActions.length) t.rls = rlsActions[rlsActions.length - 1][1].toUpperCase() === 'ENABLE';
        const rn = /^\s*RENAME\s+TO\s+/i.exec(rest);
        if (rn) {
          const to = readQualifiedName(rest, rn[0].length);
          if (to) {
            tables.delete(k);
            t.name = to.name;
            t.key = `${t.schema}.${to.name}`;
            tables.set(t.key, t);
          }
        }
        const ss = /^\s*SET\s+SCHEMA\s+/i.exec(rest);
        if (ss) {
          const to = readQualifiedName(rest, ss[0].length);
          if (to) {
            tables.delete(k);
            t.schema = to.name.toLowerCase();
            t.key = `${t.schema}.${t.name}`;
            tables.set(t.key, t);
          }
        }
        continue;
      }

      // ── CREATE / DROP / ALTER POLICY ─────────────────────────────────────
      const policyTarget = (re) => {
        const m = re.exec(head);
        if (!m) return null;
        const pn = readQualifiedName(head, m[0].length);
        if (!pn) return null;
        const on = /^\s*ON\s+/i.exec(head.slice(pn.end));
        if (!on) return null;
        const tn = readQualifiedName(head, pn.end + on[0].length);
        if (!tn) return null;
        return { pn, tn, table: tables.get(tkey(tn)) };
      };
      if (/^CREATE\s+POLICY\s+/i.test(head)) {
        const pt = policyTarget(/^CREATE\s+POLICY\s+/i);
        coverage.policiesSeen++;
        if (pt?.table) pt.table.policies.set(pt.pn.name, { name: pt.pn.name, file, line, ...parsePolicyClauses(head.slice(pt.tn.end)) });
        continue;
      }
      if (/^DROP\s+POLICY\s+/i.test(head)) {
        const pt = policyTarget(/^DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?/i);
        pt?.table?.policies.delete(pt.pn.name);
        continue;
      }
      if (/^ALTER\s+POLICY\s+/i.test(head)) {
        const pt = policyTarget(/^ALTER\s+POLICY\s+/i);
        const p = pt?.table?.policies.get(pt.pn.name);
        if (!p) continue;
        const rest = head.slice(pt.tn.end);
        const rn = /^\s*RENAME\s+TO\s+/i.exec(rest);
        if (rn) {
          const to = readQualifiedName(rest, rn[0].length);
          if (to) {
            pt.table.policies.delete(pt.pn.name);
            p.name = to.name;
            pt.table.policies.set(to.name, p);
          }
          continue;
        }
        const upd = parsePolicyClauses(rest);
        if (upd.hasTo) p.roles = upd.roles;
        if (upd.using !== null) p.using = upd.using;
        if (upd.check !== null) p.check = upd.check;
        continue;
      }

      // ── CREATE [OR REPLACE] FUNCTION ─────────────────────────────────────
      const cf = /^CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+/i.exec(head);
      if (cf) {
        const isReplace = Boolean(cf[1]);
        const n = readQualifiedName(head, cf[0].length);
        if (!n) continue;
        const paren = readParenGroup(head, n.end);
        if (!paren) continue;
        const schema = schemaOf(n);
        const argsig = normaliseArgs(paren.raw);
        const k = signatureKey(schema, n.name, argsig);
        const { header, body, trailer } = splitFunctionBody(head.slice(paren.end));
        const attrs = `${header}\n${trailer}`;
        const spm = SEARCH_PATH_RE.exec(attrs);
        const existed = functions.has(k);
        const prev = functions.get(k);
        const d = fnDefaultsFor(schema);
        functions.set(k, {
          key: k,
          schema,
          name: n.name,
          argsig,
          file,
          line,
          body,
          isSecurityDefiner: /\bSECURITY\s+DEFINER\b/i.test(attrs),
          isTrigger: /\bRETURNS\s+"?trigger"?(?!\w)/i.test(header),
          searchPath: spm ? (spm[1] ?? 'FROM CURRENT').trim().replace(/;$/, '') : null,
          // CREATE OR REPLACE on an existing function keeps its grants;
          // a fresh CREATE takes whatever the defaults say right now.
          publicExec: isReplace && existed ? prev.publicExec : !globalPublicExecRevoked || d.publicGrant,
          anonExec: isReplace && existed ? prev.anonExec : d.anon || globalFn.anon,
          authExec: isReplace && existed ? prev.authExec : d.authenticated || globalFn.authenticated,
        });
        coverage.functionsSeen++;
        continue;
      }

      // ── ALTER FUNCTION ───────────────────────────────────────────────────
      const af = /^ALTER\s+FUNCTION\s+/i.exec(head);
      if (af) {
        const [ref] = readFunctionList(head, af[0].length);
        if (!ref) continue;
        const restStart = ref.args !== null ? readParenGroup(head, ref.n.end).end : ref.n.end;
        const rest = head.slice(restStart);
        for (const k of fnKeysFor(ref)) {
          const f = functions.get(k);
          if (!f) continue;
          if (/\bSECURITY\s+DEFINER\b/i.test(rest)) f.isSecurityDefiner = true;
          if (/\bSECURITY\s+INVOKER\b/i.test(rest)) f.isSecurityDefiner = false;
          const spm = SEARCH_PATH_RE.exec(rest);
          if (spm) f.searchPath = (spm[1] ?? 'FROM CURRENT').trim().replace(/;$/, '');
          if (/\bRESET\s+("?search_path"?|ALL)\b/i.test(rest)) f.searchPath = null;
          const oldName = `${f.schema}.${f.name}`;
          const rn = /^\s*RENAME\s+TO\s+/i.exec(rest);
          const ss = /^\s*SET\s+SCHEMA\s+/i.exec(rest);
          if (rn || ss) {
            const to = readQualifiedName(rest, (rn ?? ss)[0].length);
            if (!to) continue;
            functions.delete(k);
            if (rn) f.name = to.name;
            else f.schema = to.name.toLowerCase();
            f.key = signatureKey(f.schema, f.name, f.argsig);
            functions.set(f.key, f);
            for (const tr of triggers) if (tr.fn === oldName) tr.fn = `${f.schema}.${f.name}`;
          }
        }
        continue;
      }

      // ── DROP FUNCTION ────────────────────────────────────────────────────
      const df = /^DROP\s+FUNCTION\s+(IF\s+EXISTS\s+)?/i.exec(head);
      if (df) {
        for (const ref of readFunctionList(head, df[0].length)) for (const k of fnKeysFor(ref)) functions.delete(k);
        continue;
      }

      // ── CREATE TRIGGER ───────────────────────────────────────────────────
      const tr = /^CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+/i.exec(head);
      if (tr) {
        const on = /\bON\s+/i.exec(head.slice(tr[0].length));
        const exec = /\bEXECUTE\s+(?:FUNCTION|PROCEDURE)\s+/i.exec(head);
        if (!on || !exec) continue;
        const tn = readQualifiedName(head, tr[0].length + on.index + on[0].length);
        const fn = readQualifiedName(head, exec.index + exec[0].length);
        if (tn && fn) triggers.push({ table: tkey(tn), fn: `${schemaOf(fn)}.${fn.name}`, file, line });
        continue;
      }

      // ── ALTER DEFAULT PRIVILEGES ─────────────────────────────────────────
      if (/^ALTER\s+DEFAULT\s+PRIVILEGES\b/i.test(head)) {
        const forRole = /\bFOR\s+(?:ROLE|USER)\s+([\s\S]*?)\s+(?=IN\s+SCHEMA\b|GRANT\b|REVOKE\b)/i.exec(head);
        if (forRole) {
          const roles = forRole[1].split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase());
          if (!roles.some((r) => migrationRoles.includes(r))) continue;
        }
        if (/\bREVOKE\s+GRANT\s+OPTION\s+FOR\b/i.test(head)) continue;
        const action = /\b(GRANT|REVOKE)\s+([\s\S]*?)\bON\s+(FUNCTIONS|ROUTINES|TABLES)\b/i.exec(head);
        if (!action) continue;
        const isRevoke = action[1].toUpperCase() === 'REVOKE';
        const onTables = action[3].toUpperCase() === 'TABLES';
        // Without FOR ROLE it changes the CURRENT role's defaults. After SET ROLE
        // that is not the role creating objects, so a revoke protects nothing here.
        if (!forRole && roleChanged && isRevoke) continue;
        const roleText = isRevoke ? (/\bFROM\s+([\s\S]*)$/i.exec(head)?.[1] ?? '') : (/\bTO\s+([\s\S]*)$/i.exec(head)?.[1] ?? '');
        const roles = rolesIn(roleText);
        const privs = parsePrivs(action[2]).table;
        const inSchema = /\bIN\s+SCHEMA\s+/i.exec(head);
        const applyTables = (d) => {
          for (const role of API_ROLES) {
            // GRANT TO PUBLIC reaches every role; REVOKE FROM PUBLIC leaves a role's own grant alone.
            if (isRevoke ? !roles[role] : !roles[role] && !roles.public) continue;
            for (const p of privs) isRevoke ? d[role].delete(p) : d[role].add(p);
          }
        };
        const execPriv = /\b(EXECUTE|ALL)\b/i.test(action[2]);
        if (!inSchema) {
          if (onTables) applyTables(globalTable);
          else if (execPriv) {
            // Only the global form reaches Postgres's built-in EXECUTE-to-PUBLIC.
            if (roles.public) globalPublicExecRevoked = isRevoke;
            if (roles.anon) globalFn.anon = !isRevoke;
            if (roles.authenticated) globalFn.authenticated = !isRevoke;
          }
          continue;
        }
        for (const s of readNameList(head, inSchema.index + inSchema[0].length)) {
          const schema = s.name.toLowerCase();
          if (onTables) applyTables(tableDefaultsFor(schema));
          else if (execPriv) {
            const d = fnDefaultsFor(schema);
            if (roles.public) d.publicGrant = !isRevoke;
            if (roles.anon) d.anon = !isRevoke;
            if (roles.authenticated) d.authenticated = !isRevoke;
          }
        }
        continue;
      }

      // ── GRANT / REVOKE on concrete objects ───────────────────────────────
      const acl = /^(REVOKE|GRANT)\s+/i.exec(head);
      if (!acl) continue;
      // Revoking the grant option leaves the privilege itself in place.
      if (/^REVOKE\s+GRANT\s+OPTION\s+FOR\b/i.test(head)) continue;
      const isRevoke = acl[1].toUpperCase() === 'REVOKE';
      const roleText = isRevoke ? (/\bFROM\s+([\s\S]*)$/i.exec(head)?.[1] ?? '') : (/\bTO\s+([\s\S]*)$/i.exec(head)?.[1] ?? '');
      const roles = rolesIn(roleText);
      if (!roles.public && !roles.anon && !roles.authenticated) continue;
      const onAt = /\bON\b/i.exec(flat);
      const privs = parsePrivs(head.slice(acl[0].length, onAt ? onAt.index : acl[0].length));

      const onSchema = /\bON\s+SCHEMA\s+/i.exec(head);
      if (onSchema) {
        // Only USAGE decides whether a role can reach objects in a schema.
        // REVOKE CREATE (the standard hardening line) changes nothing here.
        if (!privs.usage) continue;
        for (const s of readNameList(head, onSchema.index + onSchema[0].length)) {
          const name = s.name.toLowerCase();
          const u = { ...usageOf(name) };
          for (const r of ['public', ...API_ROLES]) if (roles[r]) u[r] = !isRevoke;
          schemaUsage.set(name, u);
        }
        continue;
      }

      const applyFn = (f) => {
        if (roles.public) f.publicExec = !isRevoke;
        if (roles.anon) f.anonExec = !isRevoke;
        if (roles.authenticated) f.authExec = !isRevoke;
      };
      const allFns = /\bON\s+ALL\s+(FUNCTIONS|ROUTINES)\s+IN\s+SCHEMA\s+/i.exec(head);
      if (allFns) {
        const schemas = new Set(readNameList(head, allFns.index + allFns[0].length).map((s) => s.name.toLowerCase()));
        for (const f of functions.values()) if (schemas.has(f.schema)) applyFn(f);
        continue;
      }
      const onFn = /\bON\s+(FUNCTION|ROUTINE|PROCEDURE)\s+/i.exec(head);
      if (onFn) {
        for (const ref of readFunctionList(head, onFn.index + onFn[0].length)) {
          for (const k of fnKeysFor(ref)) {
            const f = functions.get(k);
            if (f) applyFn(f);
          }
        }
        continue;
      }

      // Table privileges: GRANT/REVOKE <privs> ON [TABLE] a, b | ON ALL TABLES IN SCHEMA s, t
      if (/\bON\s+(?:ALL\s+)?(SEQUENCES?|TYPE|DOMAIN|LANGUAGE|DATABASE|FOREIGN|LARGE|TABLESPACE|PARAMETER)\b/i.test(head)) continue;
      // A REVOKE of a column list doesn't remove a table-level grant; a GRANT of one does give access.
      const effective = isRevoke ? privs.table : new Set([...privs.table, ...privs.column]);
      if (effective.size === 0) continue;
      const applyTable = (t) => {
        for (const role of API_ROLES) {
          if (isRevoke ? !roles[role] : !roles[role] && !roles.public) continue;
          for (const p of effective) isRevoke ? t.privs[role].delete(p) : t.privs[role].add(p);
        }
      };
      const allTables = /\bON\s+ALL\s+TABLES\s+IN\s+SCHEMA\s+/i.exec(head);
      if (allTables) {
        const schemas = new Set(readNameList(head, allTables.index + allTables[0].length).map((s) => s.name.toLowerCase()));
        for (const t of tables.values()) if (schemas.has(t.schema)) applyTable(t);
        continue;
      }
      const onTable = /\bON\s+(?:TABLE\s+)?/i.exec(head);
      if (onTable) {
        for (const n of readNameList(head, onTable.index + onTable[0].length)) {
          const t = tables.get(tkey(n));
          if (t) applyTable(t);
        }
      }
    }
  }

  return { tables, functions, triggers, schemaUsage, exposedSchemas, defaults, coverage };
}

// Splits what follows a function's argument list into the header (RETURNS,
// LANGUAGE, SECURITY ...), the body, and the trailer (attributes may follow
// the body too). Handles $tag$ bodies, 'single-quoted' bodies, and SQL-standard
// bodies (RETURN ... / BEGIN ATOMIC ... END) that have no quotes at all.
function splitFunctionBody(after) {
  const m = /\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$|\bAS\s+(?=[Ee]?')/i.exec(after);
  if (!m) return { header: after, body: after, trailer: '' };
  if (m[0].startsWith('$')) {
    const tag = m[0];
    const bStart = m.index + tag.length;
    const bEnd = after.indexOf(tag, bStart);
    return {
      header: after.slice(0, m.index),
      body: after.slice(bStart, bEnd === -1 ? after.length : bEnd),
      trailer: bEnd === -1 ? '' : after.slice(bEnd + tag.length),
    };
  }
  const q = after.indexOf("'", m.index + m[0].length);
  const end = quotedEnd(after, q);
  return {
    header: after.slice(0, m.index),
    body: after.slice(q + 1, end - 1).replace(/''/g, "'"),
    trailer: after.slice(end),
  };
}

// Parses the tail of CREATE/ALTER POLICY after the table name.
function parsePolicyClauses(rest) {
  // AS / FOR / TO all come before USING and WITH CHECK, so only look there:
  // the word "to" inside a USING expression must not be read as a role list.
  const exprAt = rest.search(/\bUSING\s*\(|\bWITH\s+CHECK\s*\(/i);
  const pre = exprAt === -1 ? rest : rest.slice(0, exprAt);
  const permissive = !/\bAS\s+RESTRICTIVE\b/i.test(pre);
  const cmd = (/\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i.exec(pre)?.[1] ?? 'ALL').toUpperCase();
  const to = /\bTO\s+([\s\S]*)$/i.exec(pre);
  const roles = parsePolicyRoles(to ? to[1] : null);
  let using = null;
  let check = null;
  const u = /\bUSING\s*(?=\()/i.exec(rest);
  if (u) using = readParenGroup(rest, u.index + u[0].length)?.raw.trim() ?? null;
  const c = /\bWITH\s+CHECK\s*(?=\()/i.exec(rest);
  if (c) check = readParenGroup(rest, c.index + c[0].length)?.raw.trim() ?? null;
  return { permissive, cmd, roles, hasTo: Boolean(to), using, check };
}

function usage(model, schema, role) {
  const u = model.schemaUsage.get(schema) ?? { public: true, anon: true, authenticated: true };
  return u.public || u[role];
}

/** A table is reachable through the Data API when its schema is exposed and usable, and the role holds a privilege. */
export function tableExposure(model, t) {
  const exposed = model.exposedSchemas.includes(t.schema);
  return {
    exposed,
    anon: exposed && t.privs.anon.size > 0 && usage(model, t.schema, 'anon'),
    authenticated: exposed && t.privs.authenticated.size > 0 && usage(model, t.schema, 'authenticated'),
  };
}

export function functionReach(model, f) {
  const anonUsage = usage(model, f.schema, 'anon');
  const authUsage = usage(model, f.schema, 'authenticated');
  return {
    public: f.publicExec && anonUsage,
    anon: (f.publicExec || f.anonExec) && anonUsage,
    authenticated: (f.publicExec || f.authExec) && authUsage,
  };
}
