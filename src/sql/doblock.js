// Reads a `DO $$ ... $$` block and returns the statements inside it that are
// CERTAIN to run, so the replay can apply them like any other statement.
//
// Why this exists: a baseline that closes Supabase's default grants almost
// always does it inside a DO block, because the role has to be read from the
// session:
//
//     DO $$ BEGIN
//       EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
//                      'REVOKE ALL ON FUNCTIONS FROM anon', current_user);
//     END $$;
//
// A replay that skips the block believes every later function is born open to
// anon, and reports a wide-open project that is in fact locked.
//
// The rule is strict, because guessing here hides real holes:
//
//   * A block is replayed in full only when EVERY statement in it is understood
//     and certain to run: all of it sits at the top level of the outermost
//     BEGIN ... END (not inside IF, CASE, a loop, a nested block or an
//     exception handler), nothing leaves the block early, nothing changes the
//     session (search_path, role, transaction), there is no EXCEPTION section,
//     and every EXECUTE has text that can be worked out from string literals,
//     format(), quote_ident(), quote_literal(), current_user and variables
//     whose value is itself known. Every statement must also be one of a short
//     list of kinds (DDL, a query, an assignment, RAISE, ASSERT, NULL): a block
//     that writes data, calls a procedure, runs another DO, or calls a function
//     the migrations themselves define could undo its own lock out of sight.
//   * In any other block, only statements that OPEN something are replayed
//     (GRANT, DISABLE ROW LEVEL SECURITY, ...), certain or not. A lock that
//     might not have been applied, or might have been undone two lines later,
//     is never counted; a door that might have been opened always is.
//   * A block whose structure can't be followed contributes nothing.
//
// Everything left out is counted, so the report can say what it did not see.

import { splitStatements, stripComments, blankLiterals, quotedEnd, dollarTagAt, readParenGroup, readQualifiedName } from './statements.js';

// Statements written directly in the block that change what the model tracks.
// Everything else (SELECT ... INTO a variable, PERFORM, RAISE, ASSERT) is
// PL/pgSQL plumbing. `SELECT x INTO v` in particular assigns a variable here;
// replaying it as SQL would invent a table called "v".
const DDL = /^(CREATE|ALTER|DROP|GRANT|REVOKE|COMMENT)\b/i;

const SESSION_ROLE = /^(current_user|session_user|current_role|user)$/i;

// A string literal at `i`: $tag$...$tag$, '...' or E'...'. Returns
// { value, end, kind, exact }. `exact` is false when an E-string uses an escape
// this reader doesn't decode (\x41, \101, A), so the value can't be trusted.
function readLiteral(sql, i) {
  const tag = dollarTagAt(sql, i);
  if (tag) {
    const end = sql.indexOf(tag, i + tag.length);
    if (end === -1) return null;
    return { value: sql.slice(i + tag.length, end), end: end + tag.length, kind: 'dollar', exact: true };
  }
  if (sql[i] === "'") {
    const end = quotedEnd(sql, i);
    return { value: sql.slice(i + 1, end - 1).replace(/''/g, "'"), end, kind: 'quote', exact: true };
  }
  if ((sql[i] === 'E' || sql[i] === 'e') && sql[i + 1] === "'") {
    const end = quotedEnd(sql, i + 1);
    const raw = sql.slice(i + 2, end - 1);
    const value = raw.replace(/''/g, "'").replace(/\\(.)/gs, (_, c) => ({ n: '\n', t: '\t', r: '\r' })[c] ?? c);
    return { value, end, kind: 'quote', exact: !/\\[^\\'"ntr]/.test(raw) };
  }
  return null;
}

// Splits on a separator at the top level: outside quotes, dollar strings and parentheses.
function splitTop(text, sep) {
  const parts = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      i = quotedEnd(text, i);
      continue;
    }
    const tag = dollarTagAt(text, i);
    if (tag) {
      const end = text.indexOf(tag, i + tag.length);
      i = end === -1 ? text.length : end + tag.length;
      continue;
    }
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (depth === 0 && text.startsWith(sep, i)) {
      parts.push(text.slice(start, i));
      i += sep.length;
      start = i;
      continue;
    }
    i++;
  }
  parts.push(text.slice(start));
  return parts;
}

const quoteIdent = (v) => `"${v.replace(/"/g, '""')}"`;
const quoteLiteral = (v) => `'${v.replace(/'/g, "''")}'`;

// Nesting deeper than this is not something a person wrote; refuse rather than recurse.
const MAX_DEPTH = 40;

// Works out the text a PL/pgSQL string expression evaluates to, or null when
// any part of it depends on something this reader can't know.
function resolveString(expr, ctx, depth = 0) {
  if (depth > MAX_DEPTH) return null;
  const pieces = splitTop(expr, '||');
  if (pieces.length > 1) {
    let out = '';
    for (const p of pieces) {
      const v = resolveString(p, ctx, depth + 1);
      if (v === null) return null;
      out += v;
    }
    return out;
  }

  let t = expr.trim();
  if (!t) return null;
  // A cast to a text type changes nothing about the value.
  t = t.replace(/\s*::\s*(text|name|varchar|character varying)\s*$/i, '').trim();

  // One or more adjacent literals: 'a' 'b' is a single string in SQL, but only
  // for quoted literals, and only across a line break.
  const first = readLiteral(t, 0);
  if (first) {
    if (!first.exact) return null;
    let out = first.value;
    let i = first.end;
    for (;;) {
      const gap = /^\s*/.exec(t.slice(i))[0];
      if (i + gap.length >= t.length) return out;
      const next = readLiteral(t, i + gap.length);
      if (!next || !next.exact || !gap.includes('\n') || first.kind !== 'quote' || next.kind !== 'quote') return null;
      out += next.value;
      i = next.end;
    }
  }

  if (t.startsWith('(')) {
    const g = readParenGroup(t, 0);
    return g && g.end === t.length ? resolveString(g.raw, ctx, depth + 1) : null;
  }

  const call = /^(format|quote_ident|quote_literal)\s*(?=\()/i.exec(t);
  if (call) {
    const g = readParenGroup(t, call[0].length);
    if (!g || g.end !== t.length) return null;
    const fn = call[1].toLowerCase();
    if (fn === 'format') return resolveFormat(g.raw, ctx, depth + 1);
    const inner = resolveString(g.raw, ctx, depth + 1);
    if (inner === null) return null;
    return fn === 'quote_ident' ? quoteIdent(inner) : quoteLiteral(inner);
  }

  // null when a SET ROLE is in effect and the session role is no longer known.
  if (SESSION_ROLE.test(t)) return ctx.currentUser ?? null;
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(t)) return ctx.vars.get(t.toLowerCase()) ?? null;
  return null;
}

// format('... %I ... %L ... %s', a, b, c) with every argument known.
function resolveFormat(rawArgs, ctx, depth) {
  const args = splitTop(rawArgs, ',');
  const fmt = resolveString(args[0], ctx, depth);
  if (fmt === null) return null;
  let next = 1;
  let failed = false;
  const out = fmt.replace(/%(?:(\d+)\$)?([^sIL%]*)([sIL%]?)/g, (whole, pos, flags, type) => {
    if (type === '%' && !pos && !flags) return '%';
    // Width and flags are legal but rare; not worth guessing at.
    if (!type || type === '%' || flags) {
      failed = true;
      return whole;
    }
    const idx = pos ? Number(pos) : next;
    next = idx + 1;
    const v = idx >= 1 && idx < args.length ? resolveString(args[idx], ctx, depth) : null;
    if (v === null) {
      failed = true;
      return whole;
    }
    return type === 'I' ? quoteIdent(v) : type === 'L' ? quoteLiteral(v) : v;
  });
  return failed ? null : out;
}

// Pulls the body and language out of `DO [LANGUAGE x] <string> [LANGUAGE x]`.
function parseDo(stmt) {
  const m = /^DO\b/i.exec(stmt);
  if (!m) return null;
  let i = m[0].length;
  let lang = 'plpgsql';
  let body = null;
  for (;;) {
    while (i < stmt.length && /\s/.test(stmt[i])) i++;
    if (i >= stmt.length) break;
    const l = /^LANGUAGE\s+(?:'([^']+)'|"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))/i.exec(stmt.slice(i));
    if (l) {
      lang = (l[1] ?? l[2] ?? l[3]).toLowerCase();
      i += l[0].length;
      continue;
    }
    const lit = readLiteral(stmt, i);
    if (!lit || body !== null) return null;
    body = lit.value;
    i = lit.end;
  }
  if (body === null || lang !== 'plpgsql') return null;
  return body;
}

// The most common way a project locks a list of functions:
//
//     FOREACH fn IN ARRAY ARRAY['f(uuid)', 'g()'] LOOP
//       EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM public, anon', fn);
//     END LOOP;
//
// A loop over a written-out list of string literals runs its body once per
// element, in order, with nothing to decide. That is exactly the same as
// assigning the variable and writing the body out each time, so the loop is
// rewritten that way and the usual rules then judge each statement (a loop
// inside an IF stays uncertain, an unknown EXECUTE still stops the replay).
// Only the plainest shape is rewritten: every element a plain '...' literal,
// and a body with no nested control flow, early exit or block of its own.
// Anything else is left as a loop, which the reader treats as uncertain.
const LOOP_BODY_CONTROL = /\b(LOOP|IF|CASE|FOR|FOREACH|WHILE|EXIT|CONTINUE|RETURN|BEGIN|DECLARE|EXCEPTION|END)\b/i;
export function unrollForeach(body) {
  const flat = blankQuoted(blankLiterals(body));
  const head = /\bFOREACH\s+([A-Za-z_][A-Za-z0-9_]*)\s+IN\s+ARRAY\s+ARRAY\s*\[/gi;
  let out = '';
  let from = 0;
  let m;
  while ((m = head.exec(flat))) {
    const close = flat.indexOf(']', head.lastIndex);
    if (close === -1) break;
    // The elements: plain literals separated by commas, nothing else.
    const values = [];
    let i = head.lastIndex;
    let ok = true;
    for (;;) {
      while (i < close && /\s/.test(body[i])) i++;
      if (body[i] !== "'") { ok = false; break; }
      const end = quotedEnd(body, i);
      if (end > close) { ok = false; break; }
      values.push(body.slice(i, end));
      i = end;
      while (i < close && /\s/.test(body[i])) i++;
      if (i === close) break;
      if (body[i] !== ',') { ok = false; break; }
      i++;
    }
    const loop = /^\s*LOOP\b/i.exec(flat.slice(close + 1));
    if (!ok || !values.length || !loop) continue;
    const bodyStart = close + 1 + loop[0].length;
    const endLoop = /\bEND\s+LOOP\s*;/i.exec(flat.slice(bodyStart));
    if (!endLoop) continue;
    const inner = body.slice(bodyStart, bodyStart + endLoop.index);
    if (LOOP_BODY_CONTROL.test(flat.slice(bodyStart, bodyStart + endLoop.index))) continue;
    const v = m[1];
    out += body.slice(from, m.index) + values.map((lit) => `${v} := ${lit};\n${inner}\n`).join('');
    from = bodyStart + endLoop.index + endLoop[0].length;
    head.lastIndex = from;
  }
  return out + body.slice(from);
}

// Where the dynamic command ends: EXECUTE <command> [INTO ...] [USING ...].
function commandText(rest) {
  const flat = blankLiterals(rest);
  let depth = 0;
  for (let i = 0; i < flat.length; i++) {
    const ch = flat[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (depth === 0 && /^(INTO|USING)\b/i.test(flat.slice(i, i + 6)) && (i === 0 || !/[A-Za-z0-9_$]/.test(flat[i - 1]))) {
      return rest.slice(0, i);
    }
  }
  return rest;
}

// SET / RESET of the settings that change what later statements mean or which
// role they run as. Once one appears, at any depth, nothing after it in the
// block is certain, and the caller is told the session is not what it assumed.
const SESSION_CHANGE = /^(SET|RESET)\s+(SESSION\s+|LOCAL\s+)?("?search_path"?|"?role"?|SESSION\s+AUTHORIZATION|ALL)\b/i;
// The same, spotted anywhere inside text that could not be resolved or followed.
const SESSION_WORDS = /\b(SET|RESET)\s+(SESSION\s+|LOCAL\s+)?("?search_path"?|"?role"?|SESSION\s+AUTHORIZATION|ALL)\b|\bset_config\b|\bpg_settings\b/i;
const SESSION_SETTINGS = new Set(['search_path', 'role', 'session_authorization']);

// set_config('search_path' | 'role' | ..., ...) or a write to pg_settings,
// anywhere in the text. set_config of some other setting is harmless; one whose
// setting name is not a plain literal is assumed to be the dangerous kind.
function changesSession(raw, flat) {
  if (/\bpg_settings\b/i.test(flat)) return true;
  for (const m of raw.matchAll(/\bset_config"?\s*\(\s*(?:[Ee]?'([^']*)'(?!'))?/gi)) {
    if (m[1] === undefined || SESSION_SETTINGS.has(m[1].trim().toLowerCase())) return true;
  }
  return false;
}

// Every name that is called like a function: foo(...) or "Foo"(...).
function callsIn(flat, into) {
  for (const m of flat.matchAll(/(?:"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_$]*))\s*\(/g)) {
    into.add(m[1] !== undefined ? m[1].replace(/""/g, '"') : m[2].toLowerCase());
  }
}

// System catalogs a block may read without running anybody's code. Any other
// relation could be a view, and a view can call a function that undoes the
// block's own lock.
const CATALOGS = new Set(`pg_aggregate pg_am pg_attrdef pg_attribute pg_auth_members pg_authid pg_available_extensions
  pg_cast pg_class pg_collation pg_constraint pg_database pg_default_acl pg_depend pg_description pg_enum
  pg_event_trigger pg_extension pg_foreign_table pg_index pg_indexes pg_inherits pg_init_privs pg_language pg_locks
  pg_matviews pg_namespace pg_opclass pg_operator pg_policies pg_policy pg_proc pg_publication pg_publication_tables
  pg_rewrite pg_roles pg_sequence pg_sequences pg_shdepend pg_stat_activity pg_tables pg_tablespace pg_trigger pg_type
  pg_user pg_views`.split(/\s+/));

// True when a query in `kw` (literals and quoted names already blanked) reads
// from anything other than a system catalog or a function call.
function readsOwnRelations(kw) {
  // `TABLE name` is shorthand for SELECT * FROM name.
  const re = /\b(?:FROM|JOIN|TABLE)\b\s*((?:(?:ONLY|LATERAL)\s+)*)(["A-Za-z_][A-Za-z0-9_$."]*)?(\s*\()?/gi;
  for (const m of kw.matchAll(re)) {
    const name = m[2];
    if (!name) continue; // a subquery, a literal, a number: extract(epoch FROM '...'), IS DISTINCT FROM 1
    const lower = name.toLowerCase();
    if (!m[3] && !/^(pg_catalog|information_schema)\.[a-z_][a-z0-9_$]*$/.test(lower) && !CATALOGS.has(lower)) return true;
    // `FROM a, b`: the second relation hides behind a comma. Don't guess.
    let span = kw.slice(m.index + m[0].length - (m[3] ? m[3].length : 0));
    span = span.slice(0, span.search(/\b(WHERE|GROUP|ORDER|HAVING|LIMIT|OFFSET|UNION|INTERSECT|EXCEPT|WINDOW|FETCH|FOR|RETURNING|INTO|ON|USING|LOOP|THEN|JOIN|FROM)\b|;|$/i));
    for (let prev = null; prev !== span; ) {
      prev = span;
      span = span.replace(/\([^()]*\)/g, '');
    }
    if (span.includes(',') || span.includes(')') === false && span.includes('(')) return true;
  }
  return false;
}
// A cast to a type the project defined can run its code too (a domain's CHECK).
const BUILTIN_TYPES = new Set(`text name varchar char character bpchar citext int integer int2 int4 int8 smallint bigint
  numeric decimal real float4 float8 double boolean bool uuid json jsonb bytea date time timetz timestamp timestamptz
  interval oid regclass regrole regproc regprocedure regnamespace regtype regoper aclitem inet cidr xml`.split(/\s+/));
function castsToOwnType(flat) {
  for (const m of flat.matchAll(/::\s*((?:"[^"]*"|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:"[^"]*"|[A-Za-z_][A-Za-z0-9_$]*))?)/g)) {
    const parts = m[1].split('.').map((x) => x.trim().replace(/"/g, '').toLowerCase());
    if (parts.length === 2 && parts[0] !== 'pg_catalog') return true;
    if (!BUILTIN_TYPES.has(parts[parts.length - 1])) return true;
  }
  return false;
}
const blankQuoted = (flat) => flat.replace(/"(?:[^"]|"")*"/g, (q) => `"${'_'.repeat(q.length - 2)}"`);

// DDL whose parentheses name things rather than run them: f(uuid) in a GRANT,
// the expression of a policy, the function a trigger will call later.
const NAMES_NOT_CALLS = /^(GRANT|REVOKE|DROP|COMMENT)\b|^(CREATE(\s+OR\s+REPLACE)?|ALTER)\s+(FUNCTION|PROCEDURE|POLICY|(CONSTRAINT\s+)?TRIGGER)\b/i;
// Statements that do nothing the model tracks.
// (EXIT / CONTINUE that reach this point only leave a loop; SET of a setting
// that matters was caught earlier.)
const PLAIN = /^(NULL|RAISE|ASSERT|PERFORM|SELECT|WITH|GET|SET|RESET|EXIT|CONTINUE)\b/i;
const WRITES = /\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|COPY|CALL)\b/i;

// Statements that can only make something MORE reachable. These are replayed
// even from a block that is otherwise not trusted.
export function reopens(sql) {
  const flat = blankLiterals(sql).trim();
  if (/^GRANT\b/i.test(flat)) return true;
  if (/^ALTER\s+DEFAULT\s+PRIVILEGES\b/i.test(flat)) return /\bGRANT\b/i.test(flat) && !/\bREVOKE\b/i.test(flat);
  if (/^ALTER\s+TABLE\b/i.test(flat)) return /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(flat) && !/\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(flat);
  // Only when making it a definer function is all the statement does: the same
  // statement can also pin search_path, and that part must not be credited.
  if (/^ALTER\s+FUNCTION\b/i.test(flat)) return /\bSECURITY\s+DEFINER\b/i.test(flat) && !/\b(SET|RESET|RENAME|INVOKER|OWNER)\b/i.test(flat);
  return false;
}

/**
 * @param {string} stmt   one statement, comments already stripped
 * @param {{currentUser?: string|null, isUserFunction?: (name: string) => boolean}} opts
 *   currentUser: the role migrations run as, or null when a SET ROLE earlier in
 *   the file means it is no longer known. isUserFunction: true for a function
 *   the project defines itself, whose effects this reader can't see.
 * @returns {null | {statements: string[], skipped: number, followed: boolean, sessionChanged: boolean}}
 *   null when `stmt` is not a PL/pgSQL DO block. `skipped` counts the dynamic
 *   and DDL statements that were not replayed; `followed` is false when the
 *   block's structure could not be read at all; `sessionChanged` is true when
 *   the block may have changed search_path or role for what follows it.
 */
export function replayableFromDo(stmt, { currentUser = 'postgres', isUserFunction = () => false } = {}) {
  if (!/^DO\b/i.test(stmt)) return null;
  const parsed = parseDo(stmt);
  if (parsed === null) return null;
  const body = unrollForeach(stripComments(parsed));

  const ctx = { currentUser, vars: new Map() };
  const stack = []; // open constructs: block | nested | handler | if | case | loop
  const entries = []; // { sql, certain }
  let unknown = 0; // statements that could do something this reader can't see
  const called = new Set(); // every function the block calls
  let session = false;
  let phase = 'pre'; // pre -> declare -> body
  let nestedDeclare = false; // inside the DECLARE section of a nested block
  let outerHandler = false;
  let stopped = false; // an early exit or a session change was seen
  let undone = false; // COMMIT / ROLLBACK inside the block
  let closed = false;
  const unreadable = () => ({ statements: [], skipped: unknown + entries.length + 1, followed: false, sessionChanged: session || SESSION_WORDS.test(body) });

  // Any variable named in text this reader doesn't fully understand may have
  // been written to (FOR r IN ..., INTO v, GET DIAGNOSTICS v = ..., CALL p(v)),
  // so it is no longer known. Case-insensitive on purpose: "V" and v are
  // different variables, and forgetting both is the safe answer.
  const forgetMentioned = (text) => {
    if (ctx.vars.size === 0) return;
    for (const w of text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []) ctx.vars.delete(w.toLowerCase());
  };

  for (const { sql: chunk } of splitStatements(stripComments(body))) {
    // Blank the literals once per chunk and walk both strings by offset.
    const flatAll = blankLiterals(chunk);
    // For keyword searches: quoted identifiers blanked too, so a column called
    // "then" or "loop" is not read as a keyword.
    const kwAll = blankQuoted(flatAll);
    if (changesSession(chunk, flatAll)) {
      session = true;
      stopped = true;
    }
    let at = 0;
    let namesOnlyFrom = null; // where a statement begins whose parentheses are names, not calls
    let plainDdlFrom = null; // where DDL begins that contains no query of its own
    for (;;) {
      while (at < chunk.length && /\s/.test(chunk[at])) at++;
      if (at >= chunk.length) break;
      if (closed) return unreadable(); // text after the final END
      const s = chunk.slice(at);
      const flat = flatAll.slice(at);
      let m;
      // Skips a leading keyword phrase up to and including `word`.
      const through = (word) => {
        const kw = kwAll.slice(at);
        const w = new RegExp(`\\b${word}\\b`, 'i').exec(kw);
        if (!w) return false;
        // A CASE expression in the condition has a THEN of its own; the first
        // THEN is then not the one that ends the condition. Don't guess.
        if (word === 'THEN' && /\bCASE\b/i.test(kw.slice(0, w.index).replace(/^\s*[A-Za-z]+/, ''))) return false;
        at += w.index + w[0].length;
        return true;
      };

      if ((m = /^<<\s*[A-Za-z_][A-Za-z0-9_]*\s*>>/.exec(flat))) {
        at += m[0].length;
        continue;
      }

      if (phase !== 'body') {
        if (phase === 'pre' && (m = /^DECLARE\b/i.exec(flat))) {
          phase = 'declare';
          at += m[0].length;
          continue;
        }
        if ((m = /^BEGIN\b/i.exec(flat))) {
          phase = 'body';
          stack.push('block');
          at += m[0].length;
          continue;
        }
        if (phase === 'pre') return unreadable();
        // A declaration: name [CONSTANT] type [:= value]. A quoted name is a
        // different variable from its unquoted spelling; trust neither.
        const name = /^("?)([A-Za-z_][A-Za-z0-9_]*)\1/.exec(flat);
        if (!name) return unreadable();
        const key = name[2].toLowerCase();
        const op = /:=|\bDEFAULT\b|(?<![:<>!=])=(?!=)/i.exec(flat);
        if (name[1] || ctx.vars.has(key)) ctx.vars.set(key, null);
        else ctx.vars.set(key, op ? resolveString(s.slice(op.index + op[0].length), ctx) : null);
        break;
      }

      if (nestedDeclare) {
        if (!(m = /^BEGIN\b/i.exec(flat))) {
          forgetMentioned(/^"?[A-Za-z_][A-Za-z0-9_]*"?/.exec(flat)?.[0] ?? '');
          break; // a nested declaration
        }
        nestedDeclare = false;
        stack.push('nested');
        at += m[0].length;
        continue;
      }

      const top = stack[stack.length - 1];

      if ((m = /^END\s+(IF|LOOP|CASE)\b/i.exec(flat))) {
        if (stack.pop() !== m[1].toLowerCase()) return unreadable();
        break;
      }
      if (/^END\b/i.test(flat)) {
        const was = stack.pop();
        if (was !== 'block' && was !== 'nested' && was !== 'handler') return unreadable();
        if (stack.length === 0) closed = true;
        break;
      }
      if ((m = /^EXCEPTION\b/i.exec(flat))) {
        if (top !== 'block' && top !== 'nested') return unreadable();
        if (stack.length === 1) outerHandler = true;
        stack[stack.length - 1] = 'handler';
        at += m[0].length;
        continue;
      }
      if (/^WHEN\b/i.test(flat)) {
        if (top !== 'handler' && top !== 'case') return unreadable();
        if (!through('THEN')) return unreadable();
        continue;
      }
      if ((m = /^DECLARE\b/i.exec(flat))) {
        nestedDeclare = true;
        at += m[0].length;
        continue;
      }
      if ((m = /^BEGIN\b/i.exec(flat))) {
        stack.push('nested');
        at += m[0].length;
        continue;
      }
      if (/^IF\b/i.test(flat)) {
        stack.push('if');
        if (!through('THEN')) return unreadable();
        continue;
      }
      if (/^(ELSIF|ELSEIF)\b/i.test(flat)) {
        if (top !== 'if') return unreadable();
        if (!through('THEN')) return unreadable();
        continue;
      }
      if ((m = /^ELSE\b/i.exec(flat))) {
        if (top !== 'if' && top !== 'case') return unreadable();
        at += m[0].length;
        continue;
      }
      if (/^CASE\b/i.test(flat)) {
        stack.push('case');
        if (!through('THEN')) return unreadable();
        continue;
      }
      if (/^(FOR|WHILE|FOREACH|LOOP)\b/i.test(flat)) {
        stack.push('loop');
        const before = at;
        if (!through('LOOP')) return unreadable();
        // FOR r IN ... assigns r, even when r was declared outside the loop.
        forgetMentioned(flatAll.slice(before, at));
        continue;
      }

      // ── an actual statement ────────────────────────────────────────────
      const certain = stack.length === 1 && stack[0] === 'block' && !stopped;
      const isDdl = DDL.test(flat);
      const isExecute = /^EXECUTE\b/i.test(flat);
      if (isDdl && NAMES_NOT_CALLS.test(flat)) namesOnlyFrom = at;
      if (isDdl && (namesOnlyFrom !== null || !/\bSELECT\b/i.test(kwAll.slice(at)))) plainDdlFrom = at;

      // Leaving the block early: RETURN at any depth, or EXIT / CONTINUE that
      // names a label or sits outside every loop. Whether it fires may depend
      // on a condition, so nothing after it is certain.
      if (/^RETURN\b/i.test(flat) || ((m = /^(EXIT|CONTINUE)\b\s*(?!WHEN\b)([A-Za-z_"]?)/i.exec(flat)) && (m[2] || !stack.includes('loop')))) {
        stopped = true;
        break;
      }
      if (/^(COMMIT|ROLLBACK|ABORT)\b/i.test(flat)) {
        undone = true;
        break;
      }
      // search_path and role decide what the following statements touch.
      if (SESSION_CHANGE.test(flat)) {
        stopped = true;
        session = true;
        forgetMentioned(flat);
        break;
      }

      // Assignment: the variable is only known when this line certainly ran.
      if ((m = /^("?)([A-Za-z_][A-Za-z0-9_]*)\1\s*(?::=|=(?!=))/.exec(flat))) {
        const key = m[2].toLowerCase();
        const value = certain && !m[1] ? resolveString(s.slice(m[0].length), ctx) : null;
        ctx.vars.set(key, value);
        break;
      }

      if (isExecute) {
        const command = commandText(s.slice('EXECUTE'.length));
        const sql = resolveString(command, ctx);
        // EXECUTE ... INTO v writes v.
        forgetMentioned(flat.slice('EXECUTE'.length + command.length));
        if (sql === null) {
          // It could be anything, including a change to the session.
          unknown++;
          stopped = true;
          if (SESSION_WORDS.test(command)) session = true;
          break;
        }
        for (const { sql: inner } of splitStatements(stripComments(sql))) {
          const innerFlat = blankLiterals(inner).trim();
          if (SESSION_CHANGE.test(innerFlat) || changesSession(inner, innerFlat)) {
            unknown++;
            stopped = true;
            session = true;
          } else if (/^(COMMIT|ROLLBACK|ABORT)\b/i.test(innerFlat)) undone = true;
          else if (DDL.test(innerFlat)) {
            entries.push({ sql: inner, certain });
            if (!NAMES_NOT_CALLS.test(innerFlat)) {
              callsIn(innerFlat, called);
              if (castsToOwnType(innerFlat)) unknown++;
              if (/\bSELECT\b/i.test(innerFlat) && readsOwnRelations(blankQuoted(innerFlat))) unknown++;
            }
          } else if (/^(SELECT|WITH)\b/i.test(innerFlat) && !WRITES.test(innerFlat)) {
            callsIn(innerFlat, called);
            if (readsOwnRelations(blankQuoted(innerFlat)) || castsToOwnType(innerFlat)) unknown++;
          } else unknown++; // another DO, a CALL, a write: not something to guess at
        }
        break;
      }
      if (isDdl) {
        entries.push({ sql: s, certain });
        break;
      }
      // PERFORM, SELECT ... INTO, GET DIAGNOSTICS, RAISE, ASSERT: nothing the
      // model tracks. Anything else (a write, CALL, a cursor) could fire a
      // trigger or run code that undoes what the block just did.
      if (!PLAIN.test(flat) || WRITES.test(kwAll.slice(at))) unknown++;
      forgetMentioned(flat);
      break;
    }
    const runs = namesOnlyFrom === null ? flatAll : flatAll.slice(0, namesOnlyFrom);
    callsIn(runs, called);
    if (castsToOwnType(runs)) unknown++;
    if (readsOwnRelations(plainDdlFrom === null ? kwAll : kwAll.slice(0, plainDdlFrom))) unknown++;
  }

  if (!closed) return unreadable();
  // Trusted in full only when nothing in the block was uncertain. A handler on
  // the outermost block means a failure undoes all of it and the migration
  // carries on; transaction control means what ran before a ROLLBACK is gone.
  // A function the project wrote can do anything, including undo this block.
  // That includes a function the block itself creates and then calls.
  const madeHere = new Set();
  for (const e of entries) {
    const m = /^CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+/i.exec(e.sql);
    const n = m && readQualifiedName(e.sql, m[0].length);
    if (n) madeHere.add(n.name);
  }
  const callsOwnCode = [...called].some((name) => madeHere.has(name) || isUserFunction(name));
  const clean = !outerHandler && !undone && unknown === 0 && !callsOwnCode && entries.every((e) => e.certain);
  const kept = clean ? entries : entries.filter((e) => reopens(e.sql));
  return { statements: kept.map((e) => e.sql), skipped: unknown + entries.length - kept.length, followed: true, sessionChanged: session };
}
