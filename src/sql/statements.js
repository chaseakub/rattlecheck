// Minimal SQL lexer: splits a migration file into statements while respecting
// the four things a naive `split(';')` gets wrong. Getting any of them wrong
// makes a checker silently skip statements and report a false all-clear.
//
//   1. dollar-quoted bodies      $$ ... ; ... $$      (every PL/pgSQL function)
//   2. single-quoted literals    'a;b'  'it''s'  and  E'it\\'s'
//   3. double-quoted identifiers "weird;name"
//   4. comments                  -- to EOL   and   /* nested */
//
// Returns [{ sql, index }] in source order. `index` is the offset of the first
// non-whitespace character of the statement, so callers can report positions.
// Use lineIndex(source) to turn an index into a 1-based line number.

const IDENT_CHAR = /[A-Za-z0-9_$]/;

// Index just past the closing quote of the literal or identifier opening at
// `i`. Handles '' / "" doubling and, for E'...' strings, backslash escapes.
// Getting E-strings wrong is not cosmetic: one E'don\'t' would otherwise
// swallow the rest of the file and every statement after it would vanish.
export function quotedEnd(sql, i) {
  const q = sql[i];
  const isE = q === "'" && (sql[i - 1] === 'E' || sql[i - 1] === 'e') && !(i >= 2 && IDENT_CHAR.test(sql[i - 2]));
  const n = sql.length;
  let j = i + 1;
  while (j < n) {
    if (isE && sql[j] === '\\') {
      j += 2;
      continue;
    }
    if (sql[j] === q) {
      if (sql[j + 1] === q) {
        j += 2;
        continue;
      }
      return j + 1;
    }
    j++;
  }
  return n;
}

// If a dollar-quote opens at `i`, returns its tag ($$ or $name$), else null.
// A `$` inside an identifier (foo$bar) or a parameter ($1) is not a quote.
export function dollarTagAt(sql, i) {
  if (sql[i] !== '$') return null;
  if (i > 0 && IDENT_CHAR.test(sql[i - 1])) return null;
  const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 256));
  return m ? m[0] : null;
}

function blockCommentEnd(sql, i) {
  let depth = 1;
  let j = i + 2;
  while (j < sql.length && depth > 0) {
    if (sql[j] === '/' && sql[j + 1] === '*') {
      depth++;
      j += 2;
    } else if (sql[j] === '*' && sql[j + 1] === '/') {
      depth--;
      j += 2;
    } else j++;
  }
  return j;
}

export function splitStatements(sql) {
  const statements = [];
  let start = 0;
  let i = 0;
  const n = sql.length;

  while (i < n) {
    const ch = sql[i];
    if (ch === '-' && sql[i + 1] === '-') {
      const nl = sql.indexOf('\n', i);
      i = nl === -1 ? n : nl + 1;
      continue;
    }
    if (ch === '/' && sql[i + 1] === '*') {
      i = blockCommentEnd(sql, i);
      continue;
    }
    if (ch === "'" || ch === '"') {
      i = quotedEnd(sql, i);
      continue;
    }
    const tag = dollarTagAt(sql, i);
    if (tag) {
      const end = sql.indexOf(tag, i + tag.length);
      i = end === -1 ? n : end + tag.length;
      continue;
    }
    if (ch === ';') {
      const raw = sql.slice(start, i);
      if (raw.trim()) statements.push({ sql: raw.trim(), index: start + (raw.length - raw.trimStart().length) });
      i++;
      start = i;
      continue;
    }
    i++;
  }

  const tail = sql.slice(start);
  if (tail.trim()) statements.push({ sql: tail.trim(), index: start + (tail.length - tail.trimStart().length) });
  return statements;
}

// Strips comments so keyword matching can't be fooled by a commented-out
// `CREATE FUNCTION` or by a `-- SECURITY DEFINER` note. Strings and
// dollar-quoted bodies are kept verbatim.
export function stripComments(sql) {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    if (ch === '-' && sql[i + 1] === '-') {
      const nl = sql.indexOf('\n', i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (ch === '/' && sql[i + 1] === '*') {
      i = blockCommentEnd(sql, i);
      out += ' ';
      continue;
    }
    if (ch === "'" || ch === '"') {
      const end = quotedEnd(sql, i);
      out += sql.slice(i, end);
      i = end;
      continue;
    }
    const tag = dollarTagAt(sql, i);
    if (tag) {
      const end = sql.indexOf(tag, i + tag.length);
      const stop = end === -1 ? n : end + tag.length;
      out += sql.slice(i, stop);
      i = stop;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

// Replaces the inside of every single-quoted literal and dollar-quoted string
// with spaces (same length), so a keyword search can't match text like
// DEFAULT 'enable row level security'. Identifiers are left alone.
export function blankLiterals(sql) {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    if (ch === "'") {
      const end = quotedEnd(sql, i);
      out += `'${' '.repeat(Math.max(0, end - i - 2))}'`.slice(0, end - i);
      i = end;
      continue;
    }
    if (ch === '"') {
      const end = quotedEnd(sql, i);
      out += sql.slice(i, end);
      i = end;
      continue;
    }
    const tag = dollarTagAt(sql, i);
    if (tag) {
      const end = sql.indexOf(tag, i + tag.length);
      const stop = end === -1 ? n : end + tag.length;
      out += ' '.repeat(stop - i);
      i = stop;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

// Reads a possibly-quoted, possibly-schema-qualified identifier starting at
// `pos`. Handles `public.foo`, `"public"."foo"`, `foo`, `"foo"`.
// Returns { schema, name, end } with identifiers already case-folded the way
// Postgres folds them (unquoted -> lower, quoted -> verbatim).
export function readQualifiedName(sql, pos) {
  const parts = [];
  let i = pos;
  for (;;) {
    while (i < sql.length && /\s/.test(sql[i])) i++;
    if (sql[i] === '"') {
      let j = i + 1;
      let val = '';
      while (j < sql.length) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') { val += '"'; j += 2; continue; }
          j++;
          break;
        }
        val += sql[j];
        j++;
      }
      parts.push(val);
      i = j;
    } else {
      const m = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(sql.slice(i));
      if (!m) break;
      parts.push(m[0].toLowerCase());
      i += m[0].length;
    }
    while (i < sql.length && /\s/.test(sql[i])) i++;
    if (sql[i] === '.') { i++; continue; }
    break;
  }
  if (parts.length === 0) return null;
  const name = parts[parts.length - 1];
  const schema = parts.length > 1 ? parts[parts.length - 2] : null;
  return { schema, name, end: i };
}

// Reads the balanced parenthesised argument list starting at the '(' at `pos`.
// Returns { raw, end } or null when there is no '(' there.
export function readParenGroup(sql, pos) {
  let i = pos;
  while (i < sql.length && /\s/.test(sql[i])) i++;
  if (sql[i] !== '(') return null;
  const open = i;
  let depth = 0;
  while (i < sql.length) {
    const ch = sql[i];
    if (ch === "'" || ch === '"') {
      i = quotedEnd(sql, i);
      continue;
    }
    const tag = dollarTagAt(sql, i);
    if (tag) {
      const end = sql.indexOf(tag, i + tag.length);
      i = end === -1 ? sql.length : end + tag.length;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { raw: sql.slice(open + 1, i), end: i + 1 };
    }
    i++;
  }
  return null;
}

// Returns a function mapping a character offset in `source` to a 1-based line
// number. Built once per file: rescanning from the start for every statement
// is quadratic and took 50 seconds on a large baseline.
export function lineIndex(source) {
  const starts = [0];
  for (let i = 0; i < source.length; i++) if (source.charCodeAt(i) === 10) starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}
