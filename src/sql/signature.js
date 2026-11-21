// Canonicalises a SQL function argument list into the type-only form Postgres
// uses for function identity (`format_type` over `proargtypes`), so overloads of
// the same name stay distinct. `foo(uuid)` and `foo(uuid, text)` are different
// functions with different grants, and merging them hides real holes.

// Words that can legitimately START a type, so `timestamp with time zone` as an
// unnamed argument is not mistaken for an argument named "timestamp".
const TYPE_INITIAL_WORDS = new Set([
  'bigint', 'int8', 'bit', 'boolean', 'bool', 'box', 'bytea', 'character', 'char',
  'varchar', 'cidr', 'circle', 'citext', 'date', 'daterange', 'decimal', 'double',
  'float4', 'float8', 'hstore', 'inet', 'int', 'int2', 'int4', 'int4range',
  'int8range', 'integer', 'interval', 'json', 'jsonb', 'jsonpath', 'line', 'lseg',
  'ltree', 'macaddr', 'macaddr8', 'money', 'name', 'numeric', 'numrange', 'oid',
  'path', 'pg_lsn', 'point', 'polygon', 'real', 'record', 'regclass', 'regproc',
  'regrole', 'smallint', 'text', 'time', 'timestamp', 'timestamptz', 'timetz',
  'tsquery', 'tsrange', 'tstzrange', 'tsvector', 'uuid', 'vector', 'xml',
  'anyarray', 'anyelement', 'anyenum', 'anynonarray', 'jsonb_path', 'void',
]);

// The multi-word types that can appear without an argument name in front.
const MULTIWORD_TYPE_RE = /^(?:double\s+precision|(?:character|char|bit)\s+varying|(?:timestamp|time)\s*(?:\(\s*\d+\s*\))?\s+with(?:out)?\s+time\s+zone)(?:\s*\(\s*\d+\s*\))?(?:\s*\[\s*\d*\s*\])*\s*$/i;

const TYPE_ALIASES = new Map([
  ['int', 'integer'], ['int4', 'integer'],
  ['int8', 'bigint'],
  ['int2', 'smallint'],
  ['bool', 'boolean'],
  ['varchar', 'character varying'],
  ['char', 'character'],
  ['float8', 'double precision'],
  ['float4', 'real'],
  ['decimal', 'numeric'],
  ['timestamptz', 'timestamp with time zone'],
  ['timetz', 'time with time zone'],
  // Bare `timestamp` / `time` mean the WITHOUT TIME ZONE variants.
  ['timestamp', 'timestamp without time zone'],
  ['time', 'time without time zone'],
]);

function splitTopLevel(argList) {
  const parts = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < argList.length; i++) {
    const ch = argList[i];
    if (ch === "'" || ch === '"') {
      const q = ch;
      cur += ch;
      i++;
      while (i < argList.length) {
        cur += argList[i];
        if (argList[i] === q) {
          if (argList[i + 1] === q) { cur += argList[i + 1]; i += 2; continue; }
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function canonicaliseType(raw) {
  let t = raw.trim().replace(/\s+/g, ' ');

  // Array suffix travels with the type: `uuid []` -> `uuid[]`.
  let arraySuffix = '';
  const arr = /((\s*\[\s*\d*\s*\])+)$/.exec(t);
  if (arr) {
    arraySuffix = '[]'.repeat((arr[1].match(/\[/g) || []).length);
    t = t.slice(0, arr.index).trim();
  }

  // Length/precision modifiers are not part of function identity, wherever
  // they sit: `timestamp(3) with time zone` must keep `with time zone`.
  t = t.replace(/\([^)]*\)/g, ' ').replace(/\s+/g, ' ').trim();

  // `public.thing` and `thing` are the same type here: format_type renders
  // public types unqualified when public is on the search_path.
  t = t.replace(/^"?public"?\./i, '');
  t = t.replace(/"/g, '');

  const lower = t.toLowerCase();
  if (TYPE_ALIASES.has(lower)) return TYPE_ALIASES.get(lower) + arraySuffix;

  // `character varying` / `bit varying` keep their two-word form.
  return lower + arraySuffix;
}

// Turns the raw text between the parentheses of a CREATE/REVOKE/GRANT/DROP
// FUNCTION statement into `type, type, type` matching the catalog.
export function normaliseArgs(rawArgs) {
  if (rawArgs == null) return null; // caller must fall back to name matching
  if (!rawArgs.trim()) return '';

  const out = [];
  for (const part of splitTopLevel(rawArgs)) {
    let arg = part;

    // Strip DEFAULT ... / `= ...`; not part of identity.
    arg = arg.replace(/\s+default\s+[\s\S]*$/i, '');
    const eq = arg.search(/(?<![:<>!])=(?!=)/);
    if (eq !== -1) arg = arg.slice(0, eq);
    arg = arg.trim();

    // Argument mode. OUT args do not participate in identity at all.
    let mode = null;
    const modeMatch = /^(in|out|inout|variadic)\s+/i.exec(arg);
    if (modeMatch) {
      mode = modeMatch[1].toLowerCase();
      arg = arg.slice(modeMatch[0].length).trim();
    }
    if (mode === 'out') continue;

    const tokens = arg.split(/\s+/);
    let typeText;
    if (tokens.length === 1) {
      typeText = tokens[0];
    } else if (MULTIWORD_TYPE_RE.test(arg)) {
      // Unnamed multi-word type: `timestamp with time zone`, `double precision`.
      // Matching the whole type keeps `name text`, `date date` and
      // `time time with time zone` (arguments named after a type) apart.
      typeText = arg;
    } else {
      typeText = tokens.slice(1).join(' '); // first token was the argument name
    }

    out.push(canonicaliseType(typeText));
  }
  return out.join(', ');
}

// `public.foo(uuid, text)`: the identity key used throughout rattlecheck.
export function signatureKey(schema, name, normalisedArgs) {
  const s = (schema || 'public').toLowerCase();
  return normalisedArgs === null ? `${s}.${name}` : `${s}.${name}(${normalisedArgs})`;
}
