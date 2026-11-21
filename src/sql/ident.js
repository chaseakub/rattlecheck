// Quote SQL identifiers for generated fix statements.
const RESERVED = new Set([
  'all', 'analyse', 'analyze', 'and', 'any', 'array', 'as', 'asc', 'asymmetric', 'both', 'case', 'cast',
  'check', 'collate', 'column', 'constraint', 'create', 'current_catalog', 'current_date', 'current_role',
  'current_time', 'current_timestamp', 'current_user', 'default', 'deferrable', 'desc', 'distinct', 'do',
  'else', 'end', 'except', 'false', 'fetch', 'for', 'foreign', 'from', 'grant', 'group', 'having', 'in',
  'initially', 'intersect', 'into', 'lateral', 'leading', 'limit', 'localtime', 'localtimestamp', 'not',
  'null', 'offset', 'on', 'only', 'or', 'order', 'placing', 'primary', 'references', 'returning', 'select',
  'session_user', 'some', 'symmetric', 'table', 'then', 'to', 'trailing', 'true', 'union', 'unique', 'user',
  'using', 'variadic', 'when', 'where', 'window', 'with',
]);

export function quoteIdent(name) {
  if (/^[a-z_][a-z0-9_$]*$/.test(name) && !RESERVED.has(name)) return name;
  return `"${name.replace(/"/g, '""')}"`;
}

export function qualified(schema, name) {
  return `${quoteIdent(schema)}.${quoteIdent(name)}`;
}

// public.f(uuid, text) as SQL: schema-qualified name plus the identity argument types.
export function functionRef(f) {
  return `${qualified(f.schema, f.name)}(${f.argsig ?? ''})`;
}
