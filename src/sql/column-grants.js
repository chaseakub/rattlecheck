import { dollarTagAt, quotedEnd, readParenGroup, readQualifiedName } from './statements.js';

const TABLE_PRIVILEGES = ['select', 'insert', 'update', 'delete'];
const COLUMN_PRIVILEGES = ['select', 'insert', 'update'];

// Lists appear in column definitions, multi-action ALTERs, and GRANT/REVOKE.
function splitList(text) {
  const parts = [];
  let start = 0;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      i = quotedEnd(text, i) - 1;
    } else if (ch === '$') {
      const tag = dollarTagAt(text, i);
      if (!tag) continue;
      const end = text.indexOf(tag, i + tag.length);
      i = end === -1 ? text.length : end + tag.length - 1;
    } else if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(text.slice(start).trim());
  return parts.filter(Boolean);
}

export function parsePrivileges(text) {
  const table = new Set();
  const column = new Map();
  let usage = false;
  for (const item of splitList(text)) {
    const paren = item.indexOf('(');
    const word = (paren === -1 ? item : item.slice(0, paren)).trim().toLowerCase();
    const all = /^all(?:\s+privileges)?$/.test(word);
    if (paren === -1) {
      if (all || word === 'usage') usage = true;
      for (const privilege of TABLE_PRIVILEGES) {
        if (all || word === privilege) table.add(privilege);
      }
      continue;
    }
    const group = readParenGroup(item, paren);
    if (!group) continue;
    for (const privilege of COLUMN_PRIVILEGES) {
      if (!all && privilege !== word) continue;
      if (!column.has(privilege)) column.set(privilege, new Set());
      for (const name of splitList(group.raw)) {
        const ident = readQualifiedName(name, 0);
        if (ident) column.get(privilege).add(ident.name);
      }
    }
  }
  return { table, column, usage };
}

export const apiRoles = ['anon', 'authenticated'];
export const grantees = ['public', ...apiRoles];

export function newTableDefaults(stock = false) {
  const direct = stock ? TABLE_PRIVILEGES : [];
  return { public: new Set(), anon: new Set(direct), authenticated: new Set(direct) };
}

export function createTableAcl(schemaDefaults, globalDefaults) {
  return Object.fromEntries(grantees.map(role => [
    role, {
      table: new Map([...schemaDefaults[role], ...globalDefaults[role]].map(privilege => [privilege, null])),
      column: new Map(),
    },
  ]));
}

// PostgreSQL stores direct grants separately for each grantee. PUBLIC is
// inherited when privileges are evaluated, not copied into the role's ACL.
export function changeTableAcl(acl, privs, revoke, location) {
  for (const privilege of privs.table) {
    if (revoke) {
      acl.table.delete(privilege);
      acl.column.delete(privilege);
    } else acl.table.set(privilege, location);
  }
  for (const [privilege, columns] of privs.column) {
    if (!acl.column.has(privilege)) {
      if (revoke) continue;
      acl.column.set(privilege, new Map());
    }
    const grants = acl.column.get(privilege);
    for (const name of columns) revoke ? grants.delete(name) : grants.set(name, location);
  }
}

export function effectivePrivileges(table, role) {
  const privileges = new Set();
  for (const acl of [table.acl.public, table.acl[role]]) {
    for (const name of acl.table.keys()) privileges.add(name);
    for (const [name, columns] of acl.column) if (columns.size) privileges.add(name);
  }
  return privileges;
}

/** Effective SELECT through PUBLIC or a direct role grant. A table-wide grant covers future columns too. */
export function tableSelectScope(table, role) {
  const direct = table.acl[role];
  const inherited = table.acl.public;
  return {
    all: direct.table.has('select') || inherited.table.has('select'),
    columns: new Set([...(direct.column.get('select')?.keys() ?? []), ...(inherited.column.get('select')?.keys() ?? [])]),
  };
}

// A newly named column may appear long after the grant covering it. Attribute
// the finding to the latest relevant DDL or still-active ACL, in replay order.
export function readColumnLocation(table, name, role = 'anon') {
  let latest = table.columnLocations.get(name);
  for (const acl of [table.acl.public, table.acl[role]]) {
    const grants = [acl.table.get('select'), acl.column.get('select')?.get(name)];
    for (const grant of grants) {
      if (grant && (!latest || grant.order > latest.order)) latest = grant;
    }
  }
  const { file, line } = latest ?? table;
  return { file, line };
}

const tableConstraint = /^(?:constraint\s|check\s*\(|exclude\s|primary\s+key\b|foreign\s+key\b|unique\s*(?:\(|nulls\b|using\s+index\b)|like\s)/i;

export function declaredColumns(text, offset) {
  const columns = new Set();
  const group = readParenGroup(text, offset);
  if (!group) return columns;
  for (const definition of splitList(group.raw)) {
    if (tableConstraint.test(definition)) continue;
    const ident = readQualifiedName(definition, 0);
    if (ident) columns.add(ident.name);
  }
  return columns;
}

export function alterColumns(table, actions, location) {
  for (const action of splitList(actions)) {
    const add = /^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?/i.exec(action);
    if (add) {
      const definition = action.slice(add[0].length);
      if (tableConstraint.test(definition)) continue;
      const name = readQualifiedName(definition, 0);
      if (name && !table.columns.has(name.name)) {
        table.columns.add(name.name);
        table.columnLocations.set(name.name, location);
      }
      continue;
    }
    if (/^(?:drop|rename)\s+constraint\s|^rename\s+to\s/i.test(action)) continue;
    const change = /^(drop|rename)\s+(?:column\s+)?(?:if\s+exists\s+)?/i.exec(action);
    if (!change) continue;
    const from = readQualifiedName(action, change[0].length);
    if (!from) continue;
    let to;
    if (change[1].toLowerCase() === 'rename') {
      const rename = /^\s*to\s+/i.exec(action.slice(from.end));
      to = rename && readQualifiedName(action, from.end + rename[0].length);
      if (!to) continue;
    }
    table.columns.delete(from.name);
    table.columnLocations.delete(from.name);
    if (to) {
      table.columns.add(to.name);
      table.columnLocations.set(to.name, location);
    }
    for (const acl of Object.values(table.acl)) {
      for (const columns of acl.column.values()) {
        const grant = columns.get(from.name);
        if (columns.delete(from.name) && to) columns.set(to.name, grant);
      }
    }
  }
}
