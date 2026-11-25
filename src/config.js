// rattlecheck.config.json
//
// {
//   "defaults": "supabase-stock",          // or "clean", or { "functions": "clean", "tables": "supabase-stock" }
//   "exposedSchemas": ["public"],          // optional; read from supabase/config.toml otherwise
//   "migrationRoles": ["postgres"],        // optional; the roles your migrations run as
//   "publish": true,                       // optional; lets the public badge service grade this repo
//   "publishDirs": ["apps/api"],           // optional, top of the repo only; the same for projects in subfolders
//   "allow": [
//     { "rule": "RC005", "object": "public.menu_items", "reason": "Menu is public on the website." }
//   ]
// }
//
// Every allow entry needs a written reason. An exception nobody can explain is
// a hole nobody owns. Entries that match nothing are reported, because a stale
// exception silently covers whatever reuses that name next.
import fs from 'node:fs';
import path from 'node:path';

export class ConfigError extends Error {}

const DEFAULT_MODES = new Set(['supabase-stock', 'clean']);

export function loadConfig(root, explicitPath) {
  const p = explicitPath ? path.resolve(explicitPath) : path.join(root, 'rattlecheck.config.json');
  if (!fs.existsSync(p)) {
    if (explicitPath) throw new ConfigError(`Config file not found: ${p}`);
    return { path: null, defaults: undefined, exposedSchemas: undefined, migrationRoles: undefined, allow: [], publish: false, publishDirs: [] };
  }
  return { path: p, ...parseConfig(fs.readFileSync(p, 'utf8'), p) };
}

/** Validates the text of a rattlecheck.config.json. `label` names the file in error messages. */
export function parseConfig(text, label = 'rattlecheck.config.json') {
  const p = label;
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`${p} is not valid JSON: ${e.message}`);
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError(`${p} must be a JSON object`);

  const d = raw.defaults;
  if (d !== undefined) {
    const ok =
      (typeof d === 'string' && DEFAULT_MODES.has(d)) ||
      (d && typeof d === 'object' && Object.entries(d).every(([k, v]) => ['functions', 'tables'].includes(k) && DEFAULT_MODES.has(v)));
    if (!ok) throw new ConfigError(`"defaults" must be "supabase-stock", "clean", or { "functions": ..., "tables": ... }`);
  }
  if (raw.exposedSchemas !== undefined && !(Array.isArray(raw.exposedSchemas) && raw.exposedSchemas.every((s) => typeof s === 'string'))) {
    throw new ConfigError('"exposedSchemas" must be an array of schema names');
  }

  const privateColumns = raw.privateColumns;
  if (privateColumns !== undefined && (
    !privateColumns || typeof privateColumns !== 'object' || Array.isArray(privateColumns) ||
    !Object.entries(privateColumns).every(([table, names]) => /^[^.]+\..+$/.test(table) &&
      Array.isArray(names) && names.every(name => typeof name === 'string' && name.trim()))
  )) throw new ConfigError('"privateColumns" must map schema-qualified tables to arrays of column names');

  const allow = raw.allow ?? [];
  if (!Array.isArray(allow)) throw new ConfigError('"allow" must be an array');
  allow.forEach((a, i) => {
    if (!a || typeof a.rule !== 'string' || typeof a.object !== 'string') {
      throw new ConfigError(`allow[${i}] needs "rule" (like "RC002") and "object" (like "public.my_function(uuid)")`);
    }
    if (typeof a.reason !== 'string' || a.reason.trim().length < 10) {
      throw new ConfigError(`allow[${i}] (${a.rule} ${a.object}) needs a "reason" that explains why this is safe`);
    }
  });

  if (raw.migrationRoles !== undefined && !(Array.isArray(raw.migrationRoles) && raw.migrationRoles.length && raw.migrationRoles.every((s) => typeof s === 'string'))) {
    throw new ConfigError('"migrationRoles" must be a non-empty array of role names (the roles your migrations run as)');
  }

  if (raw.publish !== undefined && typeof raw.publish !== 'boolean') throw new ConfigError('"publish" must be true or false');
  const dirs = raw.publishDirs ?? [];
  if (!(Array.isArray(dirs) && dirs.every((x) => typeof x === 'string'))) throw new ConfigError('"publishDirs" must be an array of folder names');

  return {
    defaults: d,
    privateColumns,
    exposedSchemas: raw.exposedSchemas,
    migrationRoles: raw.migrationRoles,
    allow,
    publish: raw.publish === true,
    publishDirs: dirs.map((x) => x.trim().replace(/^\.?\/+|\/+$/g, '')),
  };
}
