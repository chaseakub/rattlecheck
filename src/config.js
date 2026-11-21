// rattlecheck.config.json
//
// {
//   "defaults": "supabase-stock",          // or "clean", or { "functions": "clean", "tables": "supabase-stock" }
//   "exposedSchemas": ["public"],          // optional; read from supabase/config.toml otherwise
//   "migrationRoles": ["postgres"],        // optional; the roles your migrations run as
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
    return { path: null, defaults: undefined, exposedSchemas: undefined, migrationRoles: undefined, allow: [] };
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    throw new ConfigError(`${p} is not valid JSON: ${e.message}`);
  }

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

  return { path: p, defaults: d, exposedSchemas: raw.exposedSchemas, migrationRoles: raw.migrationRoles, allow };
}
