// The single entry point every surface uses: CLI, MCP server, tests.
import path from 'node:path';
import { buildModel, findMigrationsDir, loadMigrations, readExposedSchemas } from './model.js';
import { loadConfig } from './config.js';
import { LIVE_RULES } from './rules/index.js';
import { decorate, runStaticRules, settle, coverageOf } from './core.js';
import { readProjectEnv, looksSecret } from './live/env.js';
import { proveOwnership } from './live/ownership.js';
import { probeTables } from './live/probe.js';
import { listExposedObjects } from './live/catalog.js';
import { tableExposure } from './model.js';
import { VERSION, USER_AGENT } from './version.js';

export const REPORT_SCHEMA = 'rattlecheck.report/v1';

export class ScanError extends Error {
  constructor(message, code = 2) {
    super(message);
    this.code = code;
  }
}

/**
 * @param {object} opts
 * @param {string} [opts.root]
 * @param {boolean} [opts.live]
 * @param {string} [opts.configPath]
 * @param {object} [opts.env]        process environment (tokens are read from here)
 * @param {Function} [opts.fetchImpl]
 */
export async function scan({ root = '.', live = false, configPath, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  root = path.resolve(root);
  const config = loadConfig(root, configPath);
  const migrationsDir = findMigrationsDir(root);
  if (!migrationsDir) {
    throw new ScanError(`No Supabase migrations found under ${root}. Run rattlecheck from your project folder (the one that contains supabase/migrations), or pass that folder as an argument.`);
  }

  const migrations = loadMigrations(migrationsDir);
  const exposedSchemas = config.exposedSchemas ?? readExposedSchemas(root);
  const model = buildModel(migrations, { defaults: config.defaults, exposedSchemas, migrationRoles: config.migrationRoles });

  const fileOf = (file) => path.relative(root, path.join(migrationsDir, file));
  const { raw, checked } = runStaticRules(model, fileOf, config);

  let liveReport = { ran: false };
  if (live) {
    const projectEnv = readProjectEnv(root, env);
    if (!projectEnv.url || !projectEnv.anonKey) {
      throw new ScanError(
        `Live check needs your project URL and public (anon or publishable) key together, either both in the environment or both in .env / .env.local (looked in: ${projectEnv.source}).`,
      );
    }
    if (looksSecret(projectEnv.anonKey) || projectEnv.anonKey === projectEnv.serviceKey) {
      throw new ScanError('The key in your public (anon or publishable) slot is a secret key. A live check with it would mean nothing, and that key should never ship in your website. Use the anon or publishable key.');
    }
    const own = await proveOwnership({ url: projectEnv.url, accessToken: projectEnv.accessToken, serviceKey: projectEnv.serviceKey, fetchImpl, userAgent: USER_AGENT });
    if (!own.ok) {
      throw new ScanError(
        `Live check refused: rattlecheck only checks projects you can prove are yours (${own.reason}). ` +
          'Run `supabase login` and set SUPABASE_ACCESS_TOKEN, or put the project\'s service key in your local .env.',
        4,
      );
    }
    const fromMigrations = [...model.tables.values()].filter((t) => tableExposure(model, t).exposed).map((t) => t.key);
    // The live check has to ask about everything the project serves, not just
    // what the migrations know about. See src/live/catalog.js.
    const catalog = own.method === 'access-token'
      ? await listExposedObjects({ ref: own.ref, accessToken: projectEnv.accessToken, schemas: exposedSchemas, fetchImpl, userAgent: USER_AGENT })
      : { ok: false, names: [], reason: 'proved ownership with a service key; the full table list needs SUPABASE_ACCESS_TOKEN' };
    const candidates = [...new Set([...fromMigrations, ...catalog.names])];
    const probe = await probeTables({ url: own.base, anonKey: projectEnv.anonKey, tables: candidates, fetchImpl, userAgent: USER_AGENT });
    for (const rule of LIVE_RULES) {
      const r = rule.check(probe, model);
      r.checked.forEach((c) => checked.add(c));
      for (const f of r.findings) raw.push(decorate(rule, f, fileOf));
    }
    const by = (s) => probe.results.filter((x) => x.state === s).length;
    const known = new Set(fromMigrations);
    const complete = catalog.ok || probe.apiList.ok;
    liveReport = {
      ran: true,
      ownership: own.method,
      // How the list of things to ask about was built. complete=false means
      // objects created outside migrations may exist and were NOT checked.
      coverage: {
        complete,
        source: catalog.ok ? 'project catalog (read-only)' : probe.apiList.ok ? 'API table list' : 'migrations only',
        fromMigrations: fromMigrations.length,
        outsideMigrations: probe.results.filter((x) => !known.has(x.table)).length,
        ...(complete ? {} : { reason: catalog.reason }),
      },
      probed: probe.results.length,
      open: by('open'),
      lockedOrEmpty: by('locked-or-empty'),
      locked: by('locked'),
      notExposed: by('not-exposed'),
      errors: by('error'),
    };
  }

  const settled = settle({ raw, checked, allow: config.allow, live });

  return {
    schema: REPORT_SCHEMA,
    tool: { name: 'rattlecheck', version: VERSION },
    target: 'supabase',
    generatedAt: new Date().toISOString(),
    root,
    migrationsDir: path.relative(root, migrationsDir) || '.',
    ...settled,
    coverage: coverageOf(model, migrations.length, exposedSchemas),
    live: liveReport,
  };
}
