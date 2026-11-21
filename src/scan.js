// The single entry point every surface uses: CLI, MCP server, tests.
import path from 'node:path';
import { buildModel, findMigrationsDir, loadMigrations, readExposedSchemas } from './model.js';
import { loadConfig } from './config.js';
import { STATIC_RULES, LIVE_RULES } from './rules/index.js';
import { countBySeverity, gradeFor, GRADES, OPEN_SEVERITIES } from './report/grade.js';
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

function decorate(rule, f, root, migrationsDir) {
  return {
    rule: rule.id,
    title: rule.title,
    target: rule.target,
    ...f,
    file: f.file && migrationsDir ? path.relative(root, path.join(migrationsDir, f.file)) : f.file,
    standards: rule.standards,
  };
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

  const raw = [];
  const checked = new Set();
  for (const rule of STATIC_RULES) {
    const r = rule.check(model);
    r.checked.forEach((c) => checked.add(c));
    for (const f of r.findings) raw.push(decorate(rule, f, root, migrationsDir));
  }

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
      for (const f of r.findings) raw.push(decorate(rule, f, root, migrationsDir));
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

  // Allowlist: exact rule + object name.
  const findings = [];
  const allowed = [];
  const used = new Set();
  for (const f of raw) {
    const idx = config.allow.findIndex((a) => a.rule.toUpperCase() === f.rule && a.object === f.name);
    if (idx === -1) findings.push(f);
    else {
      used.add(idx);
      allowed.push({ ...f, reason: config.allow[idx].reason });
    }
  }
  const configWarnings = config.allow
    .map((a, i) => ({ a, i }))
    .filter(({ a, i }) => !used.has(i) && !(a.rule.toUpperCase() === 'RC101' && !live))
    .map(({ a }) => `allow entry ${a.rule} ${a.object} matches nothing. Remove it, so it can't quietly cover something new later.`);

  const order = { critical: 0, high: 1, warning: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.rule.localeCompare(b.rule) || a.name.localeCompare(b.name));

  const counts = countBySeverity(findings);
  const letter = gradeFor(counts);
  const open = new Set(findings.filter((f) => OPEN_SEVERITIES.has(f.severity)).map((f) => f.object));

  const coverageOk = !(migrations.length > 0 && model.coverage.statements === 0);

  return {
    schema: REPORT_SCHEMA,
    tool: { name: 'rattlecheck', version: VERSION },
    target: 'supabase',
    generatedAt: new Date().toISOString(),
    root,
    migrationsDir: path.relative(root, migrationsDir) || '.',
    grade: { letter, ...GRADES[letter] },
    doors: { checked: checked.size, open: open.size },
    counts,
    findings,
    allowed,
    configWarnings,
    coverage: {
      ok: coverageOk,
      ...model.coverage,
      tables: model.tables.size,
      functions: model.functions.size,
      exposedSchemas,
      defaults: model.defaults,
    },
    live: liveReport,
  };
}
