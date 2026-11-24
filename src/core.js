// The static check with no file system and no network: migrations in, graded
// report out. The CLI, the MCP server and the publish service all go through
// here, so a grade means the same thing wherever it was computed.
import { buildModel } from './model.js';
import { STATIC_RULES } from './rules/index.js';
import { countBySeverity, gradeFor, GRADES, OPEN_SEVERITIES } from './report/grade.js';

const SEVERITY_ORDER = { critical: 0, high: 1, warning: 2 };

export function decorate(rule, f, fileOf) {
  return {
    rule: rule.id,
    title: rule.title,
    target: rule.target,
    ...f,
    file: f.file ? fileOf(f.file) : f.file,
    standards: rule.standards,
  };
}

/** Runs every static rule over a model. Returns the raw findings and the set of objects checked. */
export function runStaticRules(model, fileOf) {
  const raw = [];
  const checked = new Set();
  for (const rule of STATIC_RULES) {
    const r = rule.check(model);
    r.checked.forEach((c) => checked.add(c));
    for (const f of r.findings) raw.push(decorate(rule, f, fileOf));
  }
  return { raw, checked };
}

/** Applies the allow list and decides the grade. `live` says whether live rules ran. */
export function settle({ raw, checked, allow = [], live = false }) {
  // Allowlist: exact rule + object name.
  const findings = [];
  const allowed = [];
  const used = new Set();
  for (const f of raw) {
    const idx = allow.findIndex((a) => a.rule.toUpperCase() === f.rule && a.object === f.name);
    if (idx === -1) findings.push(f);
    else {
      used.add(idx);
      allowed.push({ ...f, reason: allow[idx].reason });
    }
  }
  const configWarnings = allow
    .map((a, i) => ({ a, i }))
    .filter(({ a, i }) => !used.has(i) && !(a.rule.toUpperCase() === 'RC101' && !live))
    .map(({ a }) => `allow entry ${a.rule} ${a.object} matches nothing. Remove it, so it can't quietly cover something new later.`);

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.rule.localeCompare(b.rule) || a.name.localeCompare(b.name));

  const counts = countBySeverity(findings);
  const letter = checked.size === 0 ? 'N/A' : gradeFor(counts);
  const open = new Set(findings.filter((f) => OPEN_SEVERITIES.has(f.severity)).map((f) => f.object));
  return {
    grade: { letter, ...GRADES[letter] },
    doors: { checked: checked.size, open: open.size },
    counts,
    findings,
    allowed,
    configWarnings,
  };
}

export function coverageOf(model, migrationCount, exposedSchemas) {
  return {
    ok: !(migrationCount > 0 && model.coverage.statements === 0),
    ...model.coverage,
    tables: model.tables.size,
    functions: model.functions.size,
    exposedSchemas,
    defaults: model.defaults,
  };
}

/**
 * The whole static check, from migration text.
 * @param {object} opts
 * @param {{file:string, sql:string}[]} opts.migrations   in replay order
 * @param {object} [opts.config]            as returned by parseConfig
 * @param {string[]} [opts.exposedSchemas]  from supabase/config.toml, when the config doesn't say
 * @param {number} [opts.maxStatements]     stop with a BudgetError past this many statements
 * @param {(file:string)=>string} [opts.fileOf]  how a migration file name is shown in findings
 */
export function scanStatic({ migrations, config = {}, exposedSchemas, maxStatements, fileOf = (f) => `supabase/migrations/${f}` }) {
  const schemas = config.exposedSchemas ?? exposedSchemas ?? ['public', 'graphql_public'];
  const model = buildModel(migrations, { defaults: config.defaults, exposedSchemas: schemas, migrationRoles: config.migrationRoles, maxStatements });
  const { raw, checked } = runStaticRules(model, fileOf);
  return { model, raw, checked, ...settle({ raw, checked, allow: config.allow ?? [] }), coverage: coverageOf(model, migrations.length, schemas) };
}
