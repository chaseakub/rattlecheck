import { readColumnLocation, tableExposure, tableSelectScope } from '../../model.js';
import { alwaysTrue } from './rc005-permissive-true-policy.js';
import { qualified, quoteIdent } from '../../sql/ident.js';

// Only literal denials prove that a policy can never return a row. Other
// predicates may expose a subset, and a column grant applies to each visible row.
function deniesAllRows(policy) {
  const expression = policy.using?.toLowerCase().replace(/[\s()]/g, '');
  return ['false', 'false::boolean', "'f'::boolean", 'null', 'null::boolean', '1=0'].includes(expression);
}

function columnSeverity(name, designated) {
  if (designated.has(name)) return 'high';
  const snake = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  if (/^(?:private|internal)_.+/.test(snake) ||
      /^(?:password|password_hash|encrypted_password|api_key|secret_key|private_key|access_token|refresh_token|session_token|ssn|social_security_number)$/.test(snake)) return 'high';
  if (snake === 'email' || snake === 'email_address') return 'warning';
  return null;
}

export default {
  id: 'RC006',
  target: 'supabase',
  severity: 'high',
  title: 'Anonymous SELECT includes a potentially private column',
  summary: 'A row policy can allow public browsing while the SELECT grant also includes private fields on those rows.',
  standards: { cwe: ['CWE-200'], nist80053: ['AC-3', 'AC-6'], cis: ['3.3'] },

  check(model, config = {}) {
    const checked = [];
    const findings = [];
    for (const table of model.tables.values()) {
      if (!table.rls || !tableExposure(model, table).anon) continue;
      const scope = tableSelectScope(table, 'anon');
      if (!scope.all && !scope.columns.size) continue;
      const policies = [...table.policies.values()].filter(p =>
        ['SELECT', 'ALL'].includes(p.cmd) && (p.roles.includes('anon') || p.roles.includes('public')));
      if (!policies.some(p => p.permissive && !deniesAllRows(p)) || policies.some(p => !p.permissive && deniesAllRows(p))) continue;

      checked.push(`table:${table.key}`);
      const ref = qualified(table.schema, table.name);
      const names = scope.all ? new Set([...table.columns, ...scope.columns]) : scope.columns;
      const designated = new Set(config.privateColumns?.[table.key] ?? []);
      const initialCount = findings.length;
      for (const name of [...names].sort()) {
        const severity = columnSeverity(name, designated);
        if (!severity) continue;
        const field = `${ref}.${quoteIdent(name)}`;
        const grant = scope.all ? 'table-wide SELECT' : 'column-level SELECT';
        findings.push({
          object: `table:${table.key}`, name: field, detail: name, ...readColumnLocation(table, name), severity,
          message: `The anon role has ${grant} on ${ref}. It includes ${quoteIdent(name)} for rows visible under its SELECT policies.`,
          plain: `Signed-out visitors have permission to read ${field} on any row visible to them.`,
          todo: designated.has(name)
            ? 'This column is marked private in your config. Limit anonymous SELECT to the public columns.'
            : 'Review whether this field belongs in the public response. If it is private, grant SELECT only on the public columns.',
          fix: '-- Review grants to anon and PUBLIC, including inherited access.\n-- Revoke the broad SELECT and grant SELECT only on the columns approved for public browsing.',
        });
      }

      // No column name can establish a team's intent. Still surface an unrestricted
      // grant independently of RC005 when a policy explicitly allows public rows.
      const publicRows = policies.some(p => p.permissive && (p.using == null || alwaysTrue(p.using)));
      if (scope.all && publicRows && findings.length === initialCount) {
        findings.push({
          object: `table:${table.key}`, name: table.key, ...readColumnLocation(table, null), severity: 'warning',
          message: `Anonymous table-wide SELECT on ${ref} covers every current and future column on visible rows.`,
          plain: `Adding a column to ${ref} also makes it readable on public rows. The anonymous SELECT grant covers the whole table.`,
          todo: 'Grant SELECT on named public columns, or allow this rule for the table if all current and future columns are intended to be public.',
          fix: '-- Review which columns should be public before replacing the table-wide grant with a named column grant.',
        });
      }
    }
    return { checked, findings };
  },
};
