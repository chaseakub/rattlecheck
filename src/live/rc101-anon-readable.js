import { qualified } from '../sql/ident.js';

export default {
  id: 'RC101',
  target: 'supabase',
  live: true,
  severity: 'critical',
  title: 'Live table hands rows to the public key',
  summary:
    'Checked against the running project, not the migration files. A table that returns rows to the anon key is readable by anyone who opens your website and copies the key out of its code. This also catches changes made in the dashboard that never made it into a migration.',
  standards: { cwe: ['CWE-200', 'CWE-284'], nist80053: ['AC-3', 'AC-6'], cis: ['3.3'] },

  check(probe, model) {
    const checked = [];
    const findings = [];
    for (const r of probe.results) {
      checked.push(`table:${r.table}`);
      if (r.state !== 'open') continue;
      const [schema, name] = r.table.split('.');
      const staticT = model?.tables.get(r.table);
      const drift = staticT && staticT.rls
        ? ' Your migrations turn row-level security on for this table, so either a policy lets the public read it, or the live database was changed outside your migrations.'
        : '';
      findings.push({
        object: `table:${r.table}`,
        name: r.table,
        file: staticT?.file ?? null,
        line: staticT?.line ?? null,
        severity: 'critical',
        message: `Live: ${r.table} returned a count of ${r.count} rows to the anon key.${drift}`,
        plain: `Right now, anyone on the internet can read ${r.count.toLocaleString('en-US')} rows from the "${name}" table. rattlecheck confirmed this by asking your live project with only your public key. It did not read or keep any of the data.${drift}`,
        todo: 'Lock this table today. If the data is meant to be public, mark it as allowed in rattlecheck.config.json with a reason.',
        fix: `alter table ${qualified(schema, name)} enable row level security;\n-- Then review the policies on ${qualified(schema, name)} and remove any that let anon read rows it shouldn't.`,
      });
    }
    return { checked, findings };
  },
};
