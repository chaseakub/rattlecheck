import { tableExposure } from '../../model.js';
import { qualified } from '../../sql/ident.js';

export default {
  id: 'RC001',
  target: 'supabase',
  severity: 'critical',
  title: 'Table reachable through the API without row-level security',
  summary:
    'Supabase serves every table in an exposed schema over HTTP. Without row-level security, the key that ships in your website lets anyone read and change every row.',
  standards: { cwe: ['CWE-284', 'CWE-862'], nist80053: ['AC-3', 'AC-6'], cis: ['3.3'] },

  check(model) {
    const checked = [];
    const findings = [];
    for (const t of model.tables.values()) {
      const exp = tableExposure(model, t);
      if (!exp.anon && !exp.authenticated) continue;
      checked.push(`table:${t.key}`);
      if (t.rls) continue;

      const privs = exp.anon ? t.privs.anon : t.privs.authenticated;
      const canRead = privs.has('select');
      const canWrite = ['insert', 'update', 'delete'].some((p) => privs.has(p));
      const verbs = canRead && canWrite ? 'read and change' : canRead ? 'read' : 'change';
      const who = exp.anon
        ? "Anyone on the internet, using only the key that ships in your website's code,"
        : 'Anyone who signs up for your app';
      const copyNote =
        t.kind === 'ctas'
          ? ' It was created as a copy of another table, and copies inherit none of the original\'s security.'
          : '';

      const ref = qualified(t.schema, t.name);
      const fix =
        t.kind === 'ctas'
          ? `alter table ${ref} enable row level security;\nrevoke all on ${ref} from anon, authenticated;\n-- This table is a copy. If it was a one-off snapshot, drop it once you're done with it.`
          : `alter table ${ref} enable row level security;\n-- With RLS on and no policies, only your server (service role) can use this table.\n-- Then add a policy for each thing users should be allowed to do, for example:\n-- create policy "read own rows" on ${ref} for select to authenticated using ((select auth.uid()) = user_id);`;

      findings.push({
        object: `table:${t.key}`,
        name: t.key,
        file: t.file,
        line: t.line,
        severity: 'critical',
        message: `${t.key} has row-level security off and is reachable through the Data API by ${exp.anon ? 'anon' : 'authenticated'} (${[...privs].join(', ')}).${t.kind === 'ctas' ? ' Created as a copy (CREATE TABLE AS or SELECT INTO).' : ''}`,
        plain: `${who} can ${verbs} every row in the "${t.name}" table.${copyNote}`,
        todo: t.kind === 'ctas' ? 'Lock the copy, or drop it if you no longer need it.' : 'Turn on row-level security for this table, then add rules for who can see what.',
        fix,
      });
    }
    return { checked, findings };
  },
};
