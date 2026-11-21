import { functionRef } from '../../sql/ident.js';

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export default {
  id: 'RC004',
  target: 'supabase',
  severity: 'high',
  title: 'Invoker-rights trigger writes to a table locked to the server',
  summary:
    'A table with RLS on and no policies is deny-all for everyone except the service role. A trigger that runs with the CALLER\'s rights and writes to it makes every user action that fires the trigger fail with 42501 and roll back. Server jobs bypass RLS, so pipelines stay green while users cannot save.',
  standards: { cwe: ['CWE-279'], nist80053: ['AC-6', 'AU-9'], cis: ['8.2'] },

  check(model) {
    const checked = [];
    const findings = [];
    const denyAll = [...model.tables.values()].filter((t) => t.rls && t.policies.size === 0);

    for (const f of model.functions.values()) {
      if (!f.isTrigger) continue;
      checked.push(`function:${f.key}`);
      if (f.isSecurityDefiner) continue;
      const fnName = `${f.schema}.${f.name}`;
      const firesOn = model.triggers.filter((tr) => tr.fn === fnName).map((tr) => tr.table);

      for (const t of denyAll) {
        const target = `(?:"?${esc(t.schema)}"?\\.)?"?${esc(t.name)}"?`;
        const writes = new RegExp(`(?:INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\s+${target}(?![\\w$])`, 'i');
        // Unqualified names only resolve to public through the default search_path.
        if (!writes.test(f.body)) continue;
        if (t.schema !== 'public' && !new RegExp(`"?${esc(t.schema)}"?\\.`, 'i').test(f.body)) continue;
        const ref = functionRef(f);
        const on = firesOn.length ? firesOn.map((x) => x.split('.').pop()).join(', ') : 'a table';
        findings.push({
          object: `function:${f.key}`,
          name: f.key,
          file: f.file,
          line: f.line,
          severity: 'high',
          message: `Trigger function ${f.key} (SECURITY INVOKER) writes to ${t.key}, which has RLS enabled and no policies. User writes that fire it raise 42501.${firesOn.length ? ` Fires on: ${firesOn.join(', ')}.` : ''}`,
          plain: `When a user changes ${on}, the "${f.name}" trigger tries to write to "${t.name}", which only your server is allowed to touch. The user's change fails and is undone. Your server jobs skip this lock, so everything can look healthy while users can't save.`,
          todo: 'Let the trigger run with its owner\'s rights, so it works no matter who fired it.',
          fix: `alter function ${ref} security definer;\nalter function ${ref} set search_path = '';\n-- Trigger functions can't be called directly, so this does not open a new door.`,
        });
      }
    }
    return { checked, findings };
  },
};
