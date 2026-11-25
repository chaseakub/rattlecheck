import { tableExposure, tableSelectScope } from '../../model.js';
import { qualified, quoteIdent } from '../../sql/ident.js';

// `true`, `(true)`, `1 = 1` and friends: an expression that admits every row.
export function alwaysTrue(expr) {
  if (expr == null) return false;
  const e = expr.toLowerCase().replace(/[\s()]/g, '');
  return e === 'true' || e === '1=1' || e === "'t'" || e === 'true::boolean';
}

export default {
  id: 'RC005',
  target: 'supabase',
  severity: 'high',
  title: 'Policy lets anyone change every row',
  summary:
    'Row-level security only protects a table as well as its policies do. A permissive policy whose condition is simply true lets every matching role touch every row, which turns RLS back off for that action.',
  standards: { cwe: ['CWE-732'], nist80053: ['AC-3', 'AC-6'], cis: ['3.3'] },

  check(model) {
    const checked = [];
    const findings = [];
    for (const t of model.tables.values()) {
      if (!t.rls) continue;
      const exp = tableExposure(model, t);
      if (!exp.anon && !exp.authenticated) continue;
      checked.push(`table:${t.key}`);

      for (const p of t.policies.values()) {
        if (!p.permissive) continue;
        const forAnon = exp.anon && (p.roles.includes('public') || p.roles.includes('anon'));
        const forUsers = exp.authenticated && (p.roles.includes('public') || p.roles.includes('authenticated'));
        if (!forAnon && !forUsers) continue;

        const usingTrue = p.cmd !== 'INSERT' && alwaysTrue(p.using);
        const checkTrue = p.cmd !== 'SELECT' && p.cmd !== 'DELETE' && alwaysTrue(p.check);
        if (!usingTrue && !checkTrue) continue;
        // Three different risks, three severities:
        //   change (UPDATE/DELETE/ALL): anyone can alter other people's rows. High.
        //   add (INSERT): anyone can add rows. Often a signup or contact form by
        //     design, so a warning: make sure nobody can add rows as someone else.
        //   claim (UPDATE/ALL with a real USING but WITH CHECK (true)): people can
        //     only touch their own rows, but can save them as someone else's. Warning.
        //   read (SELECT): often deliberate (a menu, store hours). Warning, anon only.
        const kind = p.cmd === 'SELECT' ? 'read' : p.cmd === 'INSERT' ? 'add' : usingTrue ? 'change' : 'claim';
        let readScope;
        if (kind === 'read') {
          if (!forAnon) continue;
          const scope = tableSelectScope(t, 'anon');
          if (!scope.all && !scope.columns.size) continue;
          readScope = scope.all ? 'every column, including future columns' : [...scope.columns].sort().map(quoteIdent).join(', ');
        }

        const who = forAnon ? 'Anyone on the internet' : 'Anyone who signs up for your app';
        const action = { ALL: 'read, add, change and delete', UPDATE: 'change', DELETE: 'delete' }[p.cmd];
        const owner = '(select auth.uid()) = user_id';
        const clause = { SELECT: `using (${owner})`, DELETE: `using (${owner})`, INSERT: `with check (${owner})`, UPDATE: `using (${owner}) with check (${owner})`, ALL: `using (${owner}) with check (${owner})` }[p.cmd];
        const ref = qualified(t.schema, t.name);
        const plain = {
          change: `${who} can ${action} any row in the "${t.name}" table, including other people's. The rule "${p.name}" allows it for every row.`,
          add: `${who} can add rows to the "${t.name}" table. That's fine for a signup or contact form. Make sure nobody can add a row that pretends to belong to someone else.`,
          claim: `${who} can save rows in the "${t.name}" table that claim to belong to someone else. The rule "${p.name}" checks which rows they start from, but not what they save.`,
          read: `The "${p.name}" policy permits signed-out reads on every row in "${t.name}". The SELECT grant covers ${readScope}.`,
        }[kind];
        const todo = {
          change: 'Replace this rule with one that only lets people touch their own rows.',
          add: 'If this is a public form, mark it as allowed in rattlecheck.config.json with a reason. If rows belong to users, check that the new row is theirs.',
          claim: 'Add a WITH CHECK that matches the USING, so a saved row still belongs to the person saving it.',
          read: 'Confirm the readable columns are intended for public use. If the public row policy is intentional, allow RC005 with a reason.',
        }[kind];
        findings.push({
          object: `table:${t.key}`,
          name: t.key,
          detail: p.name,
          file: p.file,
          line: p.line,
          severity: kind === 'change' ? 'high' : 'warning',
          message: `Policy "${p.name}" on ${t.key} is permissive FOR ${p.cmd} TO ${p.roles.join(', ')} with an always-true condition.`,
          plain,
          todo,
          fix: `drop policy ${quoteIdent(p.name)} on ${ref};\n-- Replace it with a rule scoped to the row's owner, for example:\n-- create policy ${quoteIdent(p.name)} on ${ref} for ${p.cmd.toLowerCase()} to authenticated ${clause};`,
        });
      }
    }
    return { checked, findings };
  },
};
