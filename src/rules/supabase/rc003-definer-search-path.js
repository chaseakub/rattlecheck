import { functionRef } from '../../sql/ident.js';

export default {
  id: 'RC003',
  target: 'supabase',
  severity: 'high',
  title: 'SECURITY DEFINER function without a pinned search_path',
  summary:
    'Without SET search_path, a privileged function looks names up in whatever order the caller\'s session says, including the caller\'s temporary schema. A caller can shadow a table or function the definer uses and have their own code run with the owner\'s powers.',
  standards: { cwe: ['CWE-426'], nist80053: ['CM-6', 'AC-6'], cis: ['4.1'] },

  check(model) {
    const checked = [];
    const findings = [];
    for (const f of model.functions.values()) {
      if (!f.isSecurityDefiner) continue;
      checked.push(`function:${f.key}`);
      if (f.searchPath) continue;
      findings.push({
        object: `function:${f.key}`,
        name: f.key,
        file: f.file,
        line: f.line,
        severity: 'high',
        message: `${f.key} is SECURITY DEFINER with no SET search_path.`,
        plain: `The "${f.name}" function runs with full database powers but doesn't lock down where it looks things up. Someone could trick it into running their code with those powers.`,
        todo: 'Pin the function\'s search path.',
        fix: `alter function ${functionRef(f)} set search_path = '';\n-- With an empty search_path, write every table inside the function with its schema (public.orders, not orders).`,
      });
    }
    return { checked, findings };
  },
};
