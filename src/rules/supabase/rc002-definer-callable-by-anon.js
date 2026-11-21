import { functionReach } from '../../model.js';
import { functionRef } from '../../sql/ident.js';

export default {
  id: 'RC002',
  target: 'supabase',
  severity: 'critical',
  title: 'SECURITY DEFINER function callable by anyone',
  summary:
    'A SECURITY DEFINER function runs with its owner\'s powers and skips row-level security. Postgres lets PUBLIC execute every new function by default, so unless that grant is revoked, anyone with your public key can call it over the API.',
  standards: { cwe: ['CWE-269', 'CWE-862'], nist80053: ['AC-3', 'AC-6'], cis: ['3.3', '6.8'] },

  check(model) {
    const checked = [];
    const findings = [];
    for (const f of model.functions.values()) {
      if (!f.isSecurityDefiner || f.isTrigger) continue;
      if (!model.exposedSchemas.includes(f.schema)) continue;
      checked.push(`function:${f.key}`);
      const reach = functionReach(model, f);
      if (!reach.public && !reach.anon) continue;
      const ref = functionRef(f);
      findings.push({
        object: `function:${f.key}`,
        name: f.key,
        file: f.file,
        line: f.line,
        severity: 'critical',
        message: `${f.key} is SECURITY DEFINER and executable by ${reach.public ? 'PUBLIC' : 'anon'}. It bypasses row-level security for every caller.`,
        plain: `Anyone on the internet can run the "${f.name}" function. It runs with full database powers and skips your security rules, so whatever it can read or change, anyone can.`,
        todo: 'Stop the public from calling it. If signed-in users need it, allow only them.',
        fix: `revoke execute on function ${ref} from public, anon;\n-- Only if signed-in users should be able to call it:\ngrant execute on function ${ref} to authenticated;`,
      });
    }
    return { checked, findings };
  },
};
