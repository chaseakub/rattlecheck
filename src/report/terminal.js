// Terminal output in two voices.
//   plain (default): what's wrong and what to do, for anyone.
//   technical:       adds file:line, the exact condition, standards and the fix SQL.

const SEV = {
  critical: { label: 'CRITICAL', color: 31 },
  high: { label: 'HIGH', color: 33 },
  warning: { label: 'CHECK', color: 36 },
};

function painter(useColor) {
  const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { bold: c(1), dim: c(2), red: c(31), green: c(32), yellow: c(33), cyan: c(36), code: c };
}

function gradeCode(letter) {
  return { A: 32, B: 32, C: 33, D: 33, F: 31 }[letter];
}

function box(lines, width) {
  const top = `┌${'─'.repeat(width + 2)}┐`;
  const bottom = `└${'─'.repeat(width + 2)}┘`;
  // eslint-disable-next-line no-control-regex
  const visible = (s) => s.replace(/\x1b\[[0-9;]*m/g, '').length;
  return [top, ...lines.map((l) => `│ ${l}${' '.repeat(Math.max(0, width - visible(l)))} │`), bottom];
}

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

export function renderTerminal(report, { technical = false, color = false } = {}) {
  const p = painter(color);
  const out = [];
  const g = report.grade;

  out.push('');
  out.push(`  ${p.bold('rattlecheck')} ${p.dim(report.tool.version)}  ${p.dim('rattle every door you own')}`);
  out.push('');
  const card = box(
    [
      `${p.bold('GRADE')}  ${p.code(`1;${gradeCode(g.letter)}`)(g.letter)}  ${p.code(gradeCode(g.letter))(g.label)}`,
      `${plural(report.doors.checked, 'door')} checked, ${report.doors.open === 0 ? p.green('0 open') : p.red(`${report.doors.open} open`)}`,
    ],
    44,
  );
  out.push(...card.map((l) => `  ${l}`));
  out.push('');

  if (report.findings.length === 0) {
    out.push(`  ${p.green('✓')} Nothing open. Every door rattlecheck knows how to check is shut.`);
    out.push('');
  }

  report.findings.forEach((f, i) => {
    const sev = SEV[f.severity];
    out.push(`  ${p.code(`1;${sev.color}`)(sev.label.padEnd(8))} ${p.bold(f.plain)}`);
    out.push(`  ${' '.repeat(8)} ${p.dim('What to do:')} ${f.todo}`);
    if (technical) {
      out.push(`  ${' '.repeat(8)} ${p.dim(`${f.rule} ${f.title}`)}`);
      out.push(`  ${' '.repeat(8)} ${p.dim(f.message)}`);
      if (f.file) out.push(`  ${' '.repeat(8)} ${p.dim(`${f.file}${f.line ? `:${f.line}` : ''}`)}`);
      out.push(`  ${' '.repeat(8)} ${p.dim(`${f.standards.cwe.join(', ')} · NIST 800-53 ${f.standards.nist80053.join(', ')} · CIS ${f.standards.cis.join(', ')}`)}`);
      out.push(`  ${' '.repeat(8)} ${p.dim('Fix:')}`);
      for (const l of f.fix.split('\n')) out.push(`  ${' '.repeat(10)} ${p.cyan(l)}`);
    }
    if (i < report.findings.length - 1) out.push('');
  });

  if (report.findings.length) out.push('');
  if (!technical && report.findings.length) {
    out.push(`  ${p.dim('Run with --technical for file locations and the exact SQL fix for each one.')}`);
    out.push('');
  }

  if (report.allowed.length) {
    out.push(`  ${p.dim(`${plural(report.allowed.length, 'finding')} allowed by rattlecheck.config.json:`)}`);
    for (const a of report.allowed) out.push(`  ${p.dim(`  ${a.rule} ${a.name}: ${a.reason}`)}`);
    out.push('');
  }
  for (const w of report.configWarnings) out.push(`  ${p.yellow('!')} ${w}`);
  if (report.configWarnings.length) out.push('');

  const c = report.coverage;
  out.push(
    `  ${p.dim(`Checked ${plural(c.files, 'migration file')}, ${plural(c.statements, 'statement')}: ${plural(c.tables, 'table')}, ${plural(c.functions, 'function')}. Exposed schemas: ${c.exposedSchemas.join(', ')}.`)}`,
  );
  if (report.live.ran) {
    const l = report.live;
    out.push(
      `  ${p.dim(`Live check (ownership proven by ${l.ownership}): ${plural(l.probed, "table or view", "tables and views")} asked, ${l.open} open, ${l.lockedOrEmpty} locked or empty, ${l.locked} locked, ${l.notExposed} not exposed${l.errors ? `, ${l.errors} errors` : ''}.`)}`,
    );
    if (l.lockedOrEmpty) out.push(`  ${p.dim('"Locked or empty": from outside, an empty table and a locked one look the same.')}`);
    if (l.coverage.complete) {
      out.push(`  ${p.dim(`Table list from the ${l.coverage.source}: ${l.coverage.fromMigrations} from your migrations, ${l.coverage.outsideMigrations} created outside them.`)}`);
    } else {
      out.push(
        `  ${p.yellow('!')} ${p.yellow(`Live check only covered the ${l.coverage.fromMigrations} tables in your migrations. The project wouldn't list its tables (${l.coverage.reason}), so anything created outside migrations, like a backup copy made by hand, was NOT checked. Set SUPABASE_ACCESS_TOKEN to cover everything.`)}`,
      );
    }
  } else {
    out.push(`  ${p.dim('Live check not run. Add --live to test your running project too.')}`);
  }
  if (!c.ok) out.push(`  ${p.red('Coverage failure: migration files were found but no statements could be parsed. The result above cannot be trusted.')}`);
  out.push('');
  return out.join('\n');
}
