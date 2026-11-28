import fs from 'node:fs';
import path from 'node:path';
import { scan, ScanError } from './scan.js';
import { ConfigError, loadConfig } from './config.js';
import { publishProject, renderPublished, PublishFailed } from './publish.js';
import { renderTerminal } from './report/terminal.js';
import { renderSarif } from './report/sarif.js';
import { renderBadge } from './report/badge-svg.js';
import { renderCard } from './report/card-svg.js';
import { ALL_RULES, getRule } from './rules/index.js';
import { VERSION, USER_AGENT } from './version.js';

const HELP = `rattlecheck ${VERSION}: rattle every door you own.

Usage
  rattlecheck [project-folder] [options]
  rattlecheck rules                 list every check
  rattlecheck explain <RULE>        explain one check, e.g. rattlecheck explain RC002
  rattlecheck mcp                   run as an MCP server (stdio) for coding agents

Options
  --technical         file locations, standards, and the exact SQL fix for each finding
  --json              machine-readable report (schema rattlecheck.report/v1)
  --format json       compact findings with high, medium and low counts
  --sarif             SARIF 2.1.0 report, for GitHub code scanning and security tools
  --out <file>        write the --json or --sarif report to a file instead of the screen
  --badge [file]      write a README badge         (default: rattlecheck-badge.svg)
  --card [file]       write a 1200x630 share card  (default: rattlecheck-card.svg)
  --fix-sql [file]    write every suggested fix to one file to review (default: rattlecheck-fixes.sql)
  --live              also check your running project, read-only, after proving it's yours
  --publish           publish a public grade and badge for this project's GitHub repository
                      (the repository must opt in with "publish": true in rattlecheck.config.json)
  --repo <owner/name> the GitHub repository to publish, when it is not the "origin" remote
  --config <file>     config file (default: rattlecheck.config.json in the project folder)
  --no-color          plain text output
  -h, --help          show this help
  -v, --version       show the version

Exit codes
  0  nothing open        1  open door found       2  usage or config error
  3  could not parse     4  live check refused (ownership not proven)
  5  publish refused or failed

rattlecheck never changes your database. Fixes are printed for you to review.`;

function parseArgs(argv) {
  const opts = { root: null, technical: false, json: false, sarif: false, out: null, badge: null, card: null, fixSql: null, live: false, config: null, color: true, publish: false, repo: null };
  const takeOptional = (i, ext, dflt) => {
    const next = argv[i + 1];
    if (next && !next.startsWith('-') && next.toLowerCase().endsWith(ext)) return [next, i + 1];
    return [dflt, i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--technical': opts.technical = true; break;
      case '--json': opts.json = true; break;
      case '--format':
        if (argv[++i] !== 'json') throw new ScanError('--format expects json.');
        opts.json = true;
        opts.compact = true;
        break;
      case '--sarif': opts.sarif = true; break;
      case '--live': opts.live = true; break;
      case '--publish': opts.publish = true; break;
      case '--repo': opts.repo = argv[++i]; if (!opts.repo) throw new ScanError('--repo needs owner/name'); break;
      case '--no-color': opts.color = false; break;
      case '--out': opts.out = argv[++i]; if (!opts.out) throw new ScanError('--out needs a file name'); break;
      case '--config': opts.config = argv[++i]; if (!opts.config) throw new ScanError('--config needs a file name'); break;
      case '--badge': [opts.badge, i] = takeOptional(i, '.svg', 'rattlecheck-badge.svg'); break;
      case '--card': [opts.card, i] = takeOptional(i, '.svg', 'rattlecheck-card.svg'); break;
      case '--fix-sql': [opts.fixSql, i] = takeOptional(i, '.sql', 'rattlecheck-fixes.sql'); break;
      default:
        if (a.startsWith('-')) throw new ScanError(`Unknown option ${a}. Run rattlecheck --help.`);
        if (opts.root) throw new ScanError(`Only one project folder can be checked at a time (got ${opts.root} and ${a}).`);
        opts.root = a;
    }
  }
  if (opts.json && opts.sarif) throw new ScanError('Pick one of --json or --sarif.');
  if (opts.repo && !opts.publish) throw new ScanError('--repo only goes with --publish.');
  return opts;
}

function renderFixSql(report) {
  const lines = [
    `-- Suggested fixes from rattlecheck ${report.tool.version}, ${report.generatedAt}`,
    '-- Review every statement. Put the ones you want in a NEW migration file.',
    '-- rattlecheck never runs these for you.',
    '',
  ];
  for (const f of report.findings) {
    lines.push(`-- ${f.rule} [${f.severity}] ${f.name}${f.detail ? ` (${f.detail})` : ''}`);
    lines.push(`-- ${f.plain}`);
    lines.push(f.fix, '');
  }
  if (!report.findings.length) lines.push('-- Nothing to fix.');
  return `${lines.join('\n')}\n`;
}

function compactReport(report) {
  const severityTier = { critical: 'high', high: 'high', warning: 'medium', medium: 'medium', low: 'low', info: 'low' };
  const summary = { high: 0, medium: 0, low: 0, total: report.findings.length };
  const findings = report.findings.map(finding => {
    const severity = severityTier[finding.severity];
    if (!severity) throw new Error('Unknown finding severity: ' + finding.severity);
    summary[severity]++;
    return { ruleId: finding.rule, severity, file: finding.file ?? null, line: finding.line ?? null,
      message: finding.message, suggestion: finding.todo };
  });
  return { version: report.tool.version, summary, findings, checked: report.doors.checked, coverageOK: report.coverage.ok };
}

function explain(rule) {
  return [
    `${rule.id}  ${rule.title}`,
    `Severity: ${rule.severity}${rule.live ? '   (live check, runs with --live)' : ''}`,
    '',
    rule.summary,
    '',
    `Standards: ${rule.standards.cwe.join(', ')} | NIST SP 800-53 ${rule.standards.nist80053.join(', ')} | CIS Controls v8 ${rule.standards.cis.join(', ')}`,
  ].join('\n');
}

export async function main(argv, { stdout = process.stdout, stderr = process.stderr, env = process.env, fetchImpl = globalThis.fetch, git } = {}) {
  try {
    if (argv.includes('-h') || argv.includes('--help')) {
      stdout.write(`${HELP}\n`);
      return 0;
    }
    if (argv.includes('-v') || argv.includes('--version')) {
      stdout.write(`${VERSION}\n`);
      return 0;
    }
    if (argv[0] === 'mcp') {
      const { runMcpServer } = await import('./mcp/server.js');
      await runMcpServer();
      return null; // stays running
    }
    if (argv[0] === 'rules') {
      for (const r of ALL_RULES) stdout.write(`${r.id}  ${r.severity.padEnd(8)}  ${r.title}${r.live ? '  (--live)' : ''}\n`);
      return 0;
    }
    if (argv[0] === 'explain') {
      const rule = getRule(argv[1]);
      if (!rule) throw new ScanError(`No rule called ${argv[1] ?? '(none)'}. Run rattlecheck rules to see them all.`);
      stdout.write(`${explain(rule)}\n`);
      return 0;
    }

    const opts = parseArgs(argv);
    const root = path.resolve(opts.root ?? '.');
    const report = await scan({ root, live: opts.live, configPath: opts.config, env });

    const written = [];
    const write = (file, content) => {
      const p = path.resolve(file);
      fs.writeFileSync(p, content);
      const rel = path.relative(process.cwd(), p);
      written.push(rel && !rel.startsWith('..') ? rel : p);
    };
    if (opts.badge) write(opts.badge, renderBadge(report));
    if (opts.card) write(opts.card, renderCard(report));
    if (opts.fixSql) write(opts.fixSql, renderFixSql(report));

    if (opts.json || opts.sarif) {
      const output = opts.compact ? compactReport(report) : opts.json ? report : renderSarif(report);
      const body = `${JSON.stringify(output, null, 2)}\n`;
      if (opts.out) write(opts.out, body);
      else stdout.write(body);
    } else {
      const color = opts.color && !env.NO_COLOR && Boolean(stdout.isTTY);
      stdout.write(renderTerminal(report, { technical: opts.technical, color }));
    }
    for (const w of written) (opts.json || opts.sarif ? stderr : stdout).write(`  wrote ${w}\n`);
    if (written.length && !(opts.json || opts.sarif)) stdout.write('\n');

    if (opts.publish) {
      // Consent is read from the top of the repository, as the service reads it.
      const consent = ({ dir, top }) => {
        const rootConfig = loadConfig(dir ? top : root, dir ? undefined : opts.config);
        return dir
          ? { optedIn: rootConfig.publishDirs.includes(dir), hint: `Add "publishDirs": ["${dir}"] to rattlecheck.config.json at the top of the repository.` }
          : { optedIn: rootConfig.publish, hint: 'Add "publish": true to rattlecheck.config.json.' };
      };
      const published = await publishProject({ root, consent, repo: opts.repo, env, fetchImpl, git, userAgent: USER_AGENT });
      (opts.json || opts.sarif ? stderr : stdout).write(renderPublished(published, report.grade.letter));
    }

    if (!report.coverage.ok) return 3;
    if (stdout.isTTY && !env.CI && !opts.json && !opts.sarif && report.doors.checked > 0) {
      stdout.write('Did this check change your migration? You can share the outcome publicly on GitHub.\n');
      stdout.write('https://github.com/chaseakub/rattlecheck/issues/new?template=migration-review.yml\n');
    }
    return report.counts.critical + report.counts.high > 0 ? 1 : 0;
  } catch (e) {
    if (e instanceof ScanError || e instanceof ConfigError || e instanceof PublishFailed) {
      stderr.write(`rattlecheck: ${e.message}\n`);
      return e.code ?? 2;
    }
    throw e;
  }
}
