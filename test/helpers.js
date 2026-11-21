import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';

/** Write migrations (and optional config) to a temp project and scan it. */
export async function scanSql(files, { config, ...opts } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-test-'));
  const dir = path.join(root, 'supabase', 'migrations');
  fs.mkdirSync(dir, { recursive: true });
  const list = typeof files === 'string' ? { '0001_init.sql': files } : files;
  for (const [name, sql] of Object.entries(list)) fs.writeFileSync(path.join(dir, name), sql);
  if (config) fs.writeFileSync(path.join(root, 'rattlecheck.config.json'), JSON.stringify(config));
  try {
    return await scan({ root, env: {}, ...opts });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

export const ids = (report) => report.findings.map((f) => `${f.rule} ${f.name}`).sort();
