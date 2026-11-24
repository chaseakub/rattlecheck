// rattlecheck --publish: sends the repository name, never the local result.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main } from '../src/cli.js';
import { parseGitHubRemote, PUBLISH_SERVICE } from '../src/publish.js';
import { parseConfig, ConfigError } from '../src/config.js';
import { scanStatic } from '../src/core.js';
import { parseExposedSchemas } from '../src/model.js';

function project(config, sub = '') {
  const top = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-publish-'));
  const root = path.join(top, sub);
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '1.sql'), 'create table public.t (id int); alter table public.t enable row level security;');
  if (config) fs.writeFileSync(path.join(top, 'rattlecheck.config.json'), JSON.stringify(config));
  return { top, root };
}

async function run(args, { config, remote = 'git@github.com:acme/shop.git', prefix = '', head = 'b'.repeat(40), answer } = {}) {
  const { top, root } = project(config, prefix);
  const out = [];
  const err = [];
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    const a = answer ?? { status: 200, body: { owner: 'acme', repo: 'shop', dir: prefix.replace(/\/$/, ''), commit: head, grade: { letter: 'A', label: 'Locked tight' }, fresh: true, page: 'https://s.test/r/acme/shop', markdown: '[![rattlecheck](https://s.test/badge/acme/shop.svg)](https://s.test/r/acme/shop)' } };
    return new Response(JSON.stringify(a.body), { status: a.status });
  };
  const git = (_root, a) => {
    if (a[0] === 'remote') { if (!remote) throw new Error('no remote'); return remote; }
    if (a.join(' ') === 'rev-parse --show-prefix') return prefix;
    if (a.join(' ') === 'rev-parse HEAD') return head;
    if (a.join(' ') === 'rev-parse --show-toplevel') return top;
    throw new Error('unexpected git call');
  };
  try {
    const code = await main([root, '--no-color', ...args], { stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) }, env: {}, fetchImpl, git });
    return { code, out: out.join(''), err: err.join(''), sent };
  } finally {
    fs.rmSync(top, { recursive: true, force: true });
  }
}

test('--publish sends only the repository and folder, and prints the page and badge', async () => {
  const r = await run(['--publish'], { config: { publishDirs: ['apps/api'] }, prefix: 'apps/api/' });
  assert.equal(r.code, 0);
  assert.deepEqual(r.sent, [{ url: `${PUBLISH_SERVICE}/api/publish`, body: { repo: 'acme/shop', dir: 'apps/api' } }]);
  assert.match(r.out, /Published {2}acme\/shop \(apps\/api\): grade A \(Locked tight\)/);
  assert.match(r.out, /Page {7}https:\/\/s\.test\/r\/acme\/shop/);
  assert.match(r.out, /Badge {6}\[!\[rattlecheck\]/);
});

test('--publish refuses before any request when the project has not opted in', async () => {
  for (const config of [undefined, {}, { publish: false }]) {
    const r = await run(['--publish'], { config });
    assert.equal(r.code, 2);
    assert.equal(r.sent.length, 0);
    assert.match(r.err, /has not opted in.*"publish": true/);
  }
  // A project in a subfolder is opted in from the top of the repository, by name.
  for (const config of [{ publish: true }, { publishDirs: ['apps/web'] }]) {
    const r = await run(['--publish'], { config, prefix: 'apps/api/' });
    assert.equal(r.code, 2);
    assert.equal(r.sent.length, 0);
    assert.match(r.err, /"publishDirs": \["apps\/api"\]/);
  }
});

test('--publish needs a GitHub remote, or --repo', async () => {
  const gitlab = await run(['--publish'], { config: { publish: true }, remote: 'git@gitlab.com:acme/shop.git' });
  assert.equal(gitlab.code, 2);
  assert.match(gitlab.err, /not a GitHub repository/);
  const secret = await run(['--publish'], { config: { publish: true }, remote: 'https://user:glpat-SECRET@gitlab.com/acme/shop.git' });
  assert.ok(!secret.err.includes('glpat-SECRET'), 'a token in the remote URL must not be printed');
  const none = await run(['--publish'], { config: { publish: true }, remote: null });
  assert.equal(none.code, 2);
  const named = await run(['--publish', '--repo', 'other/thing'], { config: { publish: true }, remote: null });
  assert.equal(named.code, 0);
  assert.equal(named.sent[0].body.repo, 'other/thing');
  assert.equal((await run(['--repo', 'a/b'], { config: { publish: true } })).code, 2);
});

test('a refusal from the service is shown, and exits 5', async () => {
  const r = await run(['--publish'], { config: { publish: true }, answer: { status: 404, body: { error: 'not_found', message: "No public GitHub repository called acme/shop. Private repositories can't be published." } } });
  assert.equal(r.code, 5);
  assert.match(r.err, /Not published: No public GitHub repository called acme\/shop/);
});

test('--publish says so when the published commit is not the local one', async () => {
  const r = await run(['--publish'], { config: { publish: true }, answer: { status: 200, body: { owner: 'acme', repo: 'shop', dir: '', commit: 'c'.repeat(40), grade: { letter: 'F', label: 'Wide open' }, fresh: true, page: 'p', markdown: 'm' } } });
  assert.match(r.out, /grade is for commit ccccccc.*Your checkout is at bbbbbbb/);
});

test('GitHub remotes are recognised in every usual spelling, and nothing else is', () => {
  for (const url of ['git@github.com:acme/shop.git', 'https://github.com/acme/shop.git', 'https://github.com/acme/shop', 'https://x-access-token@github.com/acme/shop/', 'ssh://git@github.com/acme/shop.git']) {
    assert.equal(parseGitHubRemote(url), 'acme/shop', url);
  }
  for (const url of ['git@gitlab.com:acme/shop.git', 'https://github.com.evil.test/acme/shop', 'https://evil.test/github.com/acme/shop', 'https://github.com/acme', '']) {
    assert.equal(parseGitHubRemote(url), null, url);
  }
});

test('config text is validated the same way without a file system', () => {
  assert.equal(parseConfig('{"publish": true}').publish, true);
  assert.equal(parseConfig('{}').publish, false);
  assert.throws(() => parseConfig('{"publish": "yes"}'), ConfigError);
  assert.throws(() => parseConfig('[]'), ConfigError);
  assert.throws(() => parseConfig('{'), ConfigError);
  assert.deepEqual(parseConfig('{"publishDirs": ["./apps/api/", "x"]}').publishDirs, ['apps/api', 'x']);
  assert.throws(() => parseConfig('{"publishDirs": "apps/api"}'), ConfigError);
});

test('scanStatic grades migration text directly, and reads exposed schemas from config.toml text', () => {
  const r = scanStatic({ migrations: [{ file: '1.sql', sql: 'create table api.t (id int); grant all on api.t to anon;' }], exposedSchemas: parseExposedSchemas('[api]\nschemas = ["api"]\n') });
  assert.equal(r.grade.letter, 'F');
  assert.equal(r.findings[0].file, 'supabase/migrations/1.sql');
  assert.deepEqual(parseExposedSchemas('[db]\nport = 1\n'), ['public', 'graphql_public']);
});
