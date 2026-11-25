// The publish service: it grades a repository itself, only with the
// repository's consent, and never says which door is open.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { handle, addressKey } from '../service/src/worker.js';
import { readTarGz, TarError } from '../service/src/tar.js';
import { parseTarget, keyFor, PublishError } from '../service/src/publish.js';

const SHA = 'a'.repeat(40);

function tarEntry(name, body, type = '0') {
  const data = Buffer.from(body);
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0);
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  h.write('ustar\0' + '00', 257);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}
const pax = (records) => Object.entries(records).map(([k, v]) => { const body = ` ${k}=${v}\n`; let len = body.length + 1; while (String(len).length + body.length !== len) len = String(len).length + body.length; return `${len}${body}`; }).join('');

/** A GitHub-shaped .tar.gz: one top folder, a global header carrying the commit. */
function tarball(files, { top = 'repo-HEAD', commit = SHA } = {}) {
  const parts = [tarEntry('pax_global_header', pax({ comment: commit }), 'g'), tarEntry(`${top}/`, '', '5')];
  for (const [name, body] of Object.entries(files)) {
    const full = `${top}/${name}`;
    if (full.length > 100) parts.push(tarEntry('PaxHeader', pax({ path: full }), 'x'), tarEntry(full.slice(0, 100), body));
    else parts.push(tarEntry(full, body));
  }
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts));
}

function world(repos, { attributes = {}, repoLimit = Infinity } = {}) {
  const kv = new Map();
  const writes = [];
  const seen = new Map();
  const env = {
    GRADES: {
      get: async (k, type) => (kv.has(k) ? (type === 'json' ? JSON.parse(kv.get(k)) : kv.get(k)) : null),
      put: async (k, v) => { writes.push(`put ${k}`); kv.set(k, v); },
      delete: async (k) => { writes.push(`delete ${k}`); kv.delete(k); },
    },
    REPO_LIMITER: { limit: async ({ key }) => { seen.set(key, (seen.get(key) ?? 0) + 1); return { success: seen.get(key) <= repoLimit }; } },
  };
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const raw = /^https:\/\/raw\.githubusercontent\.com\/([^/]+\/[^/]+)\/[0-9a-f]{40}\/(.*)$/.exec(url);
    if (raw) return attributes[raw[2]] === undefined ? new Response('', { status: 404 }) : new Response(attributes[raw[2]], { status: 200 });
    const m = /^https:\/\/codeload\.github\.com\/([^/]+\/[^/]+)\/tar\.gz\/HEAD$/.exec(url);
    const body = m && repos[m[1]];
    if (!body) return new Response('Not Found', { status: 404 });
    return new Response(body, { status: 200 });
  };
  const post = (payload, headers = { 'Content-Type': 'application/json' }) =>
    handle(new Request('https://grade.test/api/publish', { method: 'POST', headers, body: typeof payload === 'string' ? payload : JSON.stringify(payload) }), env, { fetchImpl, now: () => new Date('2026-11-24T12:00:00Z') });
  const get = (path) => handle(new Request(`https://grade.test${path}`), env, { fetchImpl });
  const downloads = () => calls.filter((u) => u.includes('codeload')).length;
  return { kv, calls, writes, post, get, downloads, env };
}

const OPEN = `create table public.customer_secrets (id int);\ncreate function public.leak_everything(uid uuid) returns int language sql security definer set search_path = '' as $$ select 1 $$;`;
const LOCKED = `create table public.notes (id int);\nalter table public.notes enable row level security;`;
const OPTED_IN = JSON.stringify({ publish: true });

test('an opted-in repository is graded by the service and the record never names a door', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/0001_init.sql': OPEN, 'README.md': 'hi' }) });
  const res = await w.post({ repo: 'acme/shop' });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.grade.letter, 'F');
  assert.equal(body.commit, SHA);
  assert.equal(body.fresh, true);
  assert.deepEqual(body.counts, { critical: 2, high: 0, warning: 0 });
  assert.equal(body.page, 'https://grade.test/r/acme/shop');
  assert.equal(body.badge, 'https://grade.test/badge/acme/shop.svg');
  const stored = w.kv.get(keyFor('acme', 'shop', ''));
  for (const secret of ['customer_secrets', 'leak_everything', 'findings', '0001_init']) {
    assert.ok(!JSON.stringify(body).includes(secret), `response leaks ${secret}`);
    assert.ok(!stored.includes(secret), `record leaks ${secret}`);
  }
  const page = await (await w.get('/r/acme/shop')).text();
  assert.match(page, /2 doors open\./);
  assert.ok(!page.includes('customer_secrets') && !page.includes('leak_everything'));
  const badge = await w.get('/badge/acme/shop.svg');
  assert.equal(badge.headers.get('content-type'), 'image/svg+xml; charset=utf-8');
  assert.match(await badge.text(), /rattlecheck: F/);
});

test('a locked project grades A, and its exceptions are counted in the open', async () => {
  const config = JSON.stringify({ publish: true, allow: [{ rule: 'RC001', object: 'public.menu', reason: 'The menu is public on the website.' }] });
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': config, 'supabase/migrations/1.sql': `${LOCKED}\ncreate table public.menu (id int);` }) });
  const body = await (await w.post({ repo: 'acme/shop' })).json();
  assert.equal(body.grade.letter, 'A');
  assert.equal(body.exceptions, 1);
  assert.match(await (await w.get('/r/acme/shop')).text(), /<b>1<\/b><span>open on purpose<\/span>/);
});

test('nothing a caller sends can set the grade', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': OPEN }) });
  const body = await (await w.post({ repo: 'acme/shop', grade: { letter: 'A' }, counts: { critical: 0 }, commit: 'f'.repeat(40) })).json();
  assert.equal(body.grade.letter, 'F');
  assert.equal(body.commit, SHA);
});

test('a repository that has not opted in is refused, and nothing is stored', async () => {
  for (const files of [{ 'supabase/migrations/1.sql': OPEN }, { 'rattlecheck.config.json': '{}', 'supabase/migrations/1.sql': OPEN }, { 'rattlecheck.config.json': '{"publish": false}', 'supabase/migrations/1.sql': OPEN }]) {
    const w = world({ 'acme/shop': tarball(files) });
    const res = await w.post({ repo: 'acme/shop' });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, 'not_opted_in');
    assert.equal(w.kv.has(keyFor('acme', 'shop', '')), false);
    assert.equal((await w.get('/r/acme/shop')).status, 404);
  }
});

test('removing the opt-in takes the published grade down at the next check', async () => {
  const repos = { 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) };
  const w = world(repos);
  assert.equal((await w.post({ repo: 'acme/shop' })).status, 200);
  assert.equal((await w.get('/r/acme/shop')).status, 200);
  repos['acme/shop'] = tarball({ 'supabase/migrations/1.sql': LOCKED });
  assert.equal((await w.post({ repo: 'acme/shop' })).status, 403);
  assert.equal((await w.get('/r/acme/shop')).status, 404);
  assert.match(await (await w.get('/badge/acme/shop.svg')).text(), /rattlecheck: none/);
});

test('a private or missing repository is a 404, and a broken config is a 422', async () => {
  const w = world({ 'acme/bad': tarball({ 'rattlecheck.config.json': '{publish', 'supabase/migrations/1.sql': LOCKED }), 'acme/empty': tarball({ 'rattlecheck.config.json': OPTED_IN }) });
  assert.equal((await w.post({ repo: 'acme/private' })).status, 404);
  assert.equal((await w.post({ repo: 'acme/bad' })).status, 422);
  const empty = await w.post({ repo: 'acme/empty' });
  assert.equal(empty.status, 422);
  assert.equal((await empty.json()).error, 'no_migrations');
});

test('past a few checks a minute for one repository, the last answer is returned and nothing is fetched', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) }, { repoLimit: 1 });
  await w.post({ repo: 'acme/shop' });
  const again = await (await w.post({ repo: 'Acme/Shop' })).json();
  assert.equal(again.fresh, false);
  assert.equal(again.grade.letter, 'A');
  // Naming another folder does not buy another download of the same repository.
  assert.equal((await w.post({ repo: 'acme/shop', dir: 'somewhere/else' })).status, 429);
  assert.equal(w.downloads(), 1);
});

test('a project in a subfolder is graded on its own page, when the top of the repository says so', async () => {
  const files = { 'rattlecheck.config.json': JSON.stringify({ publishDirs: ['apps/api'] }), 'apps/api/supabase/migrations/1.sql': LOCKED, 'supabase/migrations/1.sql': OPEN };
  const w = world({ 'acme/mono': tarball(files) });
  const body = await (await w.post({ repo: 'acme/mono', dir: 'apps/api/' })).json();
  assert.equal(body.grade.letter, 'A');
  assert.equal(body.page, 'https://grade.test/r/acme/mono?dir=apps%2Fapi');
  assert.equal((await w.get('/r/acme/mono?dir=apps/api')).status, 200);
  // The root never opted in, so it has no page, whatever its migrations say.
  assert.equal((await w.get('/r/acme/mono')).status, 404);
  assert.equal((await w.post({ repo: 'acme/mono' })).status, 403);
});

test('a config inside a folder cannot opt that folder in: a vendored copy does not speak for the repository', async () => {
  const w = world({ 'victim/app': tarball({ 'vendor/thing/examples/demo/rattlecheck.config.json': OPTED_IN, 'vendor/thing/examples/demo/supabase/migrations/1.sql': OPEN }) });
  const res = await w.post({ repo: 'victim/app', dir: 'vendor/thing/examples/demo' });
  assert.equal(res.status, 403);
  assert.match((await res.json()).message, /"publishDirs": \["vendor\/thing\/examples\/demo"\]/);
  assert.equal(w.kv.size, 0);
});

test('only the migrations folder is read, in the order the command line reads it', async () => {
  const w = world({
    'acme/shop': tarball({
      'rattlecheck.config.json': OPTED_IN,
      'supabase/migrations/0002_lock.sql': 'alter table public.t enable row level security;',
      'supabase/migrations/0001_make.sql': 'create table public.t (id int);',
      'supabase/migrations/archive/old.sql': OPEN,
      'docs/example.sql': OPEN,
      'supabase/seed.sql': OPEN,
    }),
  });
  const body = await (await w.post({ repo: 'acme/shop' })).json();
  assert.equal(body.grade.letter, 'A');
  assert.equal(body.coverage.files, 2);
});

test('repository and folder names are validated before anything is fetched', async () => {
  const w = world({});
  for (const bad of [{ repo: 'acme' }, { repo: 'acme/shop/extra' }, { repo: '../etc/passwd' }, { repo: 'acme/<script>' }, { repo: 'acme/shop', dir: '../other' }, { repo: 'acme/shop', dir: 'a/../../b' }, { repo: 'acme/shop', dir: 'a b' }, { repo: '-acme/shop' }, {}]) {
    const res = await w.post(bad);
    assert.equal(res.status, 400, JSON.stringify(bad));
  }
  assert.equal((await w.post('not json')).status, 400);
  assert.equal(w.calls.length, 0);
  assert.throws(() => parseTarget({ repo: 'acme/..' }), PublishError);
  assert.equal(parseTarget({ repo: 'Acme/Shop.git', dir: './apps/api/' }).key, 'v1:acme/shop:apps/api');
});

test('pages carry no script and set a strict content policy', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) });
  await w.post({ repo: 'acme/shop' });
  for (const path of ['/', '/r/acme/shop', '/r/acme/none', '/nope']) {
    const res = await w.get(path);
    assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
    const body = await res.text();
    assert.ok(!/<script/i.test(body), path);
    assert.ok(!/[–—]/.test(body), `${path} has a dash character`);
  }
  assert.equal((await handle(new Request('https://grade.test/api/publish'), {}, {})).status, 405);
  assert.match(await (await w.get('/r/acme/shop')).text(), /API schemas checked: <span class="mono">public, graphql_public<\/span>/);
  assert.equal((await handle(new Request('https://grade.test/r/acme/shop', { method: 'DELETE' }), {}, {})).status, 405);
});

test('the tar reader keeps only what was asked for and enforces its caps', async () => {
  const long = `supabase/migrations/${'x'.repeat(120)}.sql`;
  const gz = tarball({ 'a.sql': 'select 1;', [long]: 'select 2;', 'big.bin': 'z'.repeat(5000) });
  const stream = () => new Response(gz).body;
  const all = await readTarGz(stream(), { want: (p) => p.endsWith('.sql'), maxUnpackedBytes: 1e6, maxKeptBytes: 1e6, maxKeptFiles: 10 });
  assert.deepEqual([...all.files.keys()].sort(), ['a.sql', long].sort());
  assert.equal(all.files.get(long), 'select 2;');
  assert.equal(all.commit, SHA);
  await assert.rejects(readTarGz(stream(), { want: () => true, maxUnpackedBytes: 1e6, maxKeptBytes: 100, maxKeptFiles: 10 }), TarError);
  await assert.rejects(readTarGz(stream(), { want: () => true, maxUnpackedBytes: 1e6, maxKeptBytes: 1e6, maxKeptFiles: 1 }), TarError);
  await assert.rejects(readTarGz(stream(), { want: () => false, maxUnpackedBytes: 2000, maxKeptBytes: 1e6, maxKeptFiles: 10 }), TarError);
  await assert.rejects(readTarGz(new Response(gz.subarray(0, gz.length - 40)).body, { want: () => true, maxUnpackedBytes: 1e6, maxKeptBytes: 1e6, maxKeptFiles: 10 }));
});

test('an oversized repository is refused, not half checked', async () => {
  const w = world({ 'acme/huge': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': `-- ${'x'.repeat(17 * 1024 * 1024)}\n${LOCKED}` }) });
  const res = await w.post({ repo: 'acme/huge' });
  assert.equal(res.status, 413);
  assert.equal(w.kv.has(keyFor('acme', 'huge', '')), false);
});

// ── From the security review of the first version ───────────────────────

test('the settings that change what counts as reachable are not taken from the project', async () => {
  for (const extra of [{ exposedSchemas: [] }, { exposedSchemas: ['nope'] }, { defaults: 'clean' }, { migrationRoles: ['someone'] }]) {
    const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': JSON.stringify({ publish: true, ...extra }), 'supabase/migrations/1.sql': OPEN }) });
    const body = await (await w.post({ repo: 'acme/shop' })).json();
    assert.equal(body.grade.letter, 'F', JSON.stringify(extra));
  }
});

test('a repository that hides files from its archive is refused', async () => {
  const repos = { 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) };
  for (const where of ['.gitattributes', 'supabase/.gitattributes', 'supabase/migrations/.gitattributes']) {
    const w = world(repos, { attributes: { [where]: '# notes\nsupabase/migrations/0002_bad.sql export-ignore\n' } });
    const res = await w.post({ repo: 'acme/shop' });
    assert.equal(res.status, 422, where);
    assert.equal((await res.json()).error, 'export_ignore');
    assert.equal(w.kv.size, 0);
  }
  const harmless = world(repos, { attributes: { '.gitattributes': '# export-ignore is not used here\n*.sql text eol=lf\n' } });
  assert.equal((await harmless.post({ repo: 'acme/shop' })).status, 200);
});

test('a grade does not outlive what it described', async () => {
  const good = tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED });
  const cases = {
    'gone private or deleted': [undefined, 404],
    'grown past the size cap': [tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED, 'supabase/migrations/2.sql': `${OPEN}\n-- ${'x'.repeat(2 * 1024 * 1024)}` }), 413],
    'lost its migrations': [tarball({ 'rattlecheck.config.json': OPTED_IN }), 422],
    'broken its config': [tarball({ 'rattlecheck.config.json': '{', 'supabase/migrations/1.sql': LOCKED }), 422],
  };
  for (const [name, [next, status]] of Object.entries(cases)) {
    const repos = { 'acme/shop': good };
    const w = world(repos);
    assert.equal((await w.post({ repo: 'acme/shop' })).status, 200);
    if (next) repos['acme/shop'] = next;
    else delete repos['acme/shop'];
    assert.equal((await w.post({ repo: 'acme/shop' })).status, status, name);
    assert.equal((await w.get('/r/acme/shop')).status, 404, name);
  }
});

test('a check that publishes nothing writes nothing', async () => {
  const w = world({ 'acme/shop': tarball({ 'supabase/migrations/1.sql': OPEN }) });
  await w.post({ repo: 'acme/shop' });
  await w.post({ repo: 'acme/missing' });
  await w.post({ repo: 'acme/shop', dir: 'nowhere' });
  assert.deepEqual(w.writes, []);
});

test('config errors never quote the config back', async () => {
  const config = JSON.stringify({ publish: true, allow: [{ rule: 'RC001', object: 'public.customer_secrets', reason: 'x' }] });
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': config, 'supabase/migrations/1.sql': OPEN }) });
  const res = await w.post({ repo: 'acme/shop' });
  assert.equal(res.status, 422);
  assert.ok(!(await res.text()).includes('customer_secrets'));
});

test('too many statements is refused before the model can eat the memory', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': 'select 1;\n'.repeat(20000) }) });
  const res = await w.post({ repo: 'acme/shop' });
  assert.equal(res.status, 413);
});

test('only small JSON bodies are read, and only as JSON', async () => {
  const w = world({});
  assert.equal((await w.post({ repo: 'acme/shop' }, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await w.post({ repo: 'acme/shop' }, {})).status, 415);
  assert.equal((await w.post(JSON.stringify({ repo: 'acme/shop', pad: 'x'.repeat(5000) }))).status, 413);
  let pulled = 0;
  const endless = new ReadableStream({ pull(c) { pulled++; c.enqueue(new Uint8Array(1024)); } });
  const res = await handle(new Request('https://grade.test/api/publish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: endless, duplex: 'half' }), w.env, {});
  assert.equal(res.status, 413);
  assert.ok(pulled < 20, `read ${pulled} KB of a body that should have been cut off`);
  assert.equal(w.calls.length, 0);
});

test('checks run one at a time, and rate limits are keyed so they cannot be sidestepped', async () => {
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) });
  const all = await Promise.all(Array.from({ length: 6 }, () => w.post({ repo: 'acme/shop' })));
  assert.deepEqual(all.map((r) => r.status), Array(6).fill(200));
  assert.equal(addressKey('2001:db8:1:2:aaaa::1'), addressKey('2001:db8:1:2:bbbb::9'));
  assert.notEqual(addressKey('2001:db8:1:2::1'), addressKey('2001:db8:1:3::1'));
  assert.equal(addressKey('203.0.113.7'), '203.0.113.7');
});

test('a repository called something.svg still has a page', async () => {
  const w = world({ 'acme/logo.svg': tarball({ 'rattlecheck.config.json': OPTED_IN, 'supabase/migrations/1.sql': LOCKED }) });
  const body = await (await w.post({ repo: 'acme/logo.svg' })).json();
  assert.equal((await w.get('/r/acme/logo.svg')).status, 200);
  assert.match(await (await w.get('/badge/acme/logo.svg.svg')).text(), /rattlecheck: A/);
  assert.equal(body.badge, 'https://grade.test/badge/acme/logo.svg.svg');
});

test('the public grade respects private-column declarations without publishing the field name', async () => {
  const config = JSON.stringify({ publish: true, privateColumns: { 'public.directory': ['draft_budget'] } });
  const schema = 'create table public.directory (id int, draft_budget int); alter table public.directory enable row level security; create policy browse on public.directory for select to anon using (true);';
  const w = world({ 'acme/shop': tarball({ 'rattlecheck.config.json': config, 'supabase/migrations/1.sql': schema }) });
  const res = await w.post({ repo: 'acme/shop' });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.counts.high, 1);
  assert.equal(body.grade.letter, 'C');
  assert.ok(!JSON.stringify(body).includes('draft_budget'));
});
