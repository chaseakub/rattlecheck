// Grades one public GitHub repository and stores the result.
//
// Three rules hold this together:
//   1. The service does the check itself, from the repository's own files at
//      a commit. Nothing a caller sends can change the grade.
//   2. A repository is only ever graded when the rattlecheck.config.json at
//      its top says so: "publish": true for the repository itself, or the
//      folder named in "publishDirs". Committing that line is the consent.
//      Remove it, and the next check deletes the published grade.
//   3. The stored record holds the grade and the counts. Never which table or
//      function is open: a failing page must not be a map.
import { scanStatic } from '../../src/core.js';
import { BudgetError } from '../../src/model.js';
import { parseConfig, ConfigError } from '../../src/config.js';
import { parseExposedSchemas } from '../../src/model.js';
import { readTarGz, TarError } from './tar.js';

// Every cap is sized for a 128 MB isolate. Measured: one megabyte of SQL can
// cost the scanner about 70 MB while it builds its model, so a megabyte of
// migrations is the most this service takes on. Larger projects still get the
// same check from `npx rattlecheck` on their own machine.
export const LIMITS = {
  downloadBytes: 60 * 1024 * 1024,
  unpackedBytes: 400 * 1024 * 1024,
  keptBytes: 1024 * 1024,
  keptFiles: 1000,
  statements: 15000,
  attributeFiles: 12,
};

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
const SEGMENT = /^[A-Za-z0-9._-]{1,100}$/;

export class PublishError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Validates and normalises { repo: "owner/name", dir?: "apps/api" }. */
export function parseTarget(input) {
  const repoText = String(input?.repo ?? '').trim().replace(/\.git$/, '');
  const parts = repoText.split('/');
  if (parts.length !== 2 || !OWNER.test(parts[0]) || !REPO.test(parts[1]) || parts[1] === '.' || parts[1] === '..') {
    throw new PublishError(400, 'bad_repo', 'Give the repository as owner/name, for example acme/shop.');
  }
  const dirText = String(input?.dir ?? '').trim().replace(/^\.?\/+|\/+$/g, '');
  const segments = dirText ? dirText.split('/') : [];
  if (segments.length > 8 || segments.some((s) => !SEGMENT.test(s) || s === '.' || s === '..')) {
    throw new PublishError(400, 'bad_dir', 'The folder must be a plain path inside the repository, for example apps/api.');
  }
  const owner = parts[0];
  const repo = parts[1];
  const dir = segments.join('/');
  return { owner, repo, dir, key: keyFor(owner, repo, dir) };
}

// GitHub names are case-insensitive; folders are not.
export const keyFor = (owner, repo, dir) => `v1:${owner.toLowerCase()}/${repo.toLowerCase()}${dir ? `:${dir}` : ''}`;

const OPT_IN_ROOT = 'Add "publish": true to rattlecheck.config.json at the top of the repository, commit it, push it, and run this again.';
const OPT_IN_DIR = (dir) => `Add "publishDirs": ["${dir}"] to rattlecheck.config.json at the top of the repository, commit it, push it, and run this again.`;

// Checks hold megabytes of text and a model built from it. One at a time per
// isolate, so several requests can't add up past the memory limit.
let queue = Promise.resolve();
const oneAtATime = (work) => {
  const run = queue.then(work, work);
  queue = run.catch(() => {});
  return run;
};

// Counts the compressed bytes actually received: GitHub does not always say
// how long the archive is.
function capped(stream, maxBytes) {
  let seen = 0;
  return stream.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > maxBytes) controller.error(new TarError('The repository is too large to check.'));
        else controller.enqueue(chunk);
      },
    }),
  );
}

/**
 * @param {{owner:string, repo:string, dir:string, key:string}} target
 * @param {object} deps
 * @param {{get:Function, put:Function, delete:Function}} deps.store   KV-shaped
 * @param {Function} deps.fetchImpl
 * @param {string} deps.version   rattlecheck version doing the check
 * @param {() => Date} [deps.now]
 */
export function publish(target, deps) {
  return oneAtATime(() => check(target, deps));
}

async function check(target, { store, fetchImpl, version, now = () => new Date() }) {
  const { owner, repo, dir, key } = target;
  const headers = { 'User-Agent': `rattlecheck-publish/${version}` };

  // A grade must not outlive what it described. When a check reaches a firm
  // answer that is not a grade, whatever was published before comes down.
  const takeDown = async () => {
    if (await store.get(key)) await store.delete(key);
  };
  const refuse = async (status, code, message) => {
    await takeDown();
    return new PublishError(status, code, message);
  };

  let res;
  try {
    res = await fetchImpl(`https://codeload.github.com/${owner}/${repo}/tar.gz/HEAD`, { headers, redirect: 'follow' });
  } catch {
    throw new PublishError(502, 'github_unreachable', 'GitHub could not be reached. Try again in a minute.');
  }
  if (res.status === 404) {
    throw await refuse(404, 'not_found', `No public GitHub repository called ${owner}/${repo}. Private repositories can't be published.`);
  }
  if (!res.ok || !res.body) throw new PublishError(502, 'github_error', `GitHub answered ${res.status}. Try again in a minute.`);
  if (Number(res.headers.get('content-length') ?? 0) > LIMITS.downloadBytes) {
    throw await refuse(413, 'too_large', 'The repository is too large to check.');
  }

  const base = dir ? `${dir}/` : '';
  const isSql = (name) => name.endsWith('.sql') && !name.includes('/');
  const want = (p) => {
    // The root config carries the consent, whichever folder is being checked.
    if (p === 'rattlecheck.config.json') return true;
    if (!p.startsWith(base)) return false;
    const rel = p.slice(base.length);
    if (rel === 'rattlecheck.config.json' || rel === 'supabase/config.toml') return true;
    if (rel.startsWith('supabase/migrations/')) return isSql(rel.slice('supabase/migrations/'.length));
    if (rel.startsWith('migrations/')) return isSql(rel.slice('migrations/'.length));
    return false;
  };

  let archive;
  try {
    archive = await readTarGz(capped(res.body, LIMITS.downloadBytes), { want, maxUnpackedBytes: LIMITS.unpackedBytes, maxKeptBytes: LIMITS.keptBytes, maxKeptFiles: LIMITS.keptFiles });
  } catch (e) {
    if (e instanceof TarError) {
      throw await refuse(413, 'too_large', `${e.message} The public service takes up to 1 MB of migrations; run npx rattlecheck on your own machine for a larger project.`);
    }
    throw new PublishError(502, 'bad_archive', 'GitHub sent an archive that could not be read. Try again in a minute.');
  }
  const file = (rel) => archive.files.get(`${base}${rel}`);

  // Consent first, and only from the top of the repository: a copied or
  // vendored folder that carries someone else's config can't speak for it.
  // Error text is fixed, because a config error message can quote the config.
  const readConfig = async (text) => {
    try {
      return parseConfig(text);
    } catch (e) {
      if (e instanceof ConfigError) throw await refuse(422, 'bad_config', 'rattlecheck.config.json is not valid. Run npx rattlecheck locally to see why.');
      throw e;
    }
  };
  const rootText = archive.files.get('rattlecheck.config.json');
  const rootConfig = rootText === undefined ? null : await readConfig(rootText);
  const consented = dir ? rootConfig?.publishDirs.includes(dir) : rootConfig?.publish;
  if (!consented) {
    throw await refuse(403, 'not_opted_in', `${owner}/${repo}${dir ? ` (${dir})` : ''} has not opted in to a public grade. ${dir ? OPT_IN_DIR(dir) : OPT_IN_ROOT}`);
  }
  const ownText = dir ? file('rattlecheck.config.json') : rootText;
  const config = ownText === undefined ? { allow: [] } : dir ? await readConfig(ownText) : rootConfig;

  // The same folders the command line looks in, in the same order.
  const pick = (folder) =>
    [...archive.files.keys()]
      .filter((p) => p.startsWith(`${base}${folder}/`) && isSql(p.slice(`${base}${folder}/`.length)))
      .sort()
      .map((p) => ({ file: p.slice(`${base}${folder}/`.length), sql: archive.files.get(p) }));
  let folder = 'supabase/migrations';
  let migrations = pick(folder);
  if (!migrations.length) {
    folder = 'migrations';
    migrations = pick(folder);
  }
  if (!migrations.length) {
    throw await refuse(422, 'no_migrations', `No Supabase migrations found${dir ? ` under ${dir}` : ''} (looked for supabase/migrations and migrations).`);
  }

  // GitHub leaves out of the archive any file a .gitattributes marks
  // export-ignore. That would let a repository hide a migration from this
  // check while keeping it in the project, so such a repository is refused.
  if (archive.commit && (await hidesFiles({ owner, repo, dir, folder, commit: archive.commit, fetchImpl, headers }))) {
    throw await refuse(422, 'export_ignore', 'This repository uses export-ignore or export-subst in .gitattributes, which can hide files from the check. Remove it to publish a grade.');
  }

  const toml = file('supabase/config.toml');
  const exposedSchemas = toml === undefined ? ['public', 'graphql_public'] : parseExposedSchemas(toml);
  let result;
  try {
    // Only the allow list is taken from the project's config. The settings
    // that change what counts as reachable (defaults, exposedSchemas,
    // migrationRoles) are not: a public grade uses the stock ones for everyone.
    result = scanStatic({ migrations, config: { allow: config.allow }, exposedSchemas, maxStatements: LIMITS.statements, fileOf: (f) => `${folder}/${f}` });
  } catch (e) {
    if (e instanceof BudgetError) throw await refuse(413, 'too_large', 'The migrations have too many statements for the public service to check. Run npx rattlecheck on your own machine.');
    throw await refuse(422, 'scan_failed', 'The migrations could not be checked. Run npx rattlecheck locally to see why.');
  }
  if (!result.coverage.ok) {
    throw await refuse(422, 'nothing_parsed', 'Migration files were found but nothing in them could be read.');
  }

  const record = {
    schema: 'rattlecheck.published/v1',
    owner,
    repo,
    dir,
    commit: archive.commit,
    grade: result.grade,
    doors: result.doors,
    counts: result.counts,
    exceptions: result.allowed.length,
    exposedSchemas,
    coverage: {
      files: result.coverage.files,
      statements: result.coverage.statements,
      tables: result.coverage.tables,
      functions: result.coverage.functions,
      notFollowed: result.coverage.doBlocks?.skipped ?? 0,
    },
    checkedAt: now().toISOString(),
    version,
  };
  await store.put(key, JSON.stringify(record));
  return { ...record, fresh: true };
}

// Looks, at the exact commit, at every .gitattributes that can apply to the
// migrations folder. raw.githubusercontent.com serves the real tree, so a
// .gitattributes that hides itself from the archive is still seen here.
async function hidesFiles({ owner, repo, dir, folder, commit, fetchImpl, headers }) {
  const segments = [...(dir ? dir.split('/') : []), ...folder.split('/')];
  const folders = [''];
  for (let i = 0; i < segments.length; i++) folders.push(`${segments.slice(0, i + 1).join('/')}/`);
  const texts = await Promise.all(
    folders.slice(0, LIMITS.attributeFiles).map(async (f) => {
      try {
        const res = await fetchImpl(`https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${f.split('/').map(encodeURIComponent).join('/')}.gitattributes`, { headers });
        if (res.status === 404) return '';
        if (!res.ok) return null;
        return (await res.text()).slice(0, 200000);
      } catch {
        return null;
      }
    }),
  );
  // Not being able to look is not the same as nothing being hidden.
  if (texts.includes(null)) throw new PublishError(502, 'github_error', 'GitHub could not be reached to finish the check. Try again in a minute.');
  return texts.some((t) => /\bexport-(ignore|subst)\b/.test(t.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')));
}
