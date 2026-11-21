// The attacker's view: ask the live project, with only the public key, how
// many rows of each table it will hand over.
//
// Read-only by construction. Every table request is a HEAD with
// Prefer: count=exact, so the server returns a row count and no row data. The
// one GET asks the API for its list of tables (names only, no rows). Nothing is
// written, no row is downloaded, nothing is stored. Count=exact makes Postgres
// count the rows, which can take a moment on very large tables.
//
// A zero is reported as "locked or empty", never as "locked". From outside,
// an empty table and a table row-level security filters to nothing look the
// same, and claiming otherwise would be reporting an instrument we can't trust.
import { authHeaders, checkTarget } from './env.js';

async function discoverPublicTables(base, headers, fetchImpl) {
  try {
    const res = await fetchImpl(`${base}/rest/v1/`, { headers: { ...headers, Accept: 'application/openapi+json' }, redirect: 'manual' });
    if (res.status !== 200) {
      await res.body?.cancel?.();
      return [];
    }
    const spec = await res.json();
    return Object.keys(spec.paths ?? {})
      .filter((p) => p !== '/' && !p.startsWith('/rpc/'))
      .map((p) => `public.${p.slice(1)}`);
  } catch {
    return [];
  }
}

function parseCount(contentRange) {
  const m = /\/(\d+|\*)\s*$/.exec(contentRange ?? '');
  return m && m[1] !== '*' ? Number(m[1]) : null;
}

export async function probeTables({ url, anonKey, tables, fetchImpl = globalThis.fetch, userAgent, concurrency = 4 }) {
  // Defense in depth: the caller already proved ownership of this exact base.
  const target = checkTarget(url);
  if (!target.ok) throw new Error(target.reason);
  const base = target.base;
  const headers = { ...authHeaders(anonKey), 'User-Agent': userAgent };
  const discovered = await discoverPublicTables(base, headers, fetchImpl);
  const all = [...new Set([...tables, ...discovered])].sort();

  const results = [];
  let next = 0;
  async function worker() {
    while (next < all.length) {
      const name = all[next++];
      const [schema, table] = name.split('.');
      try {
        const res = await fetchImpl(`${base}/rest/v1/${encodeURIComponent(table)}?select=*`, {
          method: 'HEAD',
          headers: { ...headers, Prefer: 'count=exact', 'Accept-Profile': schema },
          redirect: 'manual',
        });
        const count = parseCount(res.headers.get('content-range'));
        if (res.status === 200 || res.status === 206) {
          results.push({ table: name, status: res.status, state: count > 0 ? 'open' : 'locked-or-empty', count });
        } else if (res.status === 401 || res.status === 403) {
          results.push({ table: name, status: res.status, state: 'locked', count: null });
        } else if (res.status === 404 || res.status === 406) {
          results.push({ table: name, status: res.status, state: 'not-exposed', count: null });
        } else {
          results.push({ table: name, status: res.status, state: 'error', count: null });
        }
      } catch (e) {
        results.push({ table: name, status: 0, state: 'error', count: null, error: e.message });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, all.length) }, worker));
  results.sort((a, b) => a.table.localeCompare(b.table));
  return { results, discovered: discovered.length };
}
