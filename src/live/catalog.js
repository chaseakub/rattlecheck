// The full list of tables and views the live check has to ask about.
//
// Migrations alone are not enough: anything created in the dashboard, by a
// script, or by hand (a quick backup copy, say) never appears in them, and
// those are exactly the objects most likely to be left open. A live check
// that only asks about tables it already knows reports "0 open" over the
// tables it never saw.
//
// With an access token, rattlecheck reads the object names from the project's
// catalog through Supabase's READ-ONLY query endpoint. Names only, no rows.
// It never falls back to the general query endpoint, which can write.
function sqlLiteral(s) {
  return `'${String(s).replace(/'/g, "''")}'`;
}

export async function listExposedObjects({ ref, accessToken, schemas, fetchImpl = globalThis.fetch, userAgent }) {
  if (!ref || !accessToken) return { ok: false, names: [], reason: 'needs an access token for a hosted project' };
  const query =
    'select n.nspname as schema, c.relname as name, c.relkind as kind ' +
    'from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace ' +
    `where n.nspname = any (array[${schemas.map(sqlLiteral).join(', ')}]::text[]) ` +
    "and c.relkind in ('r', 'p', 'v', 'm', 'f') order by 1, 2";
  try {
    const res = await fetchImpl(`https://api.supabase.com/v1/projects/${ref}/database/query/read-only`, {
      method: 'POST',
      redirect: 'manual',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'User-Agent': userAgent },
      body: JSON.stringify({ query }),
    });
    if (res.status !== 200 && res.status !== 201) {
      await res.body?.cancel?.();
      return { ok: false, names: [], reason: `the read-only catalog query was refused (HTTP ${res.status})` };
    }
    const rows = await res.json();
    if (!Array.isArray(rows)) return { ok: false, names: [], reason: 'the catalog query returned something unexpected' };
    const names = rows
      .filter((r) => typeof r.schema === 'string' && typeof r.name === 'string')
      .map((r) => `${r.schema}.${r.name}`);
    return { ok: true, names, views: rows.filter((r) => r.kind === 'v' || r.kind === 'm').length };
  } catch (e) {
    return { ok: false, names: [], reason: `could not reach the Management API (${e.message})` };
  }
}
