// Live checks only run against a project the person running rattlecheck can
// prove they control. This is the line between a tool that checks your own
// doors and a tool that tries other people's. It is not optional and there is
// no flag to skip it.
//
// Proof is one of:
//   1. A Supabase access token (from `supabase login`) that can see the
//      project through the Management API.
//   2. The project's own service key, accepted by the project's admin API.
//      Only the owner has it. It is used for this one request and nothing else.
//
// No request follows a redirect. Otherwise a server could pass the proof
// itself and then forward every probe somewhere else.
import { authHeaders, checkTarget } from './env.js';

// An id no real user has. The admin API answers "user not found" to a service
// key and "not allowed" to anything else, and no user data comes back either way.
const NOBODY = '00000000-0000-0000-0000-000000000000';

async function smallText(res) {
  try {
    const t = await res.text();
    return t.slice(0, 4096);
  } catch {
    return '';
  }
}

export function projectRefFromUrl(url) {
  const t = checkTarget(url);
  return t.ok && !t.local ? t.ref : null;
}

export async function proveOwnership({ url, accessToken, serviceKey, fetchImpl = globalThis.fetch, userAgent }) {
  const target = checkTarget(url);
  if (!target.ok) return { ok: false, method: null, ref: null, reason: target.reason };
  const attempts = [];

  if (accessToken && target.ref) {
    try {
      const res = await fetchImpl(`https://api.supabase.com/v1/projects/${target.ref}`, {
        headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': userAgent },
        redirect: 'manual',
      });
      await res.body?.cancel?.();
      if (res.status === 200) return { ok: true, method: 'access-token', ref: target.ref, base: target.base };
      attempts.push(`access token was not accepted for project ${target.ref} (HTTP ${res.status})`);
    } catch (e) {
      attempts.push(`could not reach the Supabase Management API (${e.message})`);
    }
  }

  if (serviceKey) {
    try {
      const res = await fetchImpl(`${target.base}/auth/v1/admin/users/${NOBODY}`, {
        headers: { ...authHeaders(serviceKey), 'User-Agent': userAgent },
        redirect: 'manual',
      });
      const body = await smallText(res);
      if (res.status === 404 && /user_not_found|user not found/i.test(body)) {
        return { ok: true, method: 'service-key', ref: target.ref, base: target.base };
      }
      attempts.push(`service key was not accepted by this project (HTTP ${res.status})`);
    } catch (e) {
      attempts.push(`could not reach the project (${e.message})`);
    }
  }

  if (!accessToken && !serviceKey) attempts.push('no SUPABASE_ACCESS_TOKEN or service key found');
  else if (accessToken && !target.ref && !serviceKey) attempts.push('an access token can only prove ownership of a hosted <ref>.supabase.co project');
  return { ok: false, method: null, ref: target.ref, reason: attempts.join('; ') };
}
