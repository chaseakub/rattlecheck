// Reads the project's own connection settings. Values are kept in memory only
// and are never printed, logged, or returned in a report.
//
// The URL and the keys always come from ONE source: either the process
// environment (if it names a project URL at all) or the project's env files.
// Mixing them would let a repo's .env supply the URL while your shell supplies
// the keys, and your keys would go wherever that repo pointed them.
import fs from 'node:fs';
import path from 'node:path';

const ENV_FILES = ['.env', '.env.local', '.env.development', '.env.development.local'];
const URL_RE = /^(?:[A-Z]+_)*SUPABASE_URL$/;

export function parseEnvFile(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, '');
    out[m[1]] = v;
  }
  return out;
}

function pick(vars, re) {
  const k = Object.keys(vars).find((name) => re.test(name) && vars[name]);
  return k ? vars[k] : null;
}

/** Collect URL and keys from one source, plus the access token from the process environment only. */
export function readProjectEnv(root, processEnv = process.env) {
  const proc = Object.fromEntries(Object.entries(processEnv).filter(([k]) => /SUPABASE/.test(k)));
  let vars;
  let source;
  if (Object.keys(proc).some((k) => URL_RE.test(k) && proc[k])) {
    vars = proc;
    source = 'environment';
  } else {
    vars = {};
    for (const f of ENV_FILES) {
      const p = path.join(root, f);
      if (fs.existsSync(p)) Object.assign(vars, parseEnvFile(fs.readFileSync(p, 'utf8')));
    }
    source = 'env files';
  }
  return {
    source,
    url: pick(vars, URL_RE),
    anonKey: pick(vars, /SUPABASE_(?:ANON|PUBLISHABLE)\w*KEY$/),
    serviceKey: pick(vars, /SUPABASE_(?:SERVICE_ROLE|SECRET)\w*KEY$/),
    accessToken: processEnv.SUPABASE_ACCESS_TOKEN || null,
  };
}

/** Legacy keys are JWTs and go in both headers; new sb_ keys go in apikey only. */
export function authHeaders(key) {
  return key.startsWith('eyJ') ? { apikey: key, Authorization: `Bearer ${key}` } : { apikey: key };
}

/**
 * The only places rattlecheck will send a key: a hosted project at
 * https://<ref>.supabase.co (or .in), or a local Supabase on localhost.
 */
export function checkTarget(url) {
  let u;
  try {
    u = new URL(String(url).trim());
  } catch {
    return { ok: false, reason: 'the project URL is not a valid URL' };
  }
  const bare = u.pathname === '/' && !u.search && !u.hash && !u.username && !u.password;
  const hosted = /^([a-z0-9]{20})\.supabase\.(?:co|in)$/i.exec(u.hostname);
  if (hosted && u.protocol === 'https:' && !u.port && bare) {
    return { ok: true, base: `https://${u.hostname.toLowerCase()}`, ref: hosted[1].toLowerCase(), local: false };
  }
  const isLoopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (isLoopback && (u.protocol === 'http:' || u.protocol === 'https:') && bare) {
    return { ok: true, base: `${u.protocol}//${u.host}`, ref: null, local: true };
  }
  return {
    ok: false,
    reason: 'rattlecheck only sends your keys to https://<project-ref>.supabase.co or to a local Supabase on localhost. Set SUPABASE_URL to that address (custom domains aren\'t supported yet)',
  };
}

/** True when a key in the public slot is actually a secret one. */
export function looksSecret(key) {
  if (key.startsWith('sb_secret_')) return true;
  if (key.startsWith('eyJ')) {
    try {
      const payload = JSON.parse(Buffer.from(key.split('.')[1], 'base64url').toString('utf8'));
      return payload.role === 'service_role';
    } catch {
      return false;
    }
  }
  return false;
}
