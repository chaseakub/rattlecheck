// rattlecheck publish service: a public grade and badge for open source
// Supabase projects that opted in. See publish.js for the rules.
import pkg from '../../package.json' with { type: 'json' };
import { renderBadge } from '../../src/report/badge-svg.js';
import { publish, parseTarget, PublishError } from './publish.js';
import { homePage, reportPage, missingPage, badgeMarkdown, unknownGrade } from './pages.js';

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

const html = (body, status = 200, extra = {}) =>
  new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...extra } });
const json = (body, status = 200, extra = {}) =>
  new Response(`${JSON.stringify(body)}\n`, { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', ...extra } });
const svg = (body, cache) =>
  new Response(body, {
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': cache,
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
    },
  });

const links = (origin, r) => {
  const path = `${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}`;
  const q = r.dir ? `?dir=${encodeURIComponent(r.dir)}` : '';
  return { page: `${origin}/r/${path}${q}`, badge: `${origin}/badge/${path}.svg${q}`, markdown: badgeMarkdown(origin, r) };
};

// One bucket per IPv4 address, and per /64 for IPv6: a single home or server
// connection owns a whole /64, so the full address would be no limit at all.
export function addressKey(ip) {
  if (!ip) return 'unknown';
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.toLowerCase().split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

// Reads a request body that is supposed to be tiny, and stops reading the
// moment it is not, instead of buffering whatever was sent.
async function readSmallBody(request, maxBytes) {
  const tooLarge = () => new PublishError(413, 'too_large', 'The request is too large.');
  if (Number(request.headers.get('content-length') ?? 0) > maxBytes) throw tooLarge();
  if (!request.body) return '';
  const reader = request.body.getReader();
  const parts = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    parts.push(value);
  }
  const all = new Uint8Array(size);
  let off = 0;
  for (const part of parts) {
    all.set(part, off);
    off += part.byteLength;
  }
  return new TextDecoder().decode(all);
}

export async function handle(request, env, { fetchImpl = fetch, now } = {}) {
  const url = new URL(request.url);
  const origin = url.origin;
  const store = env.GRADES;

  if (url.pathname === '/api/publish') {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed', message: 'Send a POST.' }, 405, { Allow: 'POST' });
    // JSON only. A web page can't send this content type across sites without
    // a preflight, and this service never answers one, so visitors' browsers
    // can't be made to request checks.
    if (!/^application\/json\b/i.test(request.headers.get('content-type') ?? '')) {
      return json({ error: 'bad_content_type', message: 'Send Content-Type: application/json.' }, 415);
    }
    if (env.PUBLISH_LIMITER) {
      const { success } = await env.PUBLISH_LIMITER.limit({ key: addressKey(request.headers.get('CF-Connecting-IP')) });
      if (!success) return json({ error: 'rate_limited', message: 'Too many checks from this address. Try again in a minute.' }, 429);
    }
    try {
      const text = await readSmallBody(request, 2000);
      let input;
      try {
        input = JSON.parse(text);
      } catch {
        throw new PublishError(400, 'bad_json', 'Send JSON like {"repo": "owner/name"}.');
      }
      const target = parseTarget(input);
      // A few checks per repository per minute, whatever folder is named and
      // whoever asks. Past that, the last answer is returned as it stands.
      if (env.REPO_LIMITER) {
        const { success } = await env.REPO_LIMITER.limit({ key: `${target.owner}/${target.repo}`.toLowerCase() });
        if (!success) {
          const existing = await store.get(target.key, 'json');
          if (existing) return json({ ...existing, fresh: false, ...links(origin, existing) });
          throw new PublishError(429, 'cooldown', 'This repository was checked a moment ago. Try again in a minute.');
        }
      }
      const record = await publish(target, { store, fetchImpl, version: pkg.version, now });
      return json({ ...record, ...links(origin, record) });
    } catch (e) {
      if (e instanceof PublishError) return json({ error: e.code, message: e.message }, e.status);
      throw e;
    }
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method_not_allowed', message: 'Send a GET.' }, 405, { Allow: 'GET, HEAD' });

  if (url.pathname === '/') return html(homePage({ origin }), 200, { 'Cache-Control': 'public, max-age=300' });
  if (url.pathname === '/robots.txt') return new Response('User-agent: *\nAllow: /\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

  // A repository may itself be called something.svg, so only the badge route
  // treats that ending as a suffix.
  const m = /^\/(badge)\/([^/]+)\/([^/]+)\.svg$/.exec(url.pathname) ?? /^\/(r|api\/r)\/([^/]+)\/([^/]+)$/.exec(url.pathname);
  if (m) {
    let target;
    try {
      target = parseTarget({ repo: `${decodeURIComponent(m[2])}/${decodeURIComponent(m[3])}`, dir: url.searchParams.get('dir') ?? '' });
    } catch {
      return m[1] === 'badge' ? svg(renderBadge(unknownGrade), 'public, max-age=300') : html(missingPage({ origin, owner: 'unknown', repo: 'unknown', dir: '' }), 404);
    }
    const record = await store.get(target.key, 'json');
    if (m[1] === 'badge') return svg(renderBadge(record ?? unknownGrade), 'public, max-age=300, s-maxage=300');
    if (m[1] === 'api/r') return record ? json({ ...record, ...links(origin, record) }) : json({ error: 'not_published', message: 'No grade is published for this project.' }, 404);
    return record ? html(reportPage({ origin, record }), 200, { 'Cache-Control': 'public, max-age=60' }) : html(missingPage({ origin, ...target }), 404);
  }

  return html(missingPage({ origin, owner: 'not', repo: 'found', dir: '' }).replace('<h1>not/found</h1>', '<h1>Page not found</h1>'), 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      return json({ error: 'internal', message: 'Something went wrong on our side.' }, 500);
    }
  },
};
