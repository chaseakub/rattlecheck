// The public pages. Plain HTML, no scripts, no trackers, nothing loaded from
// anywhere else. Every value that came from a repository is escaped.
import { GRADES } from '../../src/report/grade.js';

export const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const n = (x) => Number(x).toLocaleString('en-US');
const plural = (count, one, many = `${one}s`) => `${n(count)} ${count === 1 ? one : many}`;

const CSS = `
:root{color-scheme:dark;--bg:#0b0b0c;--panel:#141416;--line:#232326;--text:#f4f4f5;--soft:#a1a1a7;--dim:#6b6b70}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 24px 72px}
a{color:inherit}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.brand{font-weight:700;font-size:20px;text-decoration:none}
.tag{color:var(--soft);margin:2px 0 40px}
h1{font-size:30px;line-height:1.2;margin:0 0 6px;overflow-wrap:anywhere}
h2{font-size:18px;margin:44px 0 10px}
p{margin:10px 0;color:var(--soft)}
p strong{color:var(--text)}
.sub{color:var(--dim);font-size:14px}
.grade{display:flex;gap:28px;align-items:center;margin:32px 0;padding:28px;background:var(--panel);border:1px solid var(--line);border-radius:14px;flex-wrap:wrap}
.ring{flex:none;width:132px;height:132px;border-radius:50%;border:8px solid var(--g);display:grid;place-items:center;font-size:72px;font-weight:800;color:var(--g);line-height:1}
.ring.small{font-size:38px}
.verdict{font-size:26px;font-weight:700;margin:0;color:var(--text)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0;padding:0;list-style:none}
.stats li{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stats b{display:block;font-size:24px;color:var(--text)}
.stats span{color:var(--soft);font-size:14px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;overflow-x:auto;font-size:14px;color:var(--text);margin:12px 0}
ol{color:var(--soft);padding-left:22px}
ol li{margin:8px 0}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);color:var(--dim);font-size:14px}
`;

function layout({ title, description, body, canonical }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
${canonical ? `<link rel="canonical" href="${esc(canonical)}">` : ''}
<style>${CSS}</style>
</head>
<body>
<main>
<a class="brand mono" href="/">rattlecheck</a>
<p class="tag">Rattle every door you own.</p>
${body}
<footer>
<p class="sub">rattlecheck is an open source check for Supabase projects. <a href="https://github.com/chaseakub/rattlecheck">Source on GitHub</a> · <a href="https://www.npmjs.com/package/rattlecheck">npm</a></p>
</footer>
</main>
</body>
</html>
`;
}

const HOW_TO = (origin) => `<ol>
<li>Add <code>"publish": true</code> to <code>rattlecheck.config.json</code> at the top of your repository. For a project in a subfolder, add <code>"publishDirs": ["apps/api"]</code> there instead. Commit it and push it. That line is your consent, and removing it takes the page down at the next check.</li>
<li>Run <code>npx rattlecheck --publish</code> from the project folder.</li>
<li>Paste the badge it prints into your README.</li>
</ol>
<p>The grade is worked out here, from your repository's own migrations at the latest commit on its default branch. Nothing your machine sends can change it. Public GitHub repositories with up to 1 MB of migrations.</p>
<p class="sub">Service address: <span class="mono">${esc(origin)}</span></p>`;

export function homePage({ origin }) {
  return layout({
    title: 'rattlecheck: a public grade for your Supabase project',
    description: 'A public, checked grade for the open doors in a Supabase project. Opt in from your own repository.',
    canonical: `${origin}/`,
    body: `<h1>A public grade for your Supabase project</h1>
<p>rattlecheck reads a project's migrations and finds the doors left open: tables anyone can read, functions anyone can call with full database powers, and policies that let anyone change every row.</p>
<p>This service gives an open source project a grade anyone can check, and a badge that links to it.</p>
<h2>Get a badge</h2>
${HOW_TO(origin)}
<h2>What a page shows</h2>
<p>The grade, how many doors were checked, how many are open, and how many the project marked as open on purpose. It <strong>never</strong> shows which table or function is open.</p>
<h2>What the grade is not</h2>
<p>It is a read of the migrations in the repository. It does not look at the running database, so something changed by hand in a dashboard is not seen here. Run <code>npx rattlecheck --live</code> against your own project for that.</p>`,
  });
}

export function badgeMarkdown(origin, r) {
  const q = r.dir ? `?dir=${encodeURIComponent(r.dir)}` : '';
  const path = `${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}`;
  return `[![rattlecheck](${origin}/badge/${path}.svg${q})](${origin}/r/${path}${q})`;
}

export function reportPage({ origin, record: r }) {
  const g = r.grade;
  const name = `${r.owner}/${r.repo}`;
  const repoUrl = `https://github.com/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}`;
  const open = r.doors.open;
  const verdict = r.doors.checked === 0 ? g.label : open === 0 ? 'Every door locked.' : open === 1 ? '1 door open.' : `${n(open)} doors open.`;
  const commit = r.commit
    ? `<a class="mono" href="${repoUrl}/tree/${esc(r.commit)}${r.dir ? `/${r.dir.split('/').map(encodeURIComponent).join('/')}` : ''}">${esc(r.commit.slice(0, 7))}</a>`
    : 'the latest commit';
  const date = r.checkedAt.slice(0, 10);
  return layout({
    title: `${name}: rattlecheck grade ${g.letter}`,
    description: `${name} has rattlecheck grade ${g.letter} (${g.label}). ${plural(r.doors.checked, 'door')} checked, ${n(open)} open.`,
    canonical: `${origin}/r/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}${r.dir ? `?dir=${encodeURIComponent(r.dir)}` : ''}`,
    body: `<h1><a href="${repoUrl}">${esc(name)}</a></h1>
${r.dir ? `<p class="sub">Project folder: <span class="mono">${esc(r.dir)}</span></p>` : ''}
<section class="grade" style="--g:${esc(g.color)}">
<div class="ring${g.letter.length > 1 ? ' small' : ''}" role="img" aria-label="Grade ${esc(g.letter)}">${esc(g.letter)}</div>
<div>
<p class="verdict">${esc(verdict)}</p>
<p>${esc(g.label)}. ${plural(r.doors.checked, 'door')} checked.</p>
<p class="sub">Checked ${esc(date)} at commit ${commit}, by rattlecheck ${esc(r.version)}.</p>
</div>
</section>
<ul class="stats">
<li><b>${n(r.counts.critical)}</b><span>critical</span></li>
<li><b>${n(r.counts.high)}</b><span>high</span></li>
<li><b>${n(r.counts.warning)}</b><span>${r.counts.warning === 1 ? 'thing' : 'things'} to check</span></li>
<li><b>${n(r.exceptions)}</b><span>open on purpose</span></li>
</ul>
<h2>What was checked</h2>
<p>${plural(r.coverage.files, 'migration file')}, ${plural(r.coverage.statements, 'statement')}: ${plural(r.coverage.tables, 'table')} and ${plural(r.coverage.functions, 'function')}. This service ran the check itself, from the repository's own files at that commit.</p>
<p><strong>Open on purpose</strong> counts the doors the project marked as meant to be open, each with a written reason in its <code>rattlecheck.config.json</code>. They are not counted against the grade, so read that file before trusting an A.</p>
${r.coverage.notFollowed ? `<p>${plural(r.coverage.notFollowed, 'statement')} inside <code>DO</code> blocks could not be followed and ${r.coverage.notFollowed === 1 ? 'was' : 'were'} not counted.</p>` : ''}
<p>API schemas checked: <span class="mono">${esc((r.exposedSchemas ?? []).join(', ') || 'none')}</span>, as the project's <code>supabase/config.toml</code> lists them. Everything else uses the same stock settings for every project.</p>
<p>This is a read of the migrations, not of the running database. It does not say which table or function is open, on purpose.</p>
<h2>Badge</h2>
<pre>${esc(badgeMarkdown(origin, r))}</pre>
<h2>Get a grade for your own project</h2>
${HOW_TO(origin)}`,
  });
}

export function missingPage({ origin, owner, repo, dir }) {
  const name = `${owner}/${repo}`;
  return layout({
    title: `${name}: no rattlecheck grade published`,
    description: `${name} has not published a rattlecheck grade.`,
    body: `<h1>${esc(name)}</h1>
${dir ? `<p class="sub">Project folder: <span class="mono">${esc(dir)}</span></p>` : ''}
<p>No grade is published for this project. Either its owner has not opted in, or it has not been checked yet.</p>
<h2>If this is your project</h2>
${HOW_TO(origin)}`,
  });
}

export const unknownGrade = { grade: { letter: 'none', label: 'No grade published', color: GRADES['N/A'].color } };
