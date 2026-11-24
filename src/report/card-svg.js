// The share card, 1200x630 (the size X, LinkedIn and Slack preview at).
//
// Grade and counts ONLY. No project URL, no table or function names. A failing
// card must never tell anyone where the hole is, so people can post it before
// they've fixed it without handing out a map.
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function renderCard(report) {
  const g = report.grade;
  const { checked, open } = report.doors;
  let headline = open === 0 ? 'Every door locked.' : open === 1 ? '1 door open.' : `${open} doors open.`;
  let sub =
    open === 0
      ? `${checked.toLocaleString('en-US')} doors checked. Nothing gave.`
      : `${checked.toLocaleString('en-US')} doors checked. Fixing ${open === 1 ? 'it' : 'them'} now.`;

  if (checked === 0) {
    headline = g.label + '.';
    sub = 'Run the check on migrations that define tables or functions.';
  }

  // A row of small doors: open ones drawn ajar in the grade color.
  const doorCount = Math.min(24, checked);
  const openCount = Math.min(open, doorCount);
  const doors = [];
  for (let i = 0; i < doorCount; i++) {
    const x = 96 + i * 42;
    const isOpen = i < openCount;
    doors.push(
      isOpen
        ? `<g><rect x="${x}" y="486" width="28" height="44" rx="3" fill="#0b0b0c" stroke="${g.color}" stroke-width="2"/><path d="M${x} 486 L${x + 16} 492 L${x + 16} 536 L${x} 530 Z" fill="${g.color}"/></g>`
        : `<g><rect x="${x}" y="486" width="28" height="44" rx="3" fill="#232326"/><circle cx="${x + 21}" cy="509" r="2.2" fill="#6b6b70"/></g>`,
    );
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="rattlecheck grade ${g.letter}: ${esc(headline)}">
  <title>rattlecheck grade ${g.letter}: ${esc(headline)}</title>
  <rect width="1200" height="630" fill="#0b0b0c"/>
  <rect x="0" y="0" width="1200" height="8" fill="${g.color}"/>
  <text x="96" y="122" fill="#f4f4f5" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="34" font-weight="700">rattlecheck</text>
  <text x="96" y="160" fill="#8b8b91" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="24">Rattle every door you own.</text>

  <circle cx="1010" cy="300" r="118" fill="none" stroke="${g.color}" stroke-width="10"/>
  <text x="1010" y="345" text-anchor="middle" fill="${g.color}" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="${checked === 0 ? 86 : 132}" font-weight="800">${g.letter}</text>
  <text x="1010" y="458" text-anchor="middle" fill="#c9c9ce" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="26" font-weight="600">${esc(g.label)}</text>

  <text x="96" y="318" fill="#f4f4f5" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="76" font-weight="800">${esc(headline)}</text>
  <text x="96" y="378" fill="#a1a1a7" font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="32">${esc(sub)}</text>

  ${doors.join('\n  ')}

  <text x="1104" y="590" text-anchor="end" fill="#6b6b70" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="22">npx rattlecheck</text>
</svg>
`;
}
