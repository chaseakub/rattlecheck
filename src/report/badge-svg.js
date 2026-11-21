// README badge: "rattlecheck | A". Shows the grade only.
const W = (s) => Math.round(s.length * 6.6 + 12);

export function renderBadge(report) {
  const left = 'rattlecheck';
  const right = report.grade.letter;
  const lw = W(left);
  const rw = Math.max(22, W(right));
  const total = lw + rw;
  const color = report.grade.color;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${left}: ${right}">
  <title>${left}: ${right} (${report.grade.label})</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#1b1b1d"/>
    <rect x="${lw}" width="${rw}" height="20" fill="${color}"/>
    <rect width="${total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lw / 2}" y="14">${left}</text>
    <text x="${lw + rw / 2}" y="14" font-weight="bold">${right}</text>
  </g>
</svg>
`;
}
