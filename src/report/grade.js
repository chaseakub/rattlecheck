// The one place the grade is decided. Cards, badges, terminal output and the
// MCP server all read from here, so they cannot disagree.
export const GRADES = {
  A: { label: 'Locked tight', color: '#1a9e55' },
  B: { label: 'Mostly locked', color: '#6fa832' },
  C: { label: 'Needs work', color: '#e0a100' },
  D: { label: 'At risk', color: '#e8710a' },
  F: { label: 'Wide open', color: '#e5322d' },
};

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, warning: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export function gradeFor(counts) {
  if (counts.critical > 0) return 'F';
  if (counts.high >= 2) return 'D';
  if (counts.high === 1) return 'C';
  if (counts.warning > 0) return 'B';
  return 'A';
}

/** Severities that mean a door is open (or broken), as opposed to worth a look. */
export const OPEN_SEVERITIES = new Set(['critical', 'high']);
