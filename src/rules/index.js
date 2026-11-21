import rc001 from './supabase/rc001-table-without-rls.js';
import rc002 from './supabase/rc002-definer-callable-by-anon.js';
import rc003 from './supabase/rc003-definer-search-path.js';
import rc004 from './supabase/rc004-invoker-trigger-locked-table.js';
import rc005 from './supabase/rc005-permissive-true-policy.js';
import rc101 from '../live/rc101-anon-readable.js';

export const STATIC_RULES = [rc001, rc002, rc003, rc004, rc005];
export const LIVE_RULES = [rc101];
export const ALL_RULES = [...STATIC_RULES, ...LIVE_RULES];

export function getRule(id) {
  return ALL_RULES.find((r) => r.id.toLowerCase() === String(id).toLowerCase()) ?? null;
}
