-- The trusted function owner can append the audit entry.
alter function public.log_order() security definer;
alter function public.log_order() set search_path = '';
revoke execute on function public.log_order() from public, authenticated;
