revoke select on public.directory from public, anon;
grant select (id, display_name) on public.directory to anon;
