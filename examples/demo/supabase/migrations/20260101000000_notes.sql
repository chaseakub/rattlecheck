-- A small, locked project: the example rattlecheck grades in public.

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid(),
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

create policy notes_owner_all on public.notes
  for all to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- Anyone may read the menu. It is public on purpose, and the config says why.
create table public.menu_items (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_cents integer not null
);

alter table public.menu_items enable row level security;

create policy menu_items_public_read on public.menu_items
  for select to anon, authenticated
  using (true);

-- Runs with the owner's powers, so it is closed to the public and pinned.
create function public.note_count()
  returns bigint
  language sql
  stable
  security definer
  set search_path = ''
as $$
  select count(*) from public.notes where owner_id = auth.uid();
$$;

revoke execute on function public.note_count() from public, anon;
grant execute on function public.note_count() to authenticated;
