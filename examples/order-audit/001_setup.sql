create table public.orders (
  id integer primary key,
  owner_id uuid not null,
  note text not null
);
grant select, update on public.orders to authenticated;
alter table public.orders enable row level security;
create policy own_orders on public.orders to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create table public.order_events (order_id integer not null);
grant insert on public.order_events to authenticated;
alter table public.order_events enable row level security;
-- No insert policy: customers cannot write their own audit entries.
