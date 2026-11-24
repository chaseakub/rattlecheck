create function public.log_order() returns trigger
language plpgsql as $$
begin
  insert into public.order_events values (new.id);
  return new;
end;
$$;
create trigger audit_order after update on public.orders
  for each row execute function public.log_order();
