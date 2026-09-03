-- Zero every moose wallet, reset totals, then put 1,000,000 on admin.
-- Names stay. Old Stripe packs cannot be claimed again.

update public.moose_wallets set coins = 0, updated_at = now();
update public.moose_house set coins = 0, updated_at = now();
insert into public.moose_epoch (id, reset_at) values (1, now())
  on conflict (id) do update set reset_at = excluded.reset_at;

do $$
declare
  a uuid;
begin
  select coalesce(
    (select o.user_id from public.owned_names o where lower(o.name) = 'admin' limit 1),
    (select p.id from public.profiles p where lower(p.display_name) = 'admin' limit 1)
  ) into a;
  if a is null then
    raise exception 'No admin account found';
  end if;
  insert into public.moose_wallets (user_id, coins) values (a, 0)
    on conflict (user_id) do nothing;
  update public.moose_wallets
    set coins = 1000000, updated_at = now()
    where user_id = a;
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref)
    values (a, false, 1000000, 'admin_seed', 'reset');
end $$;

do $$
begin
  perform public.moose_refresh_totals();
exception when undefined_function then
  insert into public.moose_totals (id, stripe_bought, everyone_holding, difference, updated_at)
    values (1, 0, 1000000, -1000000, now())
    on conflict (id) do update set
      stripe_bought = 0,
      everyone_holding = 1000000,
      difference = -1000000,
      updated_at = now();
end $$;
