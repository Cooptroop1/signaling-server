-- Extra SQL for selling names for moose. Run after moose-coins.sql.
-- Safe to run twice.

alter table public.owned_names add column if not exists sale_price_coins int;

create or replace function public.moose_spend_resale(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
  seller uuid;
  cost int;
  have bigint;
  cut int;
  net int;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(coalesce(p_name, '')), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 then
    return jsonb_build_object('ok', false, 'error', 'Missing name');
  end if;

  select o.user_id, coalesce(o.sale_price_coins, 0)
    into seller, cost
    from public.owned_names o
    where lower(o.name) = lower(nm) and o.listed_for_sale = true
    for update;
  if seller is null or cost < 20 then
    return jsonb_build_object('ok', false, 'error', 'Not listed for moose');
  end if;
  if seller = me then
    return jsonb_build_object('ok', false, 'error', 'That is your listing');
  end if;

  insert into public.moose_wallets (user_id, coins) values (me, 0)
    on conflict (user_id) do nothing;
  insert into public.moose_wallets (user_id, coins) values (seller, 0)
    on conflict (user_id) do nothing;
  select w.coins into have from public.moose_wallets w where w.user_id = me for update;
  if coalesce(have, 0) < cost then
    return jsonb_build_object(
      'ok', false,
      'error', 'Need ' || cost::text || ' moose. You have ' || coalesce(have, 0)::text,
      'coins', coalesce(have, 0),
      'need', cost
    );
  end if;
  perform 1 from public.moose_wallets w where w.user_id = seller for update;

  cut := greatest(1, floor(cost * 0.05));
  net := cost - cut;

  update public.moose_wallets set coins = coins - cost, updated_at = now() where user_id = me;
  update public.moose_wallets set coins = coins + net, updated_at = now() where user_id = seller;
  insert into public.moose_house (id, coins) values (1, cut)
    on conflict (id) do update
      set coins = public.moose_house.coins + excluded.coins, updated_at = now();
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref) values
    (me, false, -cost, 'resale_buy', lower(nm)),
    (seller, false, net, 'resale_sell', lower(nm)),
    (null, true, cut, 'resale_cut', lower(nm));
  update public.owned_names
    set user_id = me, listed_for_sale = false, sale_price_cents = null, sale_price_coins = null
    where lower(name) = lower(nm);

  return jsonb_build_object('ok', true, 'name', nm, 'coins', have - cost, 'spent', cost, 'seller_net', net);
end;
$$;
revoke all on function public.moose_spend_resale(text) from public;
grant execute on function public.moose_spend_resale(text) to authenticated;
