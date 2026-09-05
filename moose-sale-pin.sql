-- PIN-locked used-name sales + moose_spend_resale checks the PIN.
create extension if not exists pgcrypto;

alter table public.owned_names add column if not exists sale_pin_hash text;

drop function if exists public.moose_spend_resale(text);
drop function if exists public.moose_spend_resale(text, text);

create or replace function public.moose_spend_resale(p_name text, p_pin text default '')
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
  need text;
  got text;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(coalesce(p_name, '')), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 then
    return jsonb_build_object('ok', false, 'error', 'Missing name');
  end if;

  select o.user_id, coalesce(o.sale_price_coins, 0), o.sale_pin_hash
    into seller, cost, need
    from public.owned_names o
    where lower(o.name) = lower(nm) and o.listed_for_sale = true
    for update;
  if seller is null or cost < 20 then
    return jsonb_build_object('ok', false, 'error', 'Not listed for moose');
  end if;
  if seller = me then
    return jsonb_build_object('ok', false, 'error', 'That is your listing');
  end if;
  if coalesce(need, '') <> '' then
    got := encode(digest('moose-sale|' || lower(nm) || '|' || coalesce(p_pin, ''), 'sha256'), 'hex');
    if got <> need then
      return jsonb_build_object('ok', false, 'error', 'Wrong PIN');
    end if;
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
  perform public.moose_pay_admin(cut, 'resale_cut', lower(nm));
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref) values
    (me, false, -cost, 'resale_buy', lower(nm)),
    (seller, false, net, 'resale_sell', lower(nm));
  update public.owned_names
    set user_id = me, listed_for_sale = false, sale_price_cents = null, sale_price_coins = null, sale_pin_hash = null
    where lower(name) = lower(nm);

  return jsonb_build_object('ok', true, 'name', nm, 'coins', have - cost, 'spent', cost, 'seller_net', net);
end;
$$;
revoke all on function public.moose_spend_resale(text, text) from public;
grant execute on function public.moose_spend_resale(text, text) to authenticated;
