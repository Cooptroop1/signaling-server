-- Fresh names: bought numbers/letters/extra names go back on sale.
-- Signup names stay. admin and reserved stay.
-- Numbers 1-10 cost 100,000 moose. 11-999 stay card prices.

alter table public.vanity_numbers add column if not exists price_coins int;

-- Point profiles at their free signup name if they were wearing a bought one.
update public.profiles p
set display_name = s.name
from public.owned_names s
where s.user_id = p.id
  and s.kind = 'signup'
  and exists (
    select 1 from public.owned_names b
    where b.user_id = p.id
      and b.kind in ('number', 'letter')
      and lower(b.name) = lower(p.display_name)
  );

-- If they only have bought names, keep the one they are using as signup.
update public.owned_names o
set kind = 'signup',
    listed_for_sale = false,
    sale_price_cents = null,
    sale_price_coins = null
where o.kind in ('number', 'letter')
  and not exists (
    select 1 from public.owned_names s
    where s.user_id = o.user_id and s.kind = 'signup'
  )
  and lower(o.name) = (
    select lower(p.display_name) from public.profiles p where p.id = o.user_id
  );

delete from public.owned_names
where kind in ('number', 'letter')
  and lower(name) not in ('admin', 'anonomoose', 'moose', 'support', 'staff', 'help', 'root', 'system');

update public.vanity_numbers
set status = 'listed',
    owner_id = null,
    held_forever = false,
    current_bid_cents = null,
    updated_at = now();

update public.vanity_numbers
set price_coins = 100000,
    gold = true,
    status = 'listed',
    held_forever = false
where n between 1 and 10;

update public.vanity_numbers
set price_coins = null
where n between 11 and 999;

update public.vanity_letters
set status = 'listed',
    owner_id = null,
    updated_at = now()
where coalesce(status, '') = 'sold';

create or replace function public.moose_number_check(p_n int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  shop public.moose_shop%rowtype;
  v public.vanity_numbers%rowtype;
  coins int := 0;
begin
  if p_n is null or p_n < 1 or p_n > 999 then
    return jsonb_build_object('ok', false, 'error', 'Pick a number from 1 to 999');
  end if;
  select * into shop from public.moose_shop where id = 1;
  select * into v from public.vanity_numbers where n = p_n;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Not a reserved number');
  end if;
  coins := coalesce(v.price_coins, 0);
  if p_n >= 1 and p_n <= 10 then
    coins := 100000;
  end if;
  return jsonb_build_object(
    'ok', true,
    'kind', 'number',
    'n', v.n,
    'status', case
      when v.status = 'sold' then 'sold'
      when coalesce(shop.numbers_on, false) then 'listed'
      else 'held' end,
    'price_cents', coalesce(v.buy_now_cents, v.price_cents),
    'price_coins', coins,
    'gold', coalesce(v.gold, false) or (p_n >= 1 and p_n <= 10),
    'held_forever', false,
    'current_bid_cents', v.current_bid_cents,
    'shop_on', coalesce(shop.numbers_on, false),
    'available', (coalesce(v.status, 'held') <> 'sold' and coalesce(shop.numbers_on, false))
  );
end;
$$;
grant execute on function public.moose_number_check(int) to authenticated, anon;

create or replace function public.moose_spend_number(p_n int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  cost int := 100000;
  have bigint;
  st text;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  if p_n is null or p_n < 1 or p_n > 10 then
    return jsonb_build_object('ok', false, 'error', 'Numbers 1–10 are 100,000 moose. 11–999 are card.');
  end if;
  if exists (select 1 from public.moose_shop s where s.id = 1 and s.numbers_on = false) then
    return jsonb_build_object('ok', false, 'error', 'Numbers are off');
  end if;
  select v.status into st from public.vanity_numbers v where v.n = p_n for update;
  if st is null then
    return jsonb_build_object('ok', false, 'error', 'Not a reserved number');
  end if;
  if st = 'sold' or exists (select 1 from public.owned_names o where o.name = p_n::text) then
    return jsonb_build_object('ok', false, 'error', 'That number is taken');
  end if;

  insert into public.moose_wallets (user_id, coins) values (me, 0)
    on conflict (user_id) do nothing;
  select w.coins into have from public.moose_wallets w where w.user_id = me for update;
  if coalesce(have, 0) < cost then
    return jsonb_build_object(
      'ok', false,
      'error', 'Need 100,000 moose. You have ' || coalesce(have, 0)::text,
      'coins', coalesce(have, 0),
      'need', cost
    );
  end if;

  update public.moose_wallets set coins = coins - cost, updated_at = now() where user_id = me;
  perform public.moose_pay_admin(cost, 'number', p_n::text);
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref)
    values (me, false, -cost, 'number', p_n::text);
  begin
    insert into public.owned_names (name, user_id, kind) values (p_n::text, me, 'number');
  exception when unique_violation then
    update public.moose_wallets set coins = coins + cost, updated_at = now() where user_id = me;
    perform public.moose_pay_admin(-cost, 'number_refund', p_n::text);
    return jsonb_build_object('ok', false, 'error', 'That number is taken');
  end;
  update public.vanity_numbers
    set status = 'sold', owner_id = me, updated_at = now()
    where n = p_n;
  return jsonb_build_object('ok', true, 'name', p_n::text, 'n', p_n, 'coins', have - cost, 'spent', cost);
end;
$$;
revoke all on function public.moose_spend_number(int) from public;
grant execute on function public.moose_spend_number(int) to authenticated;
