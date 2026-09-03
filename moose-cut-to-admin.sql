-- Shop cut (5% of used moose sales, and extra-name 20 moose) goes to
-- whoever owns the name "admin". Moves the current pot too. Safe twice.

create or replace function public.moose_admin_uid()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select o.user_id from public.owned_names o where lower(o.name) = 'admin' limit 1),
    (select p.id from public.profiles p where lower(p.display_name) = 'admin' limit 1)
  );
$$;
revoke all on function public.moose_admin_uid() from public, anon, authenticated;

create or replace function public.moose_pay_admin(p_coins bigint, p_reason text, p_ref text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  a uuid := public.moose_admin_uid();
begin
  if a is null or p_coins is null or p_coins = 0 then
    return a;
  end if;
  insert into public.moose_wallets (user_id, coins) values (a, 0)
    on conflict (user_id) do nothing;
  if p_coins > 0 then
    update public.moose_wallets
      set coins = coins + p_coins, updated_at = now()
      where user_id = a;
  else
    update public.moose_wallets
      set coins = coins + p_coins, updated_at = now()
      where user_id = a and coins + p_coins >= 0;
  end if;
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref)
    values (a, false, p_coins, coalesce(p_reason, 'admin_cut'), p_ref);
  return a;
end;
$$;
revoke all on function public.moose_pay_admin(bigint, text, text) from public, anon, authenticated;

create or replace function public.moose_admin_coins()
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  a uuid := public.moose_admin_uid();
  n bigint;
begin
  if a is not null then
    select w.coins into n from public.moose_wallets w where w.user_id = a;
    if n is not null then return n; end if;
  end if;
  select h.coins into n from public.moose_house h where h.id = 1;
  return coalesce(n, 0);
end;
$$;
revoke all on function public.moose_admin_coins() from public, anon, authenticated;
grant execute on function public.moose_admin_coins() to service_role;

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
  perform public.moose_pay_admin(cut, 'resale_cut', lower(nm));
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref) values
    (me, false, -cost, 'resale_buy', lower(nm)),
    (seller, false, net, 'resale_sell', lower(nm));
  update public.owned_names
    set user_id = me, listed_for_sale = false, sale_price_cents = null, sale_price_coins = null
    where lower(name) = lower(nm);

  return jsonb_build_object('ok', true, 'name', nm, 'coins', have - cost, 'spent', cost, 'seller_net', net);
end;
$$;
revoke all on function public.moose_spend_resale(text) from public;
grant execute on function public.moose_spend_resale(text) to authenticated;

create or replace function public.moose_spend_claim(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
  cost int := 20;
  have bigint;
  reserved text[] := array['admin', 'anonomoose', 'moose', 'support', 'staff', 'help', 'root', 'system'];
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(coalesce(p_name, '')), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 4 or char_length(nm) > 16 then
    return jsonb_build_object('ok', false, 'error', 'Use 4–16 letters or numbers');
  end if;
  if nm ~ '^[0-9]+$' and nm::bigint >= 1 and nm::bigint <= 999 then
    return jsonb_build_object('ok', false, 'error', 'Numbers 1–999 are under Numbers');
  end if;
  if lower(nm) = any (reserved) then
    return jsonb_build_object('ok', false, 'error', 'That name is reserved');
  end if;
  if exists (select 1 from public.moose_shop s where s.id = 1 and s.names_claim_on = false) then
    return jsonb_build_object('ok', false, 'error', 'Name claims are off');
  end if;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm))
     or exists (select 1 from public.profiles p where lower(p.display_name) = lower(nm)) then
    return jsonb_build_object('ok', false, 'error', 'That name is taken');
  end if;

  insert into public.moose_wallets (user_id, coins) values (me, 0)
    on conflict (user_id) do nothing;
  select w.coins into have from public.moose_wallets w where w.user_id = me for update;
  if coalesce(have, 0) < cost then
    return jsonb_build_object(
      'ok', false,
      'error', 'Need 20 moose. You have ' || coalesce(have, 0)::text,
      'coins', coalesce(have, 0),
      'need', cost
    );
  end if;

  update public.moose_wallets
    set coins = coins - cost, updated_at = now()
    where user_id = me;
  perform public.moose_pay_admin(cost, 'claim', lower(nm));
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref) values
    (me, false, -cost, 'claim', lower(nm));
  begin
    insert into public.owned_names (name, user_id, kind) values (nm, me, 'letter');
  exception when unique_violation then
    update public.moose_wallets set coins = coins + cost, updated_at = now() where user_id = me;
    perform public.moose_pay_admin(-cost, 'claim_refund', lower(nm));
    return jsonb_build_object('ok', false, 'error', 'That name is taken');
  end;
  return jsonb_build_object('ok', true, 'name', nm, 'coins', have - cost, 'spent', cost);
end;
$$;
revoke all on function public.moose_spend_claim(text) from public;
grant execute on function public.moose_spend_claim(text) to authenticated;

-- Move whatever is already in the pot onto admin (once).
do $$
declare
  a uuid := public.moose_admin_uid();
  pot bigint;
begin
  select h.coins into pot from public.moose_house h where h.id = 1;
  if a is not null and coalesce(pot, 0) > 0 then
    perform public.moose_pay_admin(pot, 'house_to_admin', 'moose_house');
    update public.moose_house set coins = 0, updated_at = now() where id = 1;
  end if;
end $$;
