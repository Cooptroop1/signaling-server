-- Moose coins. Paste this in the Supabase SQL editor once.
-- 10 moose = £1. Extra names = 20 moose. Coins cannot be cashed out.
-- Stripe is only used to buy coin packs. Name spends never hit Stripe.

create table if not exists public.moose_wallets (
  user_id uuid primary key references auth.users (id) on delete cascade,
  coins bigint not null default 0 check (coins >= 0),
  updated_at timestamptz default now()
);
alter table public.moose_wallets enable row level security;
drop policy if exists "wallet self read" on public.moose_wallets;
create policy "wallet self read" on public.moose_wallets
  for select using (auth.uid() = user_id);

create table if not exists public.moose_house (
  id int primary key default 1,
  coins bigint not null default 0 check (coins >= 0),
  updated_at timestamptz default now()
);
insert into public.moose_house (id, coins) values (1, 0) on conflict (id) do nothing;
alter table public.moose_house enable row level security;

create table if not exists public.moose_coin_ledger (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  house boolean not null default false,
  delta bigint not null,
  reason text not null,
  ref text,
  created_at timestamptz default now()
);
alter table public.moose_coin_ledger enable row level security;
create unique index if not exists moose_coin_pack_session
  on public.moose_coin_ledger (ref)
  where reason = 'stripe_pack' and ref is not null;

create or replace function public.moose_my_wallet()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  have bigint;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first', 'coins', 0);
  end if;
  insert into public.moose_wallets (user_id, coins) values (me, 0)
    on conflict (user_id) do nothing;
  select w.coins into have from public.moose_wallets w where w.user_id = me;
  return jsonb_build_object('ok', true, 'coins', coalesce(have, 0));
end;
$$;
revoke all on function public.moose_my_wallet() from public;
grant execute on function public.moose_my_wallet() to authenticated;

create or replace function public.moose_credit_coins(p_user uuid, p_coins int, p_session text, p_pence int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  have bigint;
begin
  if p_user is null or p_coins is null or p_coins < 1 or p_coins > 100000 then
    return jsonb_build_object('ok', false, 'error', 'Bad pack');
  end if;
  if p_session is null or char_length(p_session) < 8 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  if p_pence is null or p_pence <> (p_coins * 10) then
    return jsonb_build_object('ok', false, 'error', 'Pack does not match £1 = 10 moose');
  end if;
  if exists (select 1 from public.moose_coin_ledger l where l.reason = 'stripe_pack' and l.ref = p_session) then
    select w.coins into have from public.moose_wallets w where w.user_id = p_user;
    return jsonb_build_object('ok', true, 'coins', coalesce(have, 0), 'already', true);
  end if;
  insert into public.moose_wallets (user_id, coins) values (p_user, 0)
    on conflict (user_id) do nothing;
  update public.moose_wallets
    set coins = coins + p_coins, updated_at = now()
    where user_id = p_user
    returning coins into have;
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref)
    values (p_user, false, p_coins, 'stripe_pack', p_session);
  return jsonb_build_object('ok', true, 'coins', have, 'added', p_coins);
end;
$$;
revoke all on function public.moose_credit_coins(uuid, int, text, int) from public, anon, authenticated;
grant execute on function public.moose_credit_coins(uuid, int, text, int) to service_role;

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
  insert into public.moose_house (id, coins) values (1, cost)
    on conflict (id) do update
      set coins = public.moose_house.coins + excluded.coins, updated_at = now();
  insert into public.moose_coin_ledger (user_id, house, delta, reason, ref) values
    (me, false, -cost, 'claim', lower(nm)),
    (null, true, cost, 'claim', lower(nm));
  begin
    insert into public.owned_names (name, user_id, kind) values (nm, me, 'letter');
  exception when unique_violation then
    update public.moose_wallets set coins = coins + cost, updated_at = now() where user_id = me;
    update public.moose_house set coins = coins - cost, updated_at = now() where id = 1 and coins >= cost;
    return jsonb_build_object('ok', false, 'error', 'That name is taken');
  end;
  return jsonb_build_object('ok', true, 'name', nm, 'coins', have - cost, 'spent', cost);
end;
$$;
revoke all on function public.moose_spend_claim(text) from public;
grant execute on function public.moose_spend_claim(text) to authenticated;
