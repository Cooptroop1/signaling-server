-- Paste this once in Supabase → SQL Editor → Run.
-- Identity + sealed inbox only. No chat transcripts.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null unique,
  public_key text,
  identity_public_key text,
  client_id text,
  last_active timestamptz default now(),
  updated_at timestamptz default now(),
  constraint display_name_format check (display_name ~ '^[a-zA-Z0-9]{1,16}$')
);

alter table public.profiles add column if not exists public_key text;
alter table public.profiles add column if not exists identity_public_key text;
alter table public.profiles add column if not exists client_id text;
alter table public.profiles add column if not exists last_active timestamptz default now();
alter table public.profiles add column if not exists updated_at timestamptz default now();

create table if not exists public.offline_messages (
  id uuid primary key default gen_random_uuid(),
  to_user_id uuid not null references public.profiles (id) on delete cascade,
  from_user_id uuid,
  payload jsonb,
  message text,
  created_at timestamptz default now()
);

alter table public.offline_messages add column if not exists payload jsonb;
alter table public.offline_messages add column if not exists from_user_id uuid;
alter table public.offline_messages add column if not exists message text;
do $$ begin
  alter table public.offline_messages alter column from_user_id drop not null;
exception when others then null;
end $$;

create index if not exists offline_messages_to_user_idx
  on public.offline_messages (to_user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.offline_messages enable row level security;

drop policy if exists "profiles readable" on public.profiles;
drop policy if exists "profiles read own" on public.profiles;
create policy "profiles read own" on public.profiles
  for select to authenticated
  using (auth.uid() = id);
revoke select on public.profiles from anon;

drop policy if exists "profiles insert own" on public.profiles;
create policy "profiles insert own" on public.profiles
  for insert to authenticated with check (auth.uid() = id);

drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "mail insert authed" on public.offline_messages;
create policy "mail insert authed" on public.offline_messages
  for insert to authenticated with check (true);

drop policy if exists "mail read own" on public.offline_messages;
create policy "mail read own" on public.offline_messages
  for select to authenticated using (to_user_id = auth.uid());

drop policy if exists "mail delete own" on public.offline_messages;
create policy "mail delete own" on public.offline_messages
  for delete to authenticated using (to_user_id = auth.uid());

create table if not exists public.owned_names (
  id uuid primary key default gen_random_uuid(),
  name text not null check (name ~ '^[a-zA-Z0-9]{1,16}$'),
  user_id uuid not null references public.profiles (id) on delete cascade,
  kind text not null default 'signup',
  listed_for_sale boolean not null default false,
  created_at timestamptz default now()
);
create unique index if not exists owned_names_ci on public.owned_names (lower(name));
create index if not exists owned_names_user_idx on public.owned_names (user_id);
alter table public.owned_names enable row level security;
drop policy if exists "owned names own" on public.owned_names;
create policy "owned names own" on public.owned_names
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  name text;
begin
  name := coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1));
  name := regexp_replace(name, '[^a-zA-Z0-9]', '', 'g');
  if char_length(name) < 1 then name := 'user'; end if;
  if char_length(name) > 16 then name := left(name, 16); end if;
  if char_length(name) < 4 then
    raise exception 'Display name must be 4-16 letters or numbers';
  end if;
  if name ~ '^[0-9]+$' and name::int >= 1 and name::int <= 999 then
    raise exception 'Numbers 1-999 are reserved';
  end if;
  if exists (select 1 from public.profiles p where lower(p.display_name) = lower(name))
     or exists (select 1 from public.owned_names o where lower(o.name) = lower(name)) then
    raise exception 'Display name already taken';
  end if;
  insert into public.profiles (id, display_name)
  values (new.id, name)
  on conflict (id) do nothing;
  insert into public.owned_names (name, user_id, kind)
  values (name, new.id, 'signup')
  on conflict do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

do $$
begin
  alter publication supabase_realtime add table public.offline_messages;
exception when duplicate_object then
  null;
end $$;

-- ===== Logged-in extras (1-14) =====
alter table public.profiles add column if not exists hide_last_seen boolean default false;
alter table public.profiles add column if not exists discover text default 'anyone';
alter table public.profiles add column if not exists device_id text;
alter table public.profiles add column if not exists qr_token text;
alter table public.profiles add column if not exists qr_expires timestamptz;

alter table public.offline_messages add column if not exists expires_at timestamptz;
alter table public.offline_messages add column if not exists kind text;

create table if not exists public.moose_trust (
  owner_id uuid not null references public.profiles (id) on delete cascade,
  peer_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz default now(),
  primary key (owner_id, peer_id)
);
alter table public.moose_trust enable row level security;
drop policy if exists "trust own" on public.moose_trust;
create policy "trust own" on public.moose_trust
  for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create table if not exists public.moose_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  device_id text not null,
  label text,
  last_seen timestamptz default now(),
  revoked boolean default false,
  unique (user_id, device_id)
);
alter table public.moose_devices enable row level security;
drop policy if exists "devices own" on public.moose_devices;
create policy "devices own" on public.moose_devices
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create or replace function public.lookup_moose(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.profiles%rowtype;
  me uuid := auth.uid();
  is_trusted boolean := false;
  online boolean := false;
begin
  if p_name is null or length(trim(p_name)) < 1 then
    return null;
  end if;
  select o.user_id into r.id from public.owned_names o
    where lower(o.name) = lower(trim(p_name)) limit 1;
  if not found then
    select * into r from public.profiles where lower(display_name) = lower(trim(p_name)) limit 1;
  else
    select * into r from public.profiles where id = r.id;
  end if;
  if not found then
    return null;
  end if;
  if r.id <> me then
    if coalesce(r.discover, 'anyone') = 'nobody' then
      return null;
    end if;
    if r.discover = 'trusted' then
      select exists(
        select 1 from public.moose_trust t
        where t.owner_id = r.id and t.peer_id = me
      ) into is_trusted;
      if not is_trusted then
        return null;
      end if;
    end if;
  end if;
  online := (r.last_active is not null and r.last_active > now() - interval '5 minutes' and coalesce(r.hide_last_seen, false) = false);
  return jsonb_build_object(
    'id', r.id,
    'display_name', coalesce(
      (select o.name from public.owned_names o
        where o.user_id = r.id and lower(o.name) = lower(trim(p_name)) limit 1),
      r.display_name
    ),
    'public_key', r.public_key,
    'identity_public_key', r.identity_public_key,
    'last_active', case when coalesce(r.hide_last_seen, false) then null else r.last_active end,
    'status', case when online then 'online' else 'offline' end
  );
end;
$$;

grant execute on function public.lookup_moose(text) to authenticated, anon;

create or replace function public.moose_name_taken(p_name text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  nm text;
begin
  nm := regexp_replace(trim(coalesce(p_name, '')), '[^a-zA-Z0-9]', '', 'g');
  if char_length(nm) < 1 then
    return true;
  end if;
  return exists (select 1 from public.owned_names o where lower(o.name) = lower(nm))
      or exists (select 1 from public.profiles p where lower(p.display_name) = lower(nm));
end;
$$;
revoke all on function public.moose_name_taken(text) from public;
grant execute on function public.moose_name_taken(text) to anon, authenticated;

create or replace function public.lookup_moose_qr(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.profiles%rowtype;
begin
  if p_token is null or char_length(trim(p_token)) < 8 then
    return null;
  end if;
  select * into r from public.profiles
    where qr_token = trim(p_token)
      and qr_expires is not null
      and qr_expires > now()
    limit 1;
  if not found then
    return null;
  end if;
  return public.lookup_moose(r.display_name);
end;
$$;
revoke all on function public.lookup_moose_qr(text) from public;
grant execute on function public.lookup_moose_qr(text) to anon, authenticated;

-- One name only, capitals do not count as different
with d as (
  select id, display_name,
    row_number() over (partition by lower(display_name) order by updated_at nulls last, id) as rn
  from public.profiles
)
update public.profiles p
set display_name = left(regexp_replace(p.display_name, '[0-9]+$', ''), 14) || d.rn::text
from d
where p.id = d.id and d.rn > 1;

create unique index if not exists profiles_display_name_ci
  on public.profiles (lower(display_name));

-- Moose numbers 1-999 (held until you switch sales on)
create table if not exists public.moose_shop (
  id int primary key default 1,
  numbers_on boolean default false,
  letters_on boolean default false,
  stripe_ready boolean default false,
  video_notes_on boolean default true,
  video_calls_on boolean default true
);
alter table public.moose_shop add column if not exists video_notes_on boolean default true;
alter table public.moose_shop add column if not exists video_calls_on boolean default true;
insert into public.moose_shop (id, numbers_on, letters_on, stripe_ready)
values (1, false, false, false)
on conflict (id) do nothing;

create table if not exists public.vanity_numbers (
  n int primary key check (n >= 1 and n <= 999),
  status text not null default 'held' check (status in ('held', 'listed', 'sold')),
  owner_id uuid references public.profiles (id) on delete set null,
  price_cents int not null default 500,
  updated_at timestamptz default now()
);

insert into public.vanity_numbers (n, status, price_cents)
select g,
  'held',
  case when g <= 9 then 2500 when g <= 99 then 1000 else 500 end
from generate_series(1, 999) g
on conflict (n) do nothing;

alter table public.moose_shop enable row level security;
alter table public.vanity_numbers enable row level security;
drop policy if exists "shop read" on public.moose_shop;
create policy "shop read" on public.moose_shop for select using (true);
drop policy if exists "vanity read" on public.vanity_numbers;
create policy "vanity read" on public.vanity_numbers for select using (true);

create or replace function public.moose_number_check(p_n int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  shop public.moose_shop%rowtype;
  v public.vanity_numbers%rowtype;
begin
  if p_n is null or p_n < 1 or p_n > 999 then
    return jsonb_build_object('ok', false, 'error', 'Pick a number from 1 to 999');
  end if;
  select * into shop from public.moose_shop where id = 1;
  select * into v from public.vanity_numbers where n = p_n;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Not a reserved number');
  end if;
  return jsonb_build_object(
    'ok', true,
    'n', v.n,
    'status', v.status,
    'price_cents', v.price_cents,
    'shop_on', coalesce(shop.numbers_on, false),
    'available', (v.status = 'listed' and coalesce(shop.numbers_on, false))
  );
end;
$$;

grant execute on function public.moose_number_check(int) to authenticated, anon;

alter table public.vanity_numbers add column if not exists gold boolean default false;
alter table public.vanity_numbers add column if not exists held_forever boolean default false;
alter table public.vanity_numbers add column if not exists buy_now_cents int;
alter table public.vanity_numbers add column if not exists current_bid_cents int;

update public.vanity_numbers
set held_forever = true, gold = true, status = 'held'
where n in (1, 7)
  and coalesce(status, 'held') <> 'sold';

update public.vanity_numbers
set gold = true,
    buy_now_cents = case n
      when 2 then 10000 when 3 then 8000 when 4 then 6000 when 5 then 8000
      when 6 then 5000 when 8 then 5000 when 9 then 8000 else 10000 end
where n in (2,3,4,5,6,8,9)
  and coalesce(status, 'held') <> 'sold';

create table if not exists public.vanity_letters (
  name text primary key,
  status text not null default 'listed' check (status in ('held', 'listed', 'sold')),
  owner_id uuid references public.profiles (id) on delete set null,
  price_cents int not null default 1000,
  gold boolean default false,
  updated_at timestamptz default now(),
  constraint vanity_letter_format check (name ~ '^[A-Za-z0-9]{1,3}$')
);
alter table public.vanity_letters enable row level security;
drop policy if exists "letters read" on public.vanity_letters;
create policy "letters read" on public.vanity_letters for select using (true);

create table if not exists public.vanity_bids (
  id uuid primary key default gen_random_uuid(),
  kind text not null,
  target text not null,
  user_id uuid references public.profiles (id) on delete cascade,
  amount_cents int not null,
  created_at timestamptz default now()
);
alter table public.vanity_bids enable row level security;
drop policy if exists "bids read" on public.vanity_bids;
create policy "bids read" on public.vanity_bids for select using (true);
drop policy if exists "bids insert own" on public.vanity_bids;
create policy "bids insert own" on public.vanity_bids
  for insert to authenticated with check (auth.uid() = user_id);

create or replace function public.moose_letter_check(p_name text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  shop public.moose_shop%rowtype;
  v public.vanity_letters%rowtype;
  nm text;
  price int;
  mixed boolean := false;
  as_num int;
begin
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 or char_length(nm) > 3 then
    return jsonb_build_object('ok', false, 'error', 'Use 1 to 3 letters or numbers, like Ace, AA1, 12A');
  end if;
  if nm ~ '^[0-9]+$' then
    as_num := nm::int;
    if as_num >= 1 and as_num <= 999 then
      return public.moose_number_check(as_num);
    end if;
  end if;
  mixed := nm ~ '[0-9]' and nm ~ '[A-Za-z]';
  select * into shop from public.moose_shop where id = 1;
  if mixed then
    price := case char_length(nm) when 1 then 300000 when 2 then 25000 else 2000 end;
  else
    price := case char_length(nm) when 1 then 300000 when 2 then 8000 else 1000 end;
  end if;
  select * into v from public.vanity_letters where lower(name) = lower(nm);
  if found then
    return jsonb_build_object(
      'ok', true, 'kind', 'letter', 'name', v.name, 'status', v.status,
      'price_cents', v.price_cents, 'gold', coalesce(v.gold, mixed or char_length(nm) = 1),
      'shop_on', coalesce(shop.letters_on, false),
      'available', (v.status = 'listed' and coalesce(shop.letters_on, false))
    );
  end if;
  return jsonb_build_object(
    'ok', true, 'kind', 'letter', 'name', nm, 'status',
    case when coalesce(shop.letters_on, false) then 'listed' else 'held' end,
    'price_cents', price, 'gold', mixed or char_length(nm) = 1,
    'shop_on', coalesce(shop.letters_on, false),
    'available', coalesce(shop.letters_on, false)
  );
end;
$$;
grant execute on function public.moose_letter_check(text) to authenticated, anon;

create or replace function public.moose_place_bid(p_kind text, p_target text, p_amount int)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  me uuid := auth.uid();
  n int;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in to bid');
  end if;
  if p_amount is null or p_amount < 100 then
    return jsonb_build_object('ok', false, 'error', 'Bid too small');
  end if;
  insert into public.vanity_bids (kind, target, user_id, amount_cents)
  values (p_kind, p_target, me, p_amount);
  if p_kind = 'number' then
    update public.vanity_numbers v
      set current_bid_cents = greatest(coalesce(v.current_bid_cents, 0), p_amount)
      where v.n = (p_target)::int and coalesce(v.held_forever, false) = false;
  end if;
  return jsonb_build_object('ok', true, 'amount_cents', p_amount);
end;
$$;
grant execute on function public.moose_place_bid(text, text, int) to authenticated;

create or replace function public.moose_number_check(p_n int)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  shop public.moose_shop%rowtype;
  v public.vanity_numbers%rowtype;
  forever boolean := false;
begin
  if p_n is null or p_n < 1 or p_n > 999 then
    return jsonb_build_object('ok', false, 'error', 'Pick a number from 1 to 999');
  end if;
  select * into shop from public.moose_shop where id = 1;
  select * into v from public.vanity_numbers where n = p_n;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Not a reserved number');
  end if;
  forever := coalesce(v.held_forever, false);
  return jsonb_build_object(
    'ok', true,
    'kind', 'number',
    'n', v.n,
    'status', case
      when forever then 'held'
      when v.status = 'sold' then 'sold'
      when coalesce(shop.numbers_on, false) then 'listed'
      else 'held' end,
    'price_cents', coalesce(v.buy_now_cents, v.price_cents),
    'gold', coalesce(v.gold, false),
    'held_forever', forever,
    'current_bid_cents', v.current_bid_cents,
    'shop_on', coalesce(shop.numbers_on, false),
    'available', (not forever and coalesce(v.status, 'held') <> 'sold' and coalesce(shop.numbers_on, false))
  );
end;
$$;

grant execute on function public.moose_number_check(int) to authenticated, anon;

create or replace function public.moose_apply_purchase(p_name text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
begin
  return jsonb_build_object('ok', false, 'error', 'Pay through the shop. This path is closed.');
end;
$$;
revoke all on function public.moose_apply_purchase(text) from public, anon, authenticated;
-- paid names: service-role moose_apply_paid only

create or replace function public.moose_set_active_name(p_name text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  if not exists (select 1 from public.owned_names o where o.user_id = me and lower(o.name) = lower(nm)) then
    return jsonb_build_object('ok', false, 'error', 'You do not own that name');
  end if;
  select o.name into nm from public.owned_names o where o.user_id = me and lower(o.name) = lower(nm) limit 1;
  update public.profiles set display_name = nm, updated_at = now() where id = me;
  return jsonb_build_object('ok', true, 'name', nm);
end;
$$;
grant execute on function public.moose_set_active_name(text) to authenticated;

insert into public.owned_names (name, user_id, kind)
select p.display_name, p.id, 'signup'
from public.profiles p
where not exists (
  select 1 from public.owned_names o where lower(o.name) = lower(p.display_name)
);

alter table public.profiles add column if not exists wipe_epoch bigint;

create table if not exists public.vanity_receipts (
  session_id text primary key,
  user_id uuid not null,
  name text not null,
  amount_cents int not null,
  created_at timestamptz default now()
);
alter table public.vanity_receipts enable row level security;
drop policy if exists "receipts read own" on public.vanity_receipts;
create policy "receipts read own" on public.vanity_receipts
  for select to authenticated using (user_id = auth.uid());

drop policy if exists "owned names own" on public.owned_names;
create policy "owned names read own" on public.owned_names
  for select to authenticated using (user_id = auth.uid());

create or replace function public.moose_apply_paid(p_user uuid, p_name text, p_session text, p_amount int)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  nm text;
  n int;
begin
  if auth.role() is distinct from 'service_role' then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_user is null or p_session is null or p_amount is null or p_amount < 100 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 or char_length(nm) > 16 then
    return jsonb_build_object('ok', false, 'error', 'Bad name');
  end if;
  insert into public.vanity_receipts (session_id, user_id, name, amount_cents)
  values (p_session, p_user, nm, p_amount)
  on conflict (session_id) do nothing;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm) and o.user_id <> p_user) then
    return jsonb_build_object('ok', false, 'error', 'Already owned');
  end if;
  if nm ~ '^[0-9]+$' then
    n := nm::int;
    if n < 1 or n > 999 then
      return jsonb_build_object('ok', false, 'error', 'Not for sale');
    end if;
    update public.vanity_numbers vn
      set status = 'sold', owner_id = p_user, updated_at = now()
      where vn.n = n and coalesce(vn.held_forever, false) = false
        and (coalesce(vn.status, 'held') <> 'sold' or vn.owner_id = p_user);
  else
    insert into public.vanity_letters (name, status, owner_id, price_cents)
    values (nm, 'sold', p_user, p_amount)
    on conflict (name) do update
      set status = 'sold', owner_id = p_user
      where vanity_letters.owner_id is null or vanity_letters.owner_id = p_user;
  end if;
  insert into public.owned_names (name, user_id, kind)
  values (nm, p_user, case when nm ~ '^[0-9]+$' then 'number' else 'letter' end)
  on conflict do nothing;
  return jsonb_build_object('ok', true, 'name', nm);
end;
$$;
revoke all on function public.moose_apply_paid(uuid, text, text, int) from public, anon, authenticated;
grant execute on function public.moose_apply_paid(uuid, text, text, int) to service_role;

create or replace function public.moose_apply_purchase(p_name text)
returns jsonb
language plpgsql security definer set search_path = public
as $$
begin
  return jsonb_build_object('ok', false, 'error', 'Pay through the shop. This path is closed.');
end;
$$;
revoke all on function public.moose_apply_purchase(text) from public, anon, authenticated;
-- paid names: service-role moose_apply_paid only
do $$
begin
  alter publication supabase_realtime add table public.profiles;
exception when duplicate_object then
  null;
end $$;

-- LIVE SHOP ROWS ARE NOT RESET HERE.
-- Numbers 1 and 2 stay as they are in Supabase. Do not paste a wipe.
-- Reset test buys. Buy now: #2 = £10,000 → #9 = £6,000 → #999 = £10
-- delete from public.owned_names where kind in ('number', 'letter');
-- delete from public.vanity_receipts where true;
-- delete from public.vanity_bids where true;

-- update public.profiles p
-- set display_name = o.name
-- from public.owned_names o
-- where o.user_id = p.id and o.kind = 'signup'
--   and p.display_name ~ '^[A-Za-z0-9]{1,3}$';
--
-- update public.vanity_numbers
-- set
--   owner_id = null,
--   current_bid_cents = 0,
--   held_forever = (n in (1, 7)),
--   gold = (n between 2 and 9),
--   status = case when n in (1, 7) then 'held' else 'listed' end,
--   buy_now_cents = case
--     when n in (1, 7) then 0
--     when n between 2 and 9 then (1000000 - round(400000.0 * (n - 2) / 7.0))::int
--     else greatest(1000, (600000 - round(599000.0 * (n - 9) / 990.0))::int)
--   end,
--   price_cents = case
--     when n in (1, 7) then 0
--     when n between 2 and 9 then (1000000 - round(400000.0 * (n - 2) / 7.0))::int
--     else greatest(1000, (600000 - round(599000.0 * (n - 9) / 990.0))::int)
--   end,
--   updated_at = now();

alter table public.vanity_letters add column if not exists buy_now_cents int;

-- Do not wipe live letter sales.
-- update public.vanity_letters
-- set
--   owner_id = null,
--   status = 'listed',
--   ...

insert into public.vanity_letters (name, status, price_cents, buy_now_cents, gold)
select chr(i), 'listed', 300000, 300000, true
from generate_series(65, 90) i
on conflict (name) do nothing;

-- Hide shop owner ids. Does not change who owns sold numbers (including 1 and 2).
revoke select (owner_id) on public.vanity_numbers from anon, authenticated, public;
revoke select (owner_id) on public.vanity_letters from anon, authenticated, public;
revoke select (user_id) on public.vanity_bids from anon, authenticated, public;

-- Used-name marketplace. Does not touch who owns #1 or #2.
-- Seller lists a bought name. Buyer pays list price.
-- You take Stripe's real fee + 5%. Seller net is the rest.

alter table public.owned_names add column if not exists sale_price_cents int;

create table if not exists public.name_sales (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  seller_id uuid not null,
  buyer_id uuid not null,
  list_cents int not null,
  stripe_fee_cents int not null default 0,
  platform_cents int not null default 0,
  seller_net_cents int not null default 0,
  stripe_session_id text unique,
  status text not null default 'pending_payout',
  created_at timestamptz default now()
);
alter table public.name_sales enable row level security;

create or replace function public.moose_used_listings()
returns jsonb
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'name', o.name,
    'kind', o.kind,
    'price_cents', o.sale_price_cents
  ) order by o.sale_price_cents desc, lower(o.name)), '[]'::jsonb)
  from public.owned_names o
  where o.listed_for_sale = true
    and coalesce(o.sale_price_cents, 0) >= 200
    and o.kind in ('number', 'letter')
    ;
$$;
grant execute on function public.moose_used_listings() to anon, authenticated;

create or replace function public.moose_list_name(p_name text, p_price_cents int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
  n int;
  kind text;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 then
    return jsonb_build_object('ok', false, 'error', 'Missing name');
  end if;
  if p_price_cents is null or p_price_cents < 200 or p_price_cents > 100000000 then
    return jsonb_build_object('ok', false, 'error', 'Price must be £2 to £1,000,000');
  end if;
  select o.kind into kind
  from public.owned_names o
  where o.user_id = me and lower(o.name) = lower(nm)
  limit 1;
  if kind is null then
    return jsonb_build_object('ok', false, 'error', 'You do not own that name');
  end if;
  if kind = 'signup' then
    return jsonb_build_object('ok', false, 'error', 'Free signup names cannot be sold');
  end if;
  if nm ~ '^[0-9]+$' then
    n := nm::int;
    if exists (select 1 from public.vanity_numbers v where v.n = n and coalesce(v.held_forever, false)) then
      return jsonb_build_object('ok', false, 'error', 'That number is not for sale');
    end if;
  end if;
  update public.owned_names
    set listed_for_sale = true, sale_price_cents = p_price_cents
    where user_id = me and lower(name) = lower(nm);
  return jsonb_build_object('ok', true, 'name', nm, 'price_cents', p_price_cents);
end;
$$;
grant execute on function public.moose_list_name(text, int) to authenticated;

create or replace function public.moose_unlist_name(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  update public.owned_names
    set listed_for_sale = false, sale_price_cents = null
    where user_id = me and lower(name) = lower(nm);
  return jsonb_build_object('ok', true, 'name', nm);
end;
$$;
grant execute on function public.moose_unlist_name(text) to authenticated;

create or replace function public.moose_apply_resale(p_buyer uuid, p_seller uuid, p_name text, p_session text, p_amount int, p_stripe_fee int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  nm text;
  n int;
  seller uuid;
  price int;
  platform int;
  fee int;
  net int;
  fallback text;
begin
  if auth.role() is distinct from 'service_role' then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_buyer is null or p_session is null or p_amount is null or p_amount < 200 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  if p_buyer is not distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Cannot buy your own listing');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  insert into public.vanity_receipts (session_id, user_id, name, amount_cents)
  values (p_session, p_buyer, nm, p_amount)
  on conflict (session_id) do nothing;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm) and o.user_id = p_buyer) then
    return jsonb_build_object('ok', true, 'name', nm, 'already', true);
  end if;
  select o.user_id, o.sale_price_cents into seller, price
  from public.owned_names o
  where lower(o.name) = lower(nm) and o.kind in ('number', 'letter')
  limit 1;
  if seller is null then
    return jsonb_build_object('ok', false, 'error', 'Name is not for resale');
  end if;
  if p_seller is not null and seller is distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Listing changed');
  end if;
  -- Stripe already locked p_amount at checkout. Still transfer if they unlisted after pay started.
  fee := greatest(0, coalesce(p_stripe_fee, 0));
  platform := greatest(1, round(p_amount * 5.0 / 100.0)::int);
  net := greatest(0, p_amount - fee - platform);
  update public.owned_names
    set user_id = p_buyer, listed_for_sale = false, sale_price_cents = null
    where lower(name) = lower(nm) and user_id = seller;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Could not move name');
  end if;
  if nm ~ '^[0-9]+$' then
    n := nm::int;
    update public.vanity_numbers vn
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where vn.n = n;
  else
    update public.vanity_letters
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where lower(name) = lower(nm);
  end if;
  select o.name into fallback
  from public.owned_names o
  where o.user_id = seller
  order by case when o.kind = 'signup' then 0 else 1 end, o.created_at
  limit 1;
  update public.profiles
    set display_name = coalesce(fallback, ('u' || substr(replace(seller::text, '-', ''), 1, 8))),
        updated_at = now()
    where id = seller and lower(coalesce(display_name, '')) = lower(nm);
  insert into public.name_sales (
    name, seller_id, buyer_id, list_cents, stripe_fee_cents, platform_cents, seller_net_cents, stripe_session_id, status
  ) values (
    nm, seller, p_buyer, p_amount, fee, platform, net, p_session, 'pending_payout'
  )
  on conflict (stripe_session_id) do nothing;
  return jsonb_build_object('ok', true, 'name', nm, 'seller_net_cents', net, 'platform_cents', platform, 'stripe_fee_cents', fee);
end;
$$;
revoke all on function public.moose_apply_resale(uuid, uuid, text, text, int, int) from public, anon, authenticated;
grant execute on function public.moose_apply_resale(uuid, uuid, text, text, int, int) to service_role;

-- Repair used-name list RPC types (int vs numeric 400s) and reload PostgREST.
drop function if exists public.moose_list_name(text, int);
drop function if exists public.moose_list_name(text, numeric);
create or replace function public.moose_list_name(p_name text, p_price_cents numeric)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  nm text;
  n int;
  kind text;
  price int;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in first');
  end if;
  nm := regexp_replace(trim(coalesce(p_name, '')), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 then
    return jsonb_build_object('ok', false, 'error', 'Missing name');
  end if;
  price := round(coalesce(p_price_cents, 0))::int;
  if price < 200 or price > 100000000 then
    return jsonb_build_object('ok', false, 'error', 'Price must be £2 to £1,000,000');
  end if;
  select o.kind into kind
  from public.owned_names o
  where o.user_id = me and lower(o.name) = lower(nm)
  limit 1;
  if kind is null then
    return jsonb_build_object('ok', false, 'error', 'You do not own that name');
  end if;
  if kind is not distinct from 'signup' then
    return jsonb_build_object('ok', false, 'error', 'Free signup names cannot be sold');
  end if;
  if nm ~ '^[0-9]+$' then
    n := nm::int;
    if exists (select 1 from public.vanity_numbers v where v.n = n and coalesce(v.held_forever, false)) then
      return jsonb_build_object('ok', false, 'error', 'That number is not for sale');
    end if;
  end if;
  update public.owned_names
    set listed_for_sale = true, sale_price_cents = price
    where user_id = me and lower(name) = lower(nm);
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Could not list that name');
  end if;
  return jsonb_build_object('ok', true, 'name', nm, 'price_cents', price);
end;
$$;
grant execute on function public.moose_list_name(text, numeric) to authenticated;

drop function if exists public.moose_used_listings();
create or replace function public.moose_used_listings()
returns jsonb
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'name', o.name,
    'kind', o.kind,
    'price_cents', o.sale_price_cents
  ) order by o.sale_price_cents desc, lower(o.name)), '[]'::jsonb)
  from public.owned_names o
  where o.listed_for_sale = true
    and coalesce(o.sale_price_cents, 0) >= 200
    and coalesce(o.kind, '') is distinct from 'signup'
    ;
$$;
grant execute on function public.moose_used_listings() to anon, authenticated;

notify pgrst, 'reload schema';

-- Allow used-sale of #1 and #2. Does not change who owns them now.
-- First-hand shop still will not sell them new (they stay sold).
create or replace function public.moose_apply_resale(p_buyer uuid, p_seller uuid, p_name text, p_session text, p_amount int, p_stripe_fee int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  nm text;
  n int;
  seller uuid;
  price int;
  platform int;
  fee int;
  net int;
  fallback text;
begin
  if auth.role() is distinct from 'service_role' then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_buyer is null or p_session is null or p_amount is null or p_amount < 200 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  if p_buyer is not distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Cannot buy your own listing');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  insert into public.vanity_receipts (session_id, user_id, name, amount_cents)
  values (p_session, p_buyer, nm, p_amount)
  on conflict (session_id) do nothing;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm) and o.user_id = p_buyer) then
    return jsonb_build_object('ok', true, 'name', nm, 'already', true);
  end if;
  select o.user_id, o.sale_price_cents into seller, price
  from public.owned_names o
  where lower(o.name) = lower(nm) and o.kind in ('number', 'letter')
  limit 1;
  if seller is null then
    return jsonb_build_object('ok', false, 'error', 'Name is not for resale');
  end if;
  if p_seller is not null and seller is distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Listing changed');
  end if;
  fee := greatest(0, coalesce(p_stripe_fee, 0));
  platform := greatest(1, round(p_amount * 5.0 / 100.0)::int);
  net := greatest(0, p_amount - fee - platform);
  update public.owned_names
    set user_id = p_buyer, listed_for_sale = false, sale_price_cents = null
    where lower(name) = lower(nm) and user_id = seller;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Could not move name');
  end if;
  if nm ~ '^[0-9]+$' then
    n := nm::int;
    update public.vanity_numbers vn
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where vn.n = n;
  else
    update public.vanity_letters
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where lower(name) = lower(nm);
  end if;
  select o.name into fallback
  from public.owned_names o
  where o.user_id = seller
  order by case when o.kind = 'signup' then 0 else 1 end, o.created_at
  limit 1;
  update public.profiles
    set display_name = coalesce(fallback, ('u' || substr(replace(seller::text, '-', ''), 1, 8))),
        updated_at = now()
    where id = seller and lower(coalesce(display_name, '')) = lower(nm);
  insert into public.name_sales (
    name, seller_id, buyer_id, list_cents, stripe_fee_cents, platform_cents, seller_net_cents, stripe_session_id, status
  ) values (
    nm, seller, p_buyer, p_amount, fee, platform, net, p_session, 'pending_payout'
  )
  on conflict (stripe_session_id) do nothing;
  return jsonb_build_object('ok', true, 'name', nm, 'seller_net_cents', net, 'platform_cents', platform, 'stripe_fee_cents', fee);
end;
$$;
revoke all on function public.moose_apply_resale(uuid, uuid, text, text, int, int) from public, anon, authenticated;
grant execute on function public.moose_apply_resale(uuid, uuid, text, text, int, int) to service_role;
notify pgrst, 'reload schema';


-- Stripe Connect Express for used-name sellers. Service role only.
create table if not exists public.seller_payouts (
  user_id uuid primary key references auth.users (id) on delete cascade,
  stripe_account_id text unique,
  payouts_enabled boolean not null default false,
  details_submitted boolean not null default false,
  updated_at timestamptz default now()
);
alter table public.seller_payouts enable row level security;
revoke all on public.seller_payouts from public, anon, authenticated;
grant all on public.seller_payouts to service_role;

alter table public.name_sales add column if not exists stripe_transfer_id text;

-- Fix ambiguous column "n" in paid/resale functions (Postgres 42702).
create or replace function public.moose_apply_paid(p_user uuid, p_name text, p_session text, p_amount int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_variable
declare
  nm text;
  num int;
begin
  if auth.role() is distinct from 'service_role' then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_user is null or p_session is null or p_amount is null or p_amount < 100 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  if char_length(nm) < 1 or char_length(nm) > 16 then
    return jsonb_build_object('ok', false, 'error', 'Bad name');
  end if;
  insert into public.vanity_receipts (session_id, user_id, name, amount_cents)
  values (p_session, p_user, nm, p_amount)
  on conflict (session_id) do nothing;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm) and o.user_id <> p_user) then
    return jsonb_build_object('ok', false, 'error', 'Already owned');
  end if;
  if nm ~ '^[0-9]+$' then
    num := nm::int;
    if num < 1 or num > 999 then
      return jsonb_build_object('ok', false, 'error', 'Not for sale');
    end if;
    update public.vanity_numbers vn
      set status = 'sold', owner_id = p_user, updated_at = now()
      where vn.n = num and coalesce(vn.held_forever, false) = false
        and (coalesce(vn.status, 'held') <> 'sold' or vn.owner_id = p_user);
  else
    insert into public.vanity_letters (name, status, owner_id, price_cents)
    values (nm, 'sold', p_user, p_amount)
    on conflict (name) do update
      set status = 'sold', owner_id = p_user
      where vanity_letters.owner_id is null or vanity_letters.owner_id = p_user;
  end if;
  insert into public.owned_names (name, user_id, kind)
  values (nm, p_user, case when nm ~ '^[0-9]+$' then 'number' else 'letter' end)
  on conflict do nothing;
  return jsonb_build_object('ok', true, 'name', nm);
end;
$$;
revoke all on function public.moose_apply_paid(uuid, text, text, int) from public, anon, authenticated;
grant execute on function public.moose_apply_paid(uuid, text, text, int) to service_role;

create or replace function public.moose_apply_resale(p_buyer uuid, p_seller uuid, p_name text, p_session text, p_amount int, p_stripe_fee int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_variable
declare
  nm text;
  num int;
  seller uuid;
  price int;
  platform int;
  fee int;
  net int;
  fallback text;
begin
  if auth.role() is distinct from 'service_role' then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  if p_buyer is null or p_session is null or p_amount is null or p_amount < 200 then
    return jsonb_build_object('ok', false, 'error', 'Bad payment');
  end if;
  if p_buyer is not distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Cannot buy your own listing');
  end if;
  nm := regexp_replace(trim(p_name), '[^A-Za-z0-9]', '', 'g');
  insert into public.vanity_receipts (session_id, user_id, name, amount_cents)
  values (p_session, p_buyer, nm, p_amount)
  on conflict (session_id) do nothing;
  if exists (select 1 from public.owned_names o where lower(o.name) = lower(nm) and o.user_id = p_buyer) then
    return jsonb_build_object('ok', true, 'name', nm, 'already', true);
  end if;
  select o.user_id, o.sale_price_cents into seller, price
  from public.owned_names o
  where lower(o.name) = lower(nm) and o.kind in ('number', 'letter')
  limit 1;
  if seller is null then
    return jsonb_build_object('ok', false, 'error', 'Name is not for resale');
  end if;
  if p_seller is not null and seller is distinct from p_seller then
    return jsonb_build_object('ok', false, 'error', 'Listing changed');
  end if;
  fee := greatest(0, coalesce(p_stripe_fee, 0));
  platform := greatest(1, round(p_amount * 5.0 / 100.0)::int);
  net := greatest(0, p_amount - fee - platform);
  update public.owned_names
    set user_id = p_buyer, listed_for_sale = false, sale_price_cents = null
    where lower(name) = lower(nm) and user_id = seller;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'Could not move name');
  end if;
  if nm ~ '^[0-9]+$' then
    num := nm::int;
    update public.vanity_numbers vn
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where vn.n = num;
  else
    update public.vanity_letters
      set owner_id = p_buyer, status = 'sold', updated_at = now()
      where lower(name) = lower(nm);
  end if;
  select o.name into fallback
  from public.owned_names o
  where o.user_id = seller
  order by case when o.kind = 'signup' then 0 else 1 end, o.created_at
  limit 1;
  update public.profiles
    set display_name = coalesce(fallback, ('u' || substr(replace(seller::text, '-', ''), 1, 8))),
        updated_at = now()
    where id = seller and lower(coalesce(display_name, '')) = lower(nm);
  insert into public.name_sales (
    name, seller_id, buyer_id, list_cents, stripe_fee_cents, platform_cents, seller_net_cents, stripe_session_id, status
  ) values (
    nm, seller, p_buyer, p_amount, fee, platform, net, p_session, 'pending_payout'
  )
  on conflict (stripe_session_id) do nothing;
  return jsonb_build_object('ok', true, 'name', nm, 'seller_net_cents', net, 'platform_cents', platform, 'stripe_fee_cents', fee);
end;
$$;
revoke all on function public.moose_apply_resale(uuid, uuid, text, text, int, int) from public, anon, authenticated;
grant execute on function public.moose_apply_resale(uuid, uuid, text, text, int, int) to service_role;
notify pgrst, 'reload schema';


-- Name claims from search (£1.99). Toggle names_claim_on or change claim_cents.
alter table public.moose_shop add column if not exists names_claim_on boolean default true;
alter table public.moose_shop add column if not exists claim_cents int default 199;
update public.moose_shop set names_claim_on = true, claim_cents = 199 where id = 1;

-- Friend requests: search a name, they confirm or burn. Burn = 24h cooldown.
-- P2P room codes stay open. Named mail/call/invite/poke need friends.
create table if not exists public.moose_friends (
  user_a uuid not null,
  user_b uuid not null,
  from_id uuid not null,
  to_id uuid not null,
  from_name text not null default '',
  to_name text not null default '',
  status text not null default 'pending' check (status in ('pending','friends','burned')),
  burned_until timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (user_a, user_b)
);
create index if not exists moose_friends_to_idx on public.moose_friends (to_id, status);
alter table public.moose_friends enable row level security;

create or replace function public.moose_uid_for_name(p_name text)
returns uuid
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  uid uuid;
  nm text := lower(trim(coalesce(p_name, '')));
begin
  if nm = '' then return null; end if;
  select o.user_id into uid from public.owned_names o where lower(o.name) = nm limit 1;
  if uid is not null then return uid; end if;
  select p.id into uid from public.profiles p where lower(p.display_name) = nm limit 1;
  return uid;
end;
$$;

create or replace function public.moose_are_friends(p_a uuid, p_b uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select p_a is not null and p_b is not null and p_a <> p_b and exists (
    select 1 from public.moose_friends f
    where f.status = 'friends'
      and f.user_a = least(p_a, p_b)
      and f.user_b = greatest(p_a, p_b)
  );
$$;

create or replace function public.moose_can_mail(p_from uuid, p_to uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select p_from is not null and p_to is not null and p_from <> p_to and (
    exists (select 1 from public.owned_names o where o.user_id = p_to and lower(o.name) = 'admin')
    or public.moose_are_friends(p_from, p_to)
  );
$$;

drop policy if exists "mail insert authed" on public.offline_messages;
drop policy if exists "mail insert friends" on public.offline_messages;
create policy "mail insert friends" on public.offline_messages
  for insert to authenticated
  with check (from_user_id = auth.uid() and public.moose_can_mail(auth.uid(), to_user_id));

create or replace function public.moose_friend_status(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  them uuid;
  r public.moose_friends%rowtype;
  wait_h numeric := 0;
begin
  if me is null then
    return jsonb_build_object('status', 'login');
  end if;
  them := public.moose_uid_for_name(p_name);
  if them is null then
    return jsonb_build_object('status', 'none');
  end if;
  if them = me then
    return jsonb_build_object('status', 'self');
  end if;
  select * into r from public.moose_friends
    where user_a = least(me, them) and user_b = greatest(me, them);
  if not found then
    return jsonb_build_object('status', 'none');
  end if;
  if r.status = 'burned' and r.burned_until is not null and r.burned_until > now() then
    wait_h := ceil(extract(epoch from (r.burned_until - now())) / 3600.0);
    return jsonb_build_object('status', 'burned', 'hours', wait_h, 'incoming', r.to_id = me);
  end if;
  if r.status = 'burned' then
    return jsonb_build_object('status', 'none');
  end if;
  return jsonb_build_object(
    'status', r.status,
    'incoming', r.to_id = me,
    'from_name', r.from_name,
    'to_name', r.to_name
  );
end;
$$;

create or replace function public.moose_friend_ask(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  them uuid;
  a uuid;
  b uuid;
  r public.moose_friends%rowtype;
  my_name text;
  their_name text := trim(coalesce(p_name, ''));
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in to add a friend');
  end if;
  them := public.moose_uid_for_name(p_name);
  if them is null then
    return jsonb_build_object('ok', false, 'error', 'Name not found');
  end if;
  if them = me then
    return jsonb_build_object('ok', false, 'error', 'That is you');
  end if;
  select coalesce(p.display_name, '') into my_name from public.profiles p where p.id = me;
  a := least(me, them);
  b := greatest(me, them);
  select * into r from public.moose_friends where user_a = a and user_b = b;
  if found then
    if r.status = 'friends' then
      return jsonb_build_object('ok', true, 'status', 'friends');
    end if;
    if r.status = 'pending' and r.from_id = me then
      return jsonb_build_object('ok', true, 'status', 'pending');
    end if;
    if r.status = 'pending' and r.to_id = me then
      update public.moose_friends set status = 'friends', updated_at = now()
        where user_a = a and user_b = b;
      return jsonb_build_object('ok', true, 'status', 'friends');
    end if;
    if r.status = 'burned' and r.burned_until is not null and r.burned_until > now() then
      return jsonb_build_object('ok', false, 'error', 'They burned the last request. Wait 24 hours.',
        'status', 'burned', 'hours', ceil(extract(epoch from (r.burned_until - now())) / 3600.0));
    end if;
    update public.moose_friends set
      from_id = me, to_id = them, from_name = my_name, to_name = their_name,
      status = 'pending', burned_until = null, updated_at = now()
      where user_a = a and user_b = b;
    return jsonb_build_object('ok', true, 'status', 'pending');
  end if;
  insert into public.moose_friends (user_a, user_b, from_id, to_id, from_name, to_name, status)
    values (a, b, me, them, my_name, their_name, 'pending');
  return jsonb_build_object('ok', true, 'status', 'pending');
end;
$$;

create or replace function public.moose_friend_accept(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  them uuid;
  n int;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in');
  end if;
  them := public.moose_uid_for_name(p_name);
  if them is null then
    return jsonb_build_object('ok', false, 'error', 'Name not found');
  end if;
  update public.moose_friends
    set status = 'friends', updated_at = now()
    where user_a = least(me, them) and user_b = greatest(me, them)
      and status = 'pending' and to_id = me;
  get diagnostics n = row_count;
  if n < 1 then
    return jsonb_build_object('ok', false, 'error', 'No request to confirm');
  end if;
  return jsonb_build_object('ok', true, 'status', 'friends');
end;
$$;

create or replace function public.moose_friend_burn(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  them uuid;
  n int;
begin
  if me is null then
    return jsonb_build_object('ok', false, 'error', 'Log in');
  end if;
  them := public.moose_uid_for_name(p_name);
  if them is null then
    return jsonb_build_object('ok', false, 'error', 'Name not found');
  end if;
  update public.moose_friends
    set status = 'burned', burned_until = now() + interval '24 hours', updated_at = now()
    where user_a = least(me, them) and user_b = greatest(me, them)
      and status = 'pending' and to_id = me;
  get diagnostics n = row_count;
  if n < 1 then
    return jsonb_build_object('ok', false, 'error', 'No request to burn');
  end if;
  return jsonb_build_object('ok', true, 'status', 'burned', 'hours', 24);
end;
$$;

create or replace function public.moose_friend_inbox()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
begin
  if me is null then
    return jsonb_build_object('pending', '[]'::jsonb, 'friends', '[]'::jsonb);
  end if;
  return jsonb_build_object(
    'pending', coalesce((
      select jsonb_agg(jsonb_build_object(
        'from_name', from_name,
        'to_name', to_name,
        'name', case when from_name <> '' then from_name else to_name end
      ))
      from public.moose_friends
      where to_id = me and status = 'pending'
    ), '[]'::jsonb),
    'friends', coalesce((
      select jsonb_agg(jsonb_build_object(
        'name', case when from_id = me then to_name else from_name end
      ))
      from public.moose_friends
      where status = 'friends' and (from_id = me or to_id = me)
    ), '[]'::jsonb)
  );
end;
$$;

revoke all on function public.moose_uid_for_name(text) from public, anon, authenticated;
grant execute on function public.moose_uid_for_name(text) to service_role;
grant execute on function public.moose_are_friends(uuid, uuid) to authenticated, service_role;
grant execute on function public.moose_can_mail(uuid, uuid) to authenticated, service_role;
grant execute on function public.moose_friend_status(text) to authenticated;
grant execute on function public.moose_friend_ask(text) to authenticated;
grant execute on function public.moose_friend_accept(text) to authenticated;
grant execute on function public.moose_friend_burn(text) to authenticated;
grant execute on function public.moose_friend_inbox() to authenticated;

-- Keep people you already Trusted so current chats do not lock.
insert into public.moose_friends (user_a, user_b, from_id, to_id, from_name, to_name, status)
select least(t.owner_id, t.peer_id), greatest(t.owner_id, t.peer_id), t.owner_id, t.peer_id,
  coalesce((select p.display_name from public.profiles p where p.id = t.owner_id), ''),
  coalesce((select p.display_name from public.profiles p where p.id = t.peer_id), ''),
  'friends'
from public.moose_trust t
where t.owner_id <> t.peer_id
on conflict (user_a, user_b) do nothing;

notify pgrst, 'reload schema';
