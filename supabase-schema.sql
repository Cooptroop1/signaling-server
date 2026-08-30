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
create policy "profiles readable" on public.profiles
  for select using (true);

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
  if exists (select 1 from public.profiles where lower(display_name) = lower(name)) then
    raise exception 'Display name already taken';
  end if;
  insert into public.profiles (id, display_name)
  values (new.id, name)
  on conflict (id) do nothing;
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
  select * into r from public.profiles where lower(display_name) = lower(trim(p_name)) limit 1;
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
    'display_name', r.display_name,
    'public_key', r.public_key,
    'identity_public_key', r.identity_public_key,
    'last_active', case when coalesce(r.hide_last_seen, false) then null else r.last_active end,
    'status', case when online then 'online' else 'offline' end
  );
end;
$$;

grant execute on function public.lookup_moose(text) to authenticated, anon;

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
  stripe_ready boolean default false
);
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
where n in (1, 7);

update public.vanity_numbers
set gold = true,
    buy_now_cents = case n
      when 2 then 10000 when 3 then 8000 when 4 then 6000 when 5 then 8000
      when 6 then 5000 when 8 then 5000 when 9 then 8000 else 10000 end
where n in (2,3,4,5,6,8,9);

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
    price := case char_length(nm) when 1 then 5000 when 2 then 3500 else 2000 end;
  else
    price := case char_length(nm) when 1 then 5000 when 2 then 2500 else 1000 end;
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
  forever := coalesce(v.held_forever, false) or p_n in (1, 7);
  return jsonb_build_object(
    'ok', true,
    'kind', 'number',
    'n', v.n,
    'status', case when forever then 'held' else v.status end,
    'price_cents', coalesce(v.buy_now_cents, v.price_cents),
    'gold', coalesce(v.gold, false),
    'held_forever', forever,
    'current_bid_cents', v.current_bid_cents,
    'shop_on', coalesce(shop.numbers_on, false),
    'available', (not forever and v.status = 'listed' and coalesce(shop.numbers_on, false))
  );
end;
$$;

-- Remote wipe
alter table public.profiles add column if not exists wipe_epoch bigint;
do $$
begin
  alter publication supabase_realtime add table public.profiles;
exception when duplicate_object then
  null;
end $$;

