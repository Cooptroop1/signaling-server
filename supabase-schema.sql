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

-- Remote wipe
alter table public.profiles add column if not exists wipe_epoch bigint;
do $$
begin
  alter publication supabase_realtime add table public.profiles;
exception when duplicate_object then
  null;
end $$;

