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

create table if not exists public.offline_messages (
  id uuid primary key default gen_random_uuid(),
  to_user_id uuid not null references public.profiles (id) on delete cascade,
  payload jsonb not null,
  created_at timestamptz default now()
);

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
