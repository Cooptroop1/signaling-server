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
