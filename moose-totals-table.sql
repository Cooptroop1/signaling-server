-- One-row table you can watch in Supabase → Table Editor → moose_totals
-- Safe to run twice.

create table if not exists public.moose_epoch (
  id int primary key default 1,
  reset_at timestamptz not null default '1970-01-01+00'::timestamptz
);
insert into public.moose_epoch (id, reset_at)
  values (1, '1970-01-01+00'::timestamptz)
  on conflict (id) do nothing;

create table if not exists public.moose_totals (
  id int primary key default 1,
  stripe_bought bigint not null default 0,
  everyone_holding bigint not null default 0,
  difference bigint not null default 0,
  updated_at timestamptz default now()
);
insert into public.moose_totals (id) values (1) on conflict (id) do nothing;
alter table public.moose_totals enable row level security;
revoke all on table public.moose_totals from public, anon, authenticated;

create or replace function public.moose_refresh_totals()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  minted bigint;
  held bigint;
  since timestamptz;
begin
  select e.reset_at into since from public.moose_epoch e where e.id = 1;
  select coalesce(sum(l.delta), 0) into minted
    from public.moose_coin_ledger l
    where l.reason = 'stripe_pack'
      and (since is null or l.created_at >= since);
  select coalesce(sum(w.coins), 0) into held from public.moose_wallets w;
  insert into public.moose_totals (id, stripe_bought, everyone_holding, difference, updated_at)
    values (1, minted, held, minted - held, now())
    on conflict (id) do update set
      stripe_bought = excluded.stripe_bought,
      everyone_holding = excluded.everyone_holding,
      difference = excluded.difference,
      updated_at = now();
end;
$$;
revoke all on function public.moose_refresh_totals() from public, anon, authenticated;

create or replace function public.moose_totals_touch()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform public.moose_refresh_totals();
  return null;
end;
$$;

drop trigger if exists moose_totals_wallets on public.moose_wallets;
create trigger moose_totals_wallets
  after insert or update or delete on public.moose_wallets
  for each statement execute function public.moose_totals_touch();

drop trigger if exists moose_totals_ledger on public.moose_coin_ledger;
create trigger moose_totals_ledger
  after insert or update or delete on public.moose_coin_ledger
  for each statement execute function public.moose_totals_touch();

select public.moose_refresh_totals();
