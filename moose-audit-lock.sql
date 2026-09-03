-- Lock minting to Stripe only. Audit table. Safe to run twice.
-- Nobody except Stripe (service role) can create moose.
-- You can run:  select * from public.moose_coin_audit();

create table if not exists public.moose_epoch (
  id int primary key default 1,
  reset_at timestamptz not null default '1970-01-01+00'::timestamptz
);
insert into public.moose_epoch (id, reset_at)
  values (1, '1970-01-01+00'::timestamptz)
  on conflict (id) do nothing;
alter table public.moose_epoch enable row level security;

revoke all on table public.moose_wallets from public, anon, authenticated;
grant select on table public.moose_wallets to authenticated;
revoke all on table public.moose_house from public, anon, authenticated;
revoke all on table public.moose_coin_ledger from public, anon, authenticated;
revoke all on table public.moose_epoch from public, anon, authenticated;

revoke all on function public.moose_credit_coins(uuid, int, text, int) from public, anon, authenticated;
grant execute on function public.moose_credit_coins(uuid, int, text, int) to service_role;
revoke all on function public.moose_pay_admin(bigint, text, text) from public, anon, authenticated;
revoke all on function public.moose_admin_uid() from public, anon, authenticated;
revoke all on function public.moose_admin_coins() from public, anon, authenticated;
grant execute on function public.moose_admin_coins() to service_role;

create or replace function public.moose_coin_audit()
returns table (item text, moose bigint)
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
  return query values
    ('Bought from Stripe', minted),
    ('Everyone holding', held),
    ('Difference (should be 0)', minted - held);
end;
$$;
revoke all on function public.moose_coin_audit() from public, anon, authenticated;
grant execute on function public.moose_coin_audit() to service_role;
