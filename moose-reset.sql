-- RESET ALL MOOSE. Run only when you want a fresh start.
-- Names stay owned. Stripe payments stay paid (nobody can re-claim old packs).
-- After this, Bought from Stripe and Everyone holding both show 0 until the next real buy.

update public.moose_wallets set coins = 0, updated_at = now();
update public.moose_house set coins = 0, updated_at = now();
insert into public.moose_epoch (id, reset_at) values (1, now())
  on conflict (id) do update set reset_at = excluded.reset_at;
