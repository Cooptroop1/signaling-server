-- Lets the seller's moose count update live when a used name sells.
-- Safe to run twice.

do $$
begin
  alter publication supabase_realtime add table public.moose_wallets;
exception
  when duplicate_object then null;
end $$;
