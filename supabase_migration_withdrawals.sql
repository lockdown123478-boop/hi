-- ============================================================
--  Migration: withdrawal reservation + 5-minute cancel lock
--  Run this in Supabase SQL Editor AFTER the main schema.
-- ============================================================

-- 'cancelled' becomes a valid status. (No enum change needed — status is text.)

-- Atomic "request withdrawal": deduct balance and create the row in one
-- transaction, so a user can't double-spend by racing two requests.
create or replace function public.request_withdrawal(p_amount numeric, p_address text)
returns public.withdrawals
language plpgsql security definer as $$
declare
  v_uid uuid := auth.uid();
  v_balance numeric;
  v_row public.withdrawals;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if p_amount is null or p_amount <= 0 then raise exception 'Invalid amount'; end if;
  if p_address is null or length(trim(p_address)) < 10 then raise exception 'Invalid address'; end if;

  -- lock the profile row so concurrent requests can't both pass the check
  select balance into v_balance from public.profiles where id = v_uid for update;
  if v_balance < p_amount then raise exception 'Insufficient balance'; end if;

  -- reserve the funds immediately
  update public.profiles set balance = balance - p_amount where id = v_uid;

  insert into public.withdrawals (user_id, amount, ltc_address, status)
  values (v_uid, p_amount, trim(p_address), 'pending')
  returning * into v_row;

  return v_row;
end;
$$;

-- Cancel a withdrawal (only your own, only if pending, only after 5 min).
-- Refunds the reserved balance.
create or replace function public.cancel_withdrawal(p_id uuid)
returns void
language plpgsql security definer as $$
declare
  v_uid uuid := auth.uid();
  v_row public.withdrawals;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;

  select * into v_row from public.withdrawals where id = p_id for update;
  if v_row is null then raise exception 'Not found'; end if;
  if v_row.user_id <> v_uid then raise exception 'Not your withdrawal'; end if;
  if v_row.status <> 'pending' then raise exception 'Cannot cancel — already %', v_row.status; end if;
  if now() < v_row.created_at + interval '5 minutes' then
    raise exception 'You can only cancel 5 minutes after requesting';
  end if;

  -- refund
  update public.profiles set balance = balance + v_row.amount where id = v_uid;
  update public.withdrawals set status = 'cancelled' where id = p_id;
end;
$$;

grant execute on function public.request_withdrawal(numeric, text) to authenticated;
grant execute on function public.cancel_withdrawal(uuid) to authenticated;

-- Make sure realtime is on for the tables we live-update.
alter publication supabase_realtime add table public.profiles;
alter publication supabase_realtime add table public.tasks;
alter publication supabase_realtime add table public.withdrawals;
alter publication supabase_realtime add table public.submissions;
