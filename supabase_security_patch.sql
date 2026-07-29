-- ============================================================
--  TbsgBounties SECURITY PATCH
--  Fixes: users could set their own balance / is_admin via the
--  PostgREST API because the "update own profile" policy had no
--  WITH CHECK and no column restriction.
--
--  Run this in Supabase → SQL Editor → Run. Safe to run once.
-- ============================================================

-- 1) Drop the unsafe blanket update policy on profiles.
drop policy if exists "update own profile (not balance/admin)" on public.profiles;
drop policy if exists "update own profile" on public.profiles;

-- 2) Lock down balance & is_admin so NO client write can ever change them.
--    We add a trigger that rejects any client (non-superuser) attempt to
--    change balance or is_admin. Server-side SECURITY DEFINER functions
--    (which run as the table owner) bypass this because they set a flag.
create or replace function public.guard_profile_columns()
returns trigger language plpgsql as $$
begin
  -- Allow trusted server-side callers:
  --  (a) the service_role key used by edge functions (bypasses RLS; runs as service_role)
  --  (b) SECURITY DEFINER RPCs that set the app.trusted_write flag
  if current_role = 'service_role'
     or current_setting('app.trusted_write', true) = 'on' then
    return new;
  end if;
  -- Otherwise, block changes to protected columns.
  if new.balance is distinct from old.balance then
    raise exception 'balance cannot be modified directly';
  end if;
  if new.is_admin is distinct from old.is_admin then
    raise exception 'is_admin cannot be modified directly';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_profile_cols on public.profiles;
create trigger guard_profile_cols
  before update on public.profiles
  for each row execute function public.guard_profile_columns();

-- 3) Re-add a SAFE update policy: a user may update only their own row,
--    and the trigger above ensures they can't touch balance/is_admin.
drop policy if exists "update own profile safe" on public.profiles;
create policy "update own profile safe" on public.profiles
  for update using (auth.uid() = id) with check (auth.uid() = id);

-- 4) Mark the trusted definer functions so their legitimate balance
--    writes still work. They set the flag at the top of their body.
--    We patch the existing balance-moving functions to set it.
create or replace function public.request_withdrawal(p_amount numeric, p_address text)
returns public.withdrawals
language plpgsql security definer as $$
declare
  v_uid uuid := auth.uid();
  v_balance numeric;
  v_row public.withdrawals;
begin
  perform set_config('app.trusted_write','on', true);   -- trust this txn's writes
  if v_uid is null then raise exception 'Not authenticated'; end if;
  if p_amount is null or p_amount <= 0 then raise exception 'Invalid amount'; end if;
  if p_address is null or length(trim(p_address)) < 10 then raise exception 'Invalid address'; end if;

  select balance into v_balance from public.profiles where id = v_uid for update;
  if v_balance < p_amount then raise exception 'Insufficient balance'; end if;

  update public.profiles set balance = balance - p_amount where id = v_uid;

  insert into public.withdrawals (user_id, amount, ltc_address, status)
  values (v_uid, p_amount, trim(p_address), 'pending')
  returning * into v_row;
  return v_row;
end;
$$;

create or replace function public.cancel_withdrawal(p_id uuid)
returns void
language plpgsql security definer as $$
declare
  v_uid uuid := auth.uid();
  v_row public.withdrawals;
begin
  perform set_config('app.trusted_write','on', true);
  if v_uid is null then raise exception 'Not authenticated'; end if;

  select * into v_row from public.withdrawals where id = p_id for update;
  if v_row is null then raise exception 'Not found'; end if;
  if v_row.user_id <> v_uid then raise exception 'Not your withdrawal'; end if;
  if v_row.status <> 'pending' then raise exception 'Cannot cancel — already %', v_row.status; end if;
  if now() < v_row.created_at + interval '5 minutes' then
    raise exception 'You can only cancel 5 minutes after requesting';
  end if;

  update public.profiles set balance = balance + v_row.amount where id = v_uid;
  update public.withdrawals set status = 'cancelled' where id = p_id;
end;
$$;

-- 5) Add the missing non-negative balance guard.
alter table public.profiles drop constraint if exists profiles_balance_nonneg;
alter table public.profiles add constraint profiles_balance_nonneg check (balance >= 0);

-- NOTE: the edge functions (review-submission, review-withdrawal) use the
-- service_role key, which bypasses RLS AND the trigger (service_role is not
-- subject to the trusted_write check because it runs as a privileged role).
-- Verify after running: as a normal logged-in user, this must FAIL:
--   update profiles set balance = 999999 where id = auth.uid();
