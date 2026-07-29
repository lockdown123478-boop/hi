-- ============================================================
--  TbsgBounties — owner-only payouts + admin PIN
--  Run AFTER supabase_migration_approval_faucet.sql.
--  Safe to run repeatedly.
-- ============================================================

-- ============================================================
-- 1) OWNER identity. Payout approval is restricted to this one
--    account, not merely "anyone with is_admin".
-- ============================================================
create or replace function public.is_owner()
returns boolean language sql security definer stable as $$
  select coalesce(
    (select lower(username) = 'snowy' and is_admin and approved
       from public.profiles where id = auth.uid()),
    false);
$$;

grant execute on function public.is_owner() to authenticated;


-- ============================================================
-- 2) ADMIN PIN
--    Stored as a salted hash, never in plaintext, never sent to
--    the browser. Verified server-side; the client only ever
--    learns "correct" or "incorrect".
-- ============================================================
create extension if not exists pgcrypto;

create table if not exists public.admin_security (
  id            int primary key default 1,
  pin_hash      text not null,
  failed_count  int  not null default 0,
  locked_until  timestamptz,
  constraint admin_security_singleton check (id = 1)
);

alter table public.admin_security enable row level security;
-- No policies at all: the table is unreachable from PostgREST.
-- Only SECURITY DEFINER functions below may touch it.

-- Seed / reset the PIN to 2469 (hashed with a random salt).
insert into public.admin_security (id, pin_hash)
values (1, crypt('2469', gen_salt('bf', 10)))
on conflict (id) do update set pin_hash = crypt('2469', gen_salt('bf', 10));


-- ============================================================
-- 3) PIN VERIFICATION — rate limited, owner-only.
--    5 wrong attempts locks it for 15 minutes.
-- ============================================================
create or replace function public.verify_admin_pin(p_pin text)
returns boolean
language plpgsql security definer as $$
declare
  v_row public.admin_security;
  v_ok  boolean;
begin
  if not public.is_owner() then
    raise exception 'Not the owner account';
  end if;

  select * into v_row from public.admin_security where id = 1 for update;
  if v_row is null then raise exception 'PIN not configured'; end if;

  if v_row.locked_until is not null and now() < v_row.locked_until then
    raise exception 'Too many attempts. Locked until %',
      to_char(v_row.locked_until, 'HH24:MI:SS UTC');
  end if;

  v_ok := (v_row.pin_hash = crypt(coalesce(p_pin,''), v_row.pin_hash));

  if v_ok then
    update public.admin_security
       set failed_count = 0, locked_until = null
     where id = 1;
  else
    update public.admin_security
       set failed_count = failed_count + 1,
           locked_until = case when failed_count + 1 >= 5
                               then now() + interval '15 minutes' end
     where id = 1;
  end if;

  return v_ok;
end;
$$;

grant execute on function public.verify_admin_pin(text) to authenticated;

-- Let the owner change the PIN later without touching SQL by hand.
create or replace function public.set_admin_pin(p_old text, p_new text)
returns void
language plpgsql security definer as $$
declare v_row public.admin_security;
begin
  if not public.is_owner() then raise exception 'Not the owner account'; end if;
  if p_new is null or p_new !~ '^[0-9]{4,10}$' then
    raise exception 'PIN must be 4-10 digits';
  end if;
  select * into v_row from public.admin_security where id = 1 for update;
  if v_row.pin_hash <> crypt(coalesce(p_old,''), v_row.pin_hash) then
    raise exception 'Current PIN is incorrect';
  end if;
  update public.admin_security
     set pin_hash = crypt(p_new, gen_salt('bf', 10)),
         failed_count = 0, locked_until = null
   where id = 1;
end;
$$;

grant execute on function public.set_admin_pin(text,text) to authenticated;


-- ============================================================
-- 4) PAYOUTS ARE NOW OWNER-ONLY.
--    Even a second admin account cannot move Litecoin.
-- ============================================================
create or replace function public.admin_lock_withdrawal(p_id uuid)
returns public.withdrawals
language plpgsql security definer as $$
declare v_row public.withdrawals;
begin
  if not public.is_owner() then
    raise exception 'Only the owner account may approve payouts';
  end if;

  update public.withdrawals
     set status = 'processing'
   where id = p_id and status = 'pending'
  returning * into v_row;

  if v_row is null then raise exception 'Already reviewed or not found'; end if;
  return v_row;
end;
$$;

create or replace function public.admin_refund_withdrawal(p_id uuid, p_status text)
returns void
language plpgsql security definer as $$
declare v_row public.withdrawals;
begin
  if not public.is_owner() then
    raise exception 'Only the owner account may review payouts';
  end if;
  perform set_config('app.trusted_write','on', true);
  if p_status not in ('denied','failed') then raise exception 'Bad status'; end if;

  select * into v_row from public.withdrawals where id = p_id for update;
  if v_row is null then raise exception 'Not found'; end if;
  if v_row.status not in ('pending','processing') then raise exception 'Already settled'; end if;

  update public.profiles    set balance = balance + v_row.amount where id = v_row.user_id;
  update public.withdrawals set status = p_status                where id = p_id;
end;
$$;

create or replace function public.admin_complete_withdrawal(p_id uuid, p_txid text)
returns void
language plpgsql security definer as $$
begin
  if not public.is_owner() then
    raise exception 'Only the owner account may complete payouts';
  end if;
  update public.withdrawals set status = 'sent', txid = p_txid
   where id = p_id and status = 'processing';
end;
$$;


-- ============================================================
-- 5) VERIFY
-- ============================================================
-- As snowy:
--   select is_owner();                     -- true
--   select verify_admin_pin('2469');       -- true
--   select verify_admin_pin('0000');       -- false (and increments failures)
--
-- As any other user (even one with is_admin = true):
--   select is_owner();                     -- false
--   select verify_admin_pin('2469');       -- ERROR: Not the owner account
--   select admin_lock_withdrawal('<id>');  -- ERROR: Only the owner account
--
-- As anyone, the PIN itself must be unreachable:
--   select * from admin_security;          -- 0 rows (RLS, no policies)
