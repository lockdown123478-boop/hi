-- ============================================================
--  TbsgBounties SECURITY PATCH 2
--  Fixes found in full audit. Run AFTER supabase_security_patch.sql.
--  Safe to run once. Idempotent.
-- ============================================================

-- ============================================================
-- FIX 1: is_admin cannot be set on INSERT (trigger was UPDATE-only)
-- ============================================================
create or replace function public.guard_profile_insert()
returns trigger language plpgsql as $$
begin
  if current_role = 'service_role' then
    return new;
  end if;
  -- Only the signup trigger (security definer, runs as owner) may grant admin.
  if new.is_admin then
    raise exception 'is_admin cannot be set on insert';
  end if;
  if new.balance is distinct from 0 then
    raise exception 'balance cannot be set on insert';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_profile_ins on public.profiles;
create trigger guard_profile_ins
  before insert on public.profiles
  for each row execute function public.guard_profile_insert();

-- No client INSERT policy on profiles at all: only the signup trigger creates rows.
drop policy if exists "insert own profile" on public.profiles;

-- Nobody may delete profiles from the client.
drop policy if exists "delete own profile" on public.profiles;


-- ============================================================
-- FIX 2: task claiming — users may ONLY claim an open task for
-- themselves. Previously any authed user could update any task.
-- ============================================================
drop policy if exists "user can claim an open task" on public.tasks;

create policy "user can claim an open task" on public.tasks
  for update
  using  (auth.role() = 'authenticated' and status = 'open' and claimed_by is null)
  with check (
    status     = 'claimed'          -- may only move open -> claimed
    and claimed_by = auth.uid()     -- and only to themselves
  );

-- Harden further: block price/title/description tampering by non-admins.
create or replace function public.guard_task_update()
returns trigger language plpgsql as $$
begin
  if current_role = 'service_role'
     or coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    return new;
  end if;
  if new.title       is distinct from old.title
     or new.description is distinct from old.description
     or new.price     is distinct from old.price then
    raise exception 'only an admin may edit task details';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_task_upd on public.tasks;
create trigger guard_task_upd
  before update on public.tasks
  for each row execute function public.guard_task_update();


-- ============================================================
-- FIX 3: a submission may only be created for a task the user
-- actually claimed, and only once.
-- ============================================================
drop policy if exists "user creates own submission" on public.submissions;

create policy "user creates own submission" on public.submissions
  for insert with check (
    auth.uid() = user_id
    and exists (
      select 1 from public.tasks t
       where t.id = task_id
         and t.claimed_by = auth.uid()
         and t.status = 'claimed'
    )
  );

-- One submission per task per user.
create unique index if not exists submissions_one_per_task_user
  on public.submissions (task_id, user_id);


-- ============================================================
-- FIX 4: atomic, race-free balance moves. Edge functions should
-- call these RPCs instead of doing select-then-update.
-- ============================================================

-- Approve a submission: verifies ownership, credits atomically,
-- and flips task + submission state in ONE transaction.
create or replace function public.admin_approve_submission(p_submission_id uuid)
returns numeric
language plpgsql security definer as $$
declare
  v_sub    public.submissions;
  v_task   public.tasks;
  v_price  numeric;
begin
  perform set_config('app.trusted_write','on', true);

  if not coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    raise exception 'Not an admin';
  end if;

  -- lock the submission
  select * into v_sub from public.submissions where id = p_submission_id for update;
  if v_sub is null then raise exception 'Submission not found'; end if;
  if v_sub.status <> 'pending' then raise exception 'Already reviewed'; end if;

  -- lock the task and verify the submitter really claimed it
  select * into v_task from public.tasks where id = v_sub.task_id for update;
  if v_task is null then raise exception 'Task not found'; end if;
  if v_task.claimed_by is distinct from v_sub.user_id then
    raise exception 'Submitter did not claim this task';
  end if;
  if v_task.status = 'completed' then raise exception 'Task already paid out'; end if;

  v_price := v_task.price;

  -- atomic credit (no read-modify-write)
  update public.profiles set balance = balance + v_price where id = v_sub.user_id;
  update public.submissions set status = 'approved'  where id = p_submission_id;
  update public.tasks       set status = 'completed' where id = v_sub.task_id;

  return v_price;
end;
$$;

create or replace function public.admin_deny_submission(p_submission_id uuid)
returns void
language plpgsql security definer as $$
declare v_sub public.submissions;
begin
  if not coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    raise exception 'Not an admin';
  end if;
  select * into v_sub from public.submissions where id = p_submission_id for update;
  if v_sub is null then raise exception 'Submission not found'; end if;
  if v_sub.status <> 'pending' then raise exception 'Already reviewed'; end if;
  update public.submissions set status = 'denied' where id = p_submission_id;
end;
$$;

-- Atomically claim a withdrawal for sending. Returns the row ONLY if this
-- call is the one that flipped it out of 'pending' — prevents double-send
-- when Approve is clicked twice.
create or replace function public.admin_lock_withdrawal(p_id uuid)
returns public.withdrawals
language plpgsql security definer as $$
declare v_row public.withdrawals;
begin
  if not coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    raise exception 'Not an admin';
  end if;

  update public.withdrawals
     set status = 'processing'
   where id = p_id and status = 'pending'
  returning * into v_row;

  if v_row is null then raise exception 'Already reviewed or not found'; end if;
  return v_row;
end;
$$;

-- Refund a reserved withdrawal atomically (used on deny / send-failure).
create or replace function public.admin_refund_withdrawal(p_id uuid, p_status text)
returns void
language plpgsql security definer as $$
declare v_row public.withdrawals;
begin
  perform set_config('app.trusted_write','on', true);
  if not coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    raise exception 'Not an admin';
  end if;
  if p_status not in ('denied','failed') then raise exception 'Bad status'; end if;

  select * into v_row from public.withdrawals where id = p_id for update;
  if v_row is null then raise exception 'Not found'; end if;
  if v_row.status not in ('pending','processing') then raise exception 'Already settled'; end if;

  update public.profiles   set balance = balance + v_row.amount where id = v_row.user_id;
  update public.withdrawals set status = p_status                where id = p_id;
end;
$$;

create or replace function public.admin_complete_withdrawal(p_id uuid, p_txid text)
returns void
language plpgsql security definer as $$
begin
  if not coalesce((select is_admin from public.profiles where id = auth.uid()), false) then
    raise exception 'Not an admin';
  end if;
  update public.withdrawals set status = 'sent', txid = p_txid
   where id = p_id and status = 'processing';
end;
$$;

grant execute on function public.admin_approve_submission(uuid)   to authenticated;
grant execute on function public.admin_deny_submission(uuid)      to authenticated;
grant execute on function public.admin_lock_withdrawal(uuid)      to authenticated;
grant execute on function public.admin_refund_withdrawal(uuid,text) to authenticated;
grant execute on function public.admin_complete_withdrawal(uuid,text) to authenticated;


-- ============================================================
-- FIX 5: set the trusted_write flag AFTER validation, not before,
-- so a failed validation can't leave it enabled in the txn.
-- ============================================================
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
  if p_address is null or length(trim(p_address)) < 26 then raise exception 'Invalid address'; end if;

  select balance into v_balance from public.profiles where id = v_uid for update;
  if v_balance is null then raise exception 'No profile'; end if;
  if v_balance < p_amount then raise exception 'Insufficient balance'; end if;

  perform set_config('app.trusted_write','on', true);   -- only after all checks pass

  update public.profiles set balance = balance - p_amount where id = v_uid;

  insert into public.withdrawals (user_id, amount, ltc_address, status)
  values (v_uid, p_amount, trim(p_address), 'pending')
  returning * into v_row;
  return v_row;
end;
$$;


-- ============================================================
-- FIX 6 (optional but recommended): restrict payout approval to
-- the OWNER account specifically, not merely "any admin".
-- Uncomment to enforce "only snowy can approve withdrawals".
-- ============================================================
-- create or replace function public.is_owner()
-- returns boolean language sql security definer stable as $$
--   select coalesce((select lower(username) = 'snowy'
--                      from public.profiles where id = auth.uid()), false);
-- $$;
-- -- then swap the is_admin checks in admin_lock_withdrawal /
-- -- admin_refund_withdrawal / admin_complete_withdrawal for is_owner().


-- ============================================================
-- VERIFY: as a normal logged-in (non-admin) user, ALL of these must FAIL.
-- ============================================================
--   update profiles set balance = 999999 where id = auth.uid();
--   update profiles set is_admin = true   where id = auth.uid();
--   insert into profiles (id, username, is_admin) values (auth.uid(),'x',true);
--   update tasks set status = 'completed' where id = '<any task>';
--   update tasks set claimed_by = auth.uid() where id = '<someone elses claimed task>';
--   update tasks set price = 100 where id = '<any task>';
--   insert into submissions (task_id,user_id) values ('<unclaimed task>', auth.uid());
--   select * from profiles where id <> auth.uid();   -- must return 0 rows
