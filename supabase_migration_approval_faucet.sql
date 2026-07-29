-- ============================================================
--  TbsgBounties — signup approval + user list + hourly faucet
--  Run AFTER supabase_security_patch_2.sql.
--  Safe to run once. Idempotent.
-- ============================================================

-- ============================================================
-- 1) NEW COLUMNS
-- ============================================================
alter table public.profiles
  add column if not exists approved       boolean not null default false,
  add column if not exists approved_at    timestamptz,
  add column if not exists approved_by    uuid references public.profiles(id),
  add column if not exists last_faucet_at timestamptz;

-- Existing users stay in. Only accounts created from now on need approval.
-- (Comment this out if you want EVERY existing account to re-apply.)
update public.profiles set approved = true where approved = false and created_at < now();

-- Admins are always approved.
update public.profiles set approved = true where is_admin;


-- ============================================================
-- 2) SIGNUP TRIGGER — new users start UNAPPROVED.
--    The owner username ('snowy') is auto-admin AND auto-approved
--    so you can never lock yourself out.
-- ============================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
declare
  v_username text := coalesce(new.raw_user_meta_data->>'username', 'user_' || substr(new.id::text,1,8));
  v_is_owner boolean := lower(v_username) = 'snowy';
begin
  insert into public.profiles (id, username, is_admin, approved, approved_at)
  values (
    new.id,
    v_username,
    v_is_owner,
    v_is_owner,                          -- owner is pre-approved
    case when v_is_owner then now() end
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ============================================================
-- 3) GUARD: `approved` is server-controlled, exactly like is_admin.
--    Rewritten to also cover the new column.
-- ============================================================
create or replace function public.guard_profile_columns()
returns trigger language plpgsql as $$
begin
  if current_role = 'service_role'
     or current_setting('app.trusted_write', true) = 'on' then
    return new;
  end if;
  if new.balance is distinct from old.balance then
    raise exception 'balance cannot be modified directly';
  end if;
  if new.is_admin is distinct from old.is_admin then
    raise exception 'is_admin cannot be modified directly';
  end if;
  if new.approved is distinct from old.approved then
    raise exception 'approved cannot be modified directly';
  end if;
  if new.last_faucet_at is distinct from old.last_faucet_at then
    raise exception 'last_faucet_at cannot be modified directly';
  end if;
  return new;
end;
$$;

create or replace function public.guard_profile_insert()
returns trigger language plpgsql as $$
begin
  if current_role = 'service_role'
     or current_setting('app.trusted_write', true) = 'on' then
    return new;
  end if;
  if new.is_admin then raise exception 'is_admin cannot be set on insert'; end if;
  if new.approved then raise exception 'approved cannot be set on insert'; end if;
  if new.balance is distinct from 0 then raise exception 'balance cannot be set on insert'; end if;
  return new;
end;
$$;


-- ============================================================
-- 4) HELPER: is the current user approved?
-- ============================================================
create or replace function public.is_approved()
returns boolean language sql security definer stable as $$
  select coalesce((select approved from public.profiles where id = auth.uid()), false);
$$;

grant execute on function public.is_approved() to authenticated;


-- ============================================================
-- 5) RLS — unapproved users can see/do NOTHING except read their
--    own profile (so the frontend can show "pending approval").
-- ============================================================

-- TASKS: must be approved to see or claim.
drop policy if exists "anyone logged in can read tasks" on public.tasks;
create policy "approved users can read tasks" on public.tasks
  for select using (public.is_approved() or public.is_admin());

drop policy if exists "user can claim an open task" on public.tasks;
create policy "user can claim an open task" on public.tasks
  for update
  using  (public.is_approved() and status = 'open' and claimed_by is null)
  with check (status = 'claimed' and claimed_by = auth.uid());

-- SUBMISSIONS: must be approved to submit.
drop policy if exists "user creates own submission" on public.submissions;
create policy "user creates own submission" on public.submissions
  for insert with check (
    auth.uid() = user_id
    and public.is_approved()
    and exists (
      select 1 from public.tasks t
       where t.id = task_id and t.claimed_by = auth.uid() and t.status = 'claimed'
    )
  );

-- WITHDRAWALS: must be approved to request.
drop policy if exists "user creates own withdrawal" on public.withdrawals;
create policy "user creates own withdrawal" on public.withdrawals
  for insert with check (auth.uid() = user_id and public.is_approved());


-- ============================================================
-- 6) ADMIN: list all users, approve, reject.
-- ============================================================

-- Full user list for the admin panel (bypasses per-row policy safely
-- because it re-checks is_admin itself).
create or replace function public.admin_list_users()
returns table (
  id             uuid,
  username       text,
  balance        numeric,
  is_admin       boolean,
  approved       boolean,
  created_at     timestamptz,
  last_faucet_at timestamptz
)
language plpgsql security definer stable as $$
begin
  if not public.is_admin() then raise exception 'Not an admin'; end if;
  return query
    select p.id, p.username, p.balance, p.is_admin, p.approved, p.created_at, p.last_faucet_at
      from public.profiles p
     order by p.approved asc, p.created_at desc;
end;
$$;

create or replace function public.admin_set_approval(p_user_id uuid, p_approved boolean)
returns void
language plpgsql security definer as $$
begin
  if not public.is_admin() then raise exception 'Not an admin'; end if;
  perform set_config('app.trusted_write','on', true);

  if not p_approved and (select is_admin from public.profiles where id = p_user_id) then
    raise exception 'Cannot un-approve an admin';
  end if;

  update public.profiles
     set approved    = p_approved,
         approved_at = case when p_approved then now() else null end,
         approved_by = case when p_approved then auth.uid() else null end
   where id = p_user_id;
end;
$$;

grant execute on function public.admin_list_users()            to authenticated;
grant execute on function public.admin_set_approval(uuid,bool) to authenticated;


-- ============================================================
-- 7) FAUCET — 0.0005 LTC, once per hour, enforced SERVER-SIDE.
--    A client cannot fake the timer: last_faucet_at is guarded
--    above and the check happens under a row lock.
-- ============================================================
create or replace function public.claim_faucet()
returns table (amount numeric, new_balance numeric, next_claim_at timestamptz)
language plpgsql security definer as $$
declare
  v_uid    uuid := auth.uid();
  v_amount numeric := 0.00050000;
  v_last   timestamptz;
  v_appr   boolean;
  v_new    numeric;
begin
  if v_uid is null then raise exception 'Not authenticated'; end if;

  -- lock the row so two concurrent calls can't both pass the time check
  select approved, last_faucet_at into v_appr, v_last
    from public.profiles where id = v_uid for update;

  if v_appr is null then raise exception 'No profile'; end if;
  if not v_appr then raise exception 'Your account is not approved yet'; end if;

  if v_last is not null and now() < v_last + interval '1 hour' then
    raise exception 'Faucet already claimed. Next claim at %',
      to_char(v_last + interval '1 hour', 'HH24:MI:SS UTC');
  end if;

  perform set_config('app.trusted_write','on', true);

  update public.profiles
     set balance = balance + v_amount,
         last_faucet_at = now()
   where id = v_uid
  returning balance into v_new;

  return query select v_amount, v_new, (now() + interval '1 hour')::timestamptz;
end;
$$;

grant execute on function public.claim_faucet() to authenticated;


-- ============================================================
-- 8) VERIFY — as an UNAPPROVED user, all of these must fail/return 0:
-- ============================================================
--   select * from tasks;                        -- 0 rows
--   select claim_faucet();                      -- 'not approved yet'
--   update profiles set approved = true where id = auth.uid();
--   select admin_list_users();                  -- 'Not an admin'
--
-- As an APPROVED non-admin user:
--   select claim_faucet();                      -- works once
--   select claim_faucet();                      -- 'already claimed'
--   select admin_set_approval('<uuid>', true);  -- 'Not an admin'
