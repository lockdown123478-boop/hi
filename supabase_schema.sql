-- ============================================================
--  TbsgBounties — Database schema
--  Paste this whole file into Supabase → SQL Editor → Run
-- ============================================================

-- ---------- PROFILES ----------
-- One row per user. Linked to Supabase auth.users.
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  username     text unique not null,
  balance      numeric(20,8) not null default 0,   -- LTC balance held on-site
  is_admin     boolean not null default false,
  created_at   timestamptz not null default now()
);

-- ---------- TASKS (bounties) ----------
create table if not exists public.tasks (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  description  text not null,
  price        numeric(20,8) not null,             -- payout in LTC
  status       text not null default 'open',       -- open | claimed | completed
  claimed_by   uuid references public.profiles(id),
  created_at   timestamptz not null default now()
);

-- ---------- SUBMISSIONS ----------
-- A user submits proof (image) for a task they claimed.
create table if not exists public.submissions (
  id           uuid primary key default gen_random_uuid(),
  task_id      uuid not null references public.tasks(id) on delete cascade,
  user_id      uuid not null references public.profiles(id) on delete cascade,
  image_url    text,                               -- link to uploaded proof
  status       text not null default 'pending',    -- pending | approved | denied
  created_at   timestamptz not null default now()
);

-- ---------- WITHDRAWALS ----------
create table if not exists public.withdrawals (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references public.profiles(id) on delete cascade,
  amount       numeric(20,8) not null,             -- LTC amount requested
  ltc_address  text not null,
  status       text not null default 'pending',    -- pending | approved | denied | sent | failed
  txid         text,                               -- filled once sent on-chain
  created_at   timestamptz not null default now()
);

-- ============================================================
--  ROW LEVEL SECURITY
--  Users can only see/change their own stuff; admins see all.
-- ============================================================
alter table public.profiles    enable row level security;
alter table public.tasks       enable row level security;
alter table public.submissions enable row level security;
alter table public.withdrawals enable row level security;

-- helper: is the current user an admin?
create or replace function public.is_admin()
returns boolean language sql security definer stable as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

-- ---- PROFILES policies ----
create policy "read own profile" on public.profiles
  for select using (auth.uid() = id or public.is_admin());
create policy "update own profile (not balance/admin)" on public.profiles
  for update using (auth.uid() = id);

-- ---- TASKS policies ----
create policy "anyone logged in can read tasks" on public.tasks
  for select using (auth.role() = 'authenticated');
create policy "admin can insert tasks" on public.tasks
  for insert with check (public.is_admin());
create policy "admin can update tasks" on public.tasks
  for update using (public.is_admin());
create policy "user can claim an open task" on public.tasks
  for update using (auth.role() = 'authenticated');

-- ---- SUBMISSIONS policies ----
create policy "read own or admin" on public.submissions
  for select using (auth.uid() = user_id or public.is_admin());
create policy "user creates own submission" on public.submissions
  for insert with check (auth.uid() = user_id);
create policy "admin updates submission" on public.submissions
  for update using (public.is_admin());

-- ---- WITHDRAWALS policies ----
create policy "read own or admin (wd)" on public.withdrawals
  for select using (auth.uid() = user_id or public.is_admin());
create policy "user creates own withdrawal" on public.withdrawals
  for insert with check (auth.uid() = user_id);
create policy "admin updates withdrawal" on public.withdrawals
  for update using (public.is_admin());

-- ============================================================
--  AUTO-CREATE PROFILE ON SIGNUP
--  Username taken from signup metadata. The username 'snowy'
--  (case-insensitive) automatically becomes admin.
-- ============================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer as $$
begin
  insert into public.profiles (id, username, is_admin)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', 'user_' || substr(new.id::text,1,8)),
    lower(coalesce(new.raw_user_meta_data->>'username','')) = 'snowy'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================
--  STORAGE BUCKET for proof images
-- ============================================================
insert into storage.buckets (id, name, public)
values ('proofs', 'proofs', true)
on conflict (id) do nothing;

create policy "anyone can view proofs" on storage.objects
  for select using (bucket_id = 'proofs');
create policy "authed can upload proofs" on storage.objects
  for insert with check (bucket_id = 'proofs' and auth.role() = 'authenticated');
