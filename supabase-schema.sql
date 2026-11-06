create table if not exists public.attendance_state (
  id text primary key check (id = 'school'),
  students jsonb not null default '[]'::jsonb check (jsonb_typeof(students) = 'array'),
  updated_at timestamptz not null default clock_timestamp()
);

alter table public.attendance_state enable row level security;
revoke all on public.attendance_state from public;

create table if not exists public.attendance_allowed_users (
  user_id uuid primary key references auth.users(id) on delete cascade
);

alter table public.attendance_allowed_users enable row level security;
revoke all on public.attendance_allowed_users from anon, authenticated;

create or replace function public.is_attendance_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.attendance_allowed_users where user_id = auth.uid()
  );
$$;

revoke all on function public.is_attendance_user() from public;
grant execute on function public.is_attendance_user() to authenticated;

drop policy if exists "Authenticated users can read attendance" on public.attendance_state;
drop policy if exists "Authenticated users can create attendance" on public.attendance_state;
drop policy if exists "Authenticated users can update attendance" on public.attendance_state;
drop policy if exists "Public can read attendance" on public.attendance_state;
drop policy if exists "Public can create attendance" on public.attendance_state;
drop policy if exists "Public can update attendance" on public.attendance_state;

create policy "Public can read attendance"
  on public.attendance_state for select to anon, authenticated using (true);
create policy "Public can create attendance"
  on public.attendance_state for insert to anon, authenticated with check (true);
create policy "Public can update attendance"
  on public.attendance_state for update to anon, authenticated using (true) with check (true);

grant select, insert, update on public.attendance_state to anon, authenticated;

create table if not exists public.attendance_roster_backup (
  id text primary key check (id = 'school'),
  students jsonb not null check (jsonb_typeof(students) = 'array')
);

alter table public.attendance_roster_backup enable row level security;
revoke all on public.attendance_roster_backup from public;

drop policy if exists "Allowed users can read roster backup" on public.attendance_roster_backup;
drop policy if exists "Public can read roster backup" on public.attendance_roster_backup;
create policy "Public can read roster backup"
  on public.attendance_roster_backup for select to anon, authenticated using (true);

grant select on public.attendance_roster_backup to anon, authenticated;

create or replace function public.save_attendance_state(
  p_students jsonb,
  p_expected_updated_at timestamptz
)
returns timestamptz
language plpgsql
security invoker
set search_path = ''
as $$
declare
  saved_at timestamptz;
begin
  if jsonb_typeof(p_students) <> 'array' then
    raise exception 'Students payload must be a JSON array' using errcode = '22023';
  end if;

  if p_expected_updated_at is null then
    insert into public.attendance_state (id, students, updated_at)
    values ('school', p_students, clock_timestamp())
    on conflict (id) do nothing
    returning updated_at into saved_at;
  else
    update public.attendance_state
      set students = p_students, updated_at = clock_timestamp()
      where id = 'school' and updated_at = p_expected_updated_at
      returning updated_at into saved_at;
  end if;

  if saved_at is null then
    raise exception 'attendance_state_conflict' using errcode = '40001';
  end if;
  return saved_at;
end;
$$;

revoke all on function public.save_attendance_state(jsonb, timestamptz) from public;
grant execute on function public.save_attendance_state(jsonb, timestamptz) to anon, authenticated;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'attendance_state'
  ) then
    alter publication supabase_realtime add table public.attendance_state;
  end if;
end;
$$;
