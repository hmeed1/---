create or replace function public.normalize_academic_number(p_value text)
returns text
language sql
immutable
set search_path = ''
as $$
  select nullif(
    regexp_replace(
      translate(
        coalesce(p_value, ''),
        '٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹',
        '01234567890123456789'
      ),
      '[^0-9]',
      '',
      'g'
    ),
    ''
  );
$$;

create table if not exists public.attendance_user_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'pending' check (role in ('pending', 'student', 'staff')),
  academic_number text,
  approved boolean not null default false,
  created_at timestamptz not null default clock_timestamp(),
  check (role <> 'student' or academic_number is not null)
);

create unique index if not exists attendance_user_profiles_student_academic_unique
  on public.attendance_user_profiles (academic_number)
  where role = 'student';

alter table public.attendance_user_profiles enable row level security;
revoke all on public.attendance_user_profiles from public, anon, authenticated;
grant select on public.attendance_user_profiles to authenticated;

do $$
declare
  existing_policy record;
begin
  for existing_policy in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename = 'attendance_user_profiles'
  loop
    execute format('drop policy %I on public.attendance_user_profiles', existing_policy.policyname);
  end loop;
end;
$$;

create policy "Users can read their own attendance profile"
  on public.attendance_user_profiles
  for select to authenticated
  using (user_id = auth.uid());

create or replace function public.create_attendance_user_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.attendance_user_profiles (user_id, academic_number)
  values (
    new.id,
    public.normalize_academic_number(new.raw_user_meta_data ->> 'academic_number')
  )
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists create_attendance_user_profile on auth.users;
create trigger create_attendance_user_profile
  after insert on auth.users
  for each row execute function public.create_attendance_user_profile();

alter table public.attendance_state enable row level security;
revoke all on public.attendance_state from public, anon, authenticated;
grant select on public.attendance_state to authenticated;

do $$
declare
  existing_policy record;
begin
  for existing_policy in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename = 'attendance_state'
  loop
    execute format('drop policy %I on public.attendance_state', existing_policy.policyname);
  end loop;
end;
$$;

create policy "Approved staff can read attendance"
  on public.attendance_state
  for select to authenticated
  using (
    exists (
      select 1
      from public.attendance_user_profiles profile
      where profile.user_id = auth.uid()
        and profile.role = 'staff'
        and profile.approved
    )
  );

alter table public.attendance_roster_backup enable row level security;
revoke all on public.attendance_roster_backup from public, anon, authenticated;
grant select on public.attendance_roster_backup to authenticated;

do $$
declare
  existing_policy record;
begin
  for existing_policy in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename = 'attendance_roster_backup'
  loop
    execute format('drop policy %I on public.attendance_roster_backup', existing_policy.policyname);
  end loop;
end;
$$;

create policy "Approved staff can read roster backup"
  on public.attendance_roster_backup
  for select to authenticated
  using (
    exists (
      select 1
      from public.attendance_user_profiles profile
      where profile.user_id = auth.uid()
        and profile.role = 'staff'
        and profile.approved
    )
  );

create or replace function public.get_attendance_session()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.attendance_user_profiles%rowtype;
  current_state public.attendance_state%rowtype;
  visible_students jsonb;
begin
  select *
    into current_profile
    from public.attendance_user_profiles
    where user_id = auth.uid();

  if not found or not current_profile.approved then
    return jsonb_build_object('role', 'pending', 'approved', false);
  end if;

  select *
    into current_state
    from public.attendance_state
    where id = 'school';

  if current_profile.role = 'staff' then
    return jsonb_build_object(
      'role', 'staff',
      'approved', true,
      'students', coalesce(current_state.students, '[]'::jsonb),
      'updated_at', current_state.updated_at
    );
  end if;

  if current_profile.role = 'student' then
    select coalesce(jsonb_agg(student.value order by student.ordinality), '[]'::jsonb)
      into visible_students
      from jsonb_array_elements(coalesce(current_state.students, '[]'::jsonb))
        with ordinality as student(value, ordinality)
      where public.normalize_academic_number(student.value ->> 'academic')
        = current_profile.academic_number;

    return jsonb_build_object(
      'role', 'student',
      'approved', true,
      'students', visible_students,
      'updated_at', current_state.updated_at
    );
  end if;

  return jsonb_build_object('role', 'pending', 'approved', false);
end;
$$;

create or replace function public.save_attendance_state(
  p_students jsonb,
  p_expected_updated_at timestamptz
)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  saved_at timestamptz;
begin
  if not exists (
    select 1
    from public.attendance_user_profiles profile
    where profile.user_id = auth.uid()
      and profile.role = 'staff'
      and profile.approved
  ) then
    raise exception 'Approved staff access is required' using errcode = '42501';
  end if;

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

revoke all on function public.create_attendance_user_profile() from public, anon, authenticated;
revoke all on function public.get_attendance_session() from public, anon;
revoke all on function public.save_attendance_state(jsonb, timestamptz) from public, anon;
grant execute on function public.get_attendance_session() to authenticated;
grant execute on function public.save_attendance_state(jsonb, timestamptz) to authenticated;
