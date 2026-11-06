-- Anyone with the project URL and public anon key can read and modify this demo roster.
-- Do not run this for real student or otherwise private data.
alter table public.attendance_state enable row level security;
revoke all on public.attendance_state from public;

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
