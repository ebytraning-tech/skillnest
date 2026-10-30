-- SkillNest production schema. Applied to the connected Supabase project.
-- Uses a non-exposed private schema for SECURITY DEFINER helpers.
create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create table if not exists public.profiles(id uuid primary key references auth.users(id) on delete cascade,email text unique,full_name text,role text not null default 'learner' check(role in ('learner','admin')),created_at timestamptz not null default now());
create table if not exists public.courses(id uuid primary key default gen_random_uuid(),title text not null,slug text not null unique,category text not null,course_type text not null default 'Certificate' check(course_type in ('Certificate','Diploma')),price numeric(10,2) not null default 0 check(price>=0),level text not null default 'Beginner',description text not null default '',image_url text not null default '',published boolean not null default false,created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create table if not exists public.enrollments(id uuid primary key default gen_random_uuid(),student_id uuid not null references public.profiles(id) on delete cascade,course_id uuid not null references public.courses(id) on delete cascade,status text not null default 'active' check(status in ('active','completed','cancelled')),progress integer not null default 0 check(progress between 0 and 100),created_at timestamptz not null default now(),unique(student_id,course_id));
create table if not exists public.orders(id uuid primary key default gen_random_uuid(),student_id uuid references public.profiles(id) on delete set null,customer_email text not null,course_id uuid references public.courses(id) on delete set null,course_title text not null,amount numeric(10,2) not null check(amount>=0),currency text not null default 'USD',status text not null default 'pending' check(status in ('pending','paid','refunded','cancelled')),payment_provider text,provider_reference text,created_at timestamptz not null default now());
create table if not exists public.site_content(id uuid primary key default gen_random_uuid(),key text not null unique,title text not null default '',body text not null default '',updated_at timestamptz not null default now());
create table if not exists public.activity_logs(id uuid primary key default gen_random_uuid(),actor_id uuid references public.profiles(id) on delete set null,action text not null,entity_type text,entity_id uuid,details jsonb not null default '{}'::jsonb,created_at timestamptz not null default now());

create or replace function private.handle_new_user() returns trigger language plpgsql security definer set search_path='' as $$
begin
 insert into public.profiles(id,email,full_name) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name',''))
 on conflict(id) do update set email=excluded.email;
 return new;
end; $$;
revoke all on function private.handle_new_user() from public,anon,authenticated;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure private.handle_new_user();

create or replace function private.is_admin() returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.profiles where id=(select auth.uid()) and role='admin');
$$;
revoke all on function private.is_admin() from public,anon;
grant execute on function private.is_admin() to authenticated;

create index if not exists courses_published_idx on public.courses(published);
create index if not exists enrollments_student_idx on public.enrollments(student_id);
create index if not exists orders_student_idx on public.orders(student_id);
create index if not exists orders_status_idx on public.orders(status);
create index if not exists enrollments_course_id_idx on public.enrollments(course_id);
create index if not exists orders_course_id_idx on public.orders(course_id);
create index if not exists activity_logs_actor_id_idx on public.activity_logs(actor_id);

alter table public.profiles enable row level security;
alter table public.courses enable row level security;
alter table public.enrollments enable row level security;
alter table public.orders enable row level security;
alter table public.site_content enable row level security;
alter table public.activity_logs enable row level security;

drop policy if exists "Profiles owner or admin read" on public.profiles;
create policy "Profiles owner or admin read" on public.profiles for select to authenticated using(id=(select auth.uid()) or private.is_admin());
drop policy if exists "Admin profile update" on public.profiles;
create policy "Admin profile update" on public.profiles for update to authenticated using(private.is_admin()) with check(private.is_admin());

drop policy if exists "Published courses read" on public.courses;
drop policy if exists "Published courses public read" on public.courses;
create policy "Published courses public read" on public.courses for select to anon using(published);
create policy "Published courses and admin read" on public.courses for select to authenticated using(published or private.is_admin());
drop policy if exists "Admin courses all" on public.courses;
create policy "Admin courses insert" on public.courses for insert to authenticated with check(private.is_admin());
create policy "Admin courses update" on public.courses for update to authenticated using(private.is_admin()) with check(private.is_admin());
create policy "Admin courses delete" on public.courses for delete to authenticated using(private.is_admin());

drop policy if exists "Enrollment owner/admin read" on public.enrollments;
create policy "Enrollment owner/admin read" on public.enrollments for select to authenticated using(student_id=(select auth.uid()) or private.is_admin());
drop policy if exists "Admin enrollments all" on public.enrollments;
create policy "Admin enrollments insert" on public.enrollments for insert to authenticated with check(private.is_admin());
create policy "Admin enrollments update" on public.enrollments for update to authenticated using(private.is_admin()) with check(private.is_admin());
create policy "Admin enrollments delete" on public.enrollments for delete to authenticated using(private.is_admin());

drop policy if exists "Orders owner/admin read" on public.orders;
create policy "Orders owner/admin read" on public.orders for select to authenticated using(student_id=(select auth.uid()) or private.is_admin());
drop policy if exists "Admin orders all" on public.orders;
create policy "Admin orders insert" on public.orders for insert to authenticated with check(private.is_admin());
create policy "Admin orders update" on public.orders for update to authenticated using(private.is_admin()) with check(private.is_admin());
create policy "Admin orders delete" on public.orders for delete to authenticated using(private.is_admin());

drop policy if exists "Site content read" on public.site_content;
create policy "Site content read" on public.site_content for select to anon,authenticated using(true);
drop policy if exists "Admin content all" on public.site_content;
create policy "Admin content insert" on public.site_content for insert to authenticated with check(private.is_admin());
create policy "Admin content update" on public.site_content for update to authenticated using(private.is_admin()) with check(private.is_admin());
create policy "Admin content delete" on public.site_content for delete to authenticated using(private.is_admin());

drop policy if exists "Admin activity logs" on public.activity_logs;
create policy "Admin activity logs" on public.activity_logs for all to authenticated using(private.is_admin()) with check(private.is_admin());

grant select on public.courses,public.site_content to anon,authenticated;
grant select,update on public.profiles to authenticated;
grant select,insert,update,delete on public.courses to authenticated;
grant select,insert,update,delete on public.enrollments,public.orders,public.site_content,public.activity_logs to authenticated;

-- Create your account through Supabase Auth first, then promote it:
-- update public.profiles set role='admin' where email='YOUR_EMAIL_ADDRESS';
