-- SkillNest Supabase schema. Run once in Supabase SQL Editor.
create extension if not exists pgcrypto;
create table if not exists public.profiles(id uuid primary key references auth.users(id) on delete cascade,email text unique,full_name text,role text not null default 'learner' check(role in ('learner','admin')),created_at timestamptz not null default now());
create table if not exists public.courses(id uuid primary key default gen_random_uuid(),title text not null,slug text not null unique,category text not null,course_type text not null default 'Certificate' check(course_type in ('Certificate','Diploma')),price numeric(10,2) not null default 0 check(price>=0),level text not null default 'Beginner',description text not null default '',image_url text not null default '',published boolean not null default false,created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create table if not exists public.enrollments(id uuid primary key default gen_random_uuid(),student_id uuid not null references public.profiles(id) on delete cascade,course_id uuid not null references public.courses(id) on delete cascade,status text not null default 'active' check(status in ('active','completed','cancelled')),progress integer not null default 0 check(progress between 0 and 100),created_at timestamptz not null default now(),unique(student_id,course_id));
create table if not exists public.orders(id uuid primary key default gen_random_uuid(),student_id uuid references public.profiles(id) on delete set null,customer_email text not null,course_id uuid references public.courses(id) on delete set null,course_title text not null,amount numeric(10,2) not null check(amount>=0),currency text not null default 'USD',status text not null default 'pending' check(status in ('pending','paid','refunded','cancelled')),payment_provider text,provider_reference text,created_at timestamptz not null default now());
create table if not exists public.site_content(id uuid primary key default gen_random_uuid(),key text not null unique,title text not null default '',body text not null default '',updated_at timestamptz not null default now());
create table if not exists public.activity_logs(id uuid primary key default gen_random_uuid(),actor_id uuid references public.profiles(id) on delete set null,action text not null,entity_type text,entity_id uuid,details jsonb not null default '{}'::jsonb,created_at timestamptz not null default now());
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$ begin insert into public.profiles(id,email,full_name) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name','')) on conflict(id) do update set email=excluded.email; return new; end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin'); $$;
alter table public.profiles enable row level security; alter table public.courses enable row level security; alter table public.enrollments enable row level security; alter table public.orders enable row level security; alter table public.site_content enable row level security; alter table public.activity_logs enable row level security;
create policy "Profiles owner or admin read" on public.profiles for select to authenticated using(id=auth.uid() or public.is_admin());
create policy "Admin profile update" on public.profiles for update to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "Published courses read" on public.courses for select to anon,authenticated using(published or public.is_admin());
create policy "Admin courses all" on public.courses for all to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "Enrollment owner/admin read" on public.enrollments for select to authenticated using(student_id=auth.uid() or public.is_admin());
create policy "Admin enrollments all" on public.enrollments for all to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "Orders owner/admin read" on public.orders for select to authenticated using(student_id=auth.uid() or public.is_admin());
create policy "Admin orders all" on public.orders for all to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "Site content read" on public.site_content for select to anon,authenticated using(true);
create policy "Admin content all" on public.site_content for all to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "Admin activity logs" on public.activity_logs for all to authenticated using(public.is_admin()) with check(public.is_admin());
-- Create your first account in Supabase Auth, then run:
-- update public.profiles set role='admin' where email='YOUR_EMAIL_ADDRESS';
