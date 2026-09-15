-- =============================================================================
-- Web Audit Platform — canonical schema
--
-- Run this in the Supabase SQL editor. It is idempotent: safe to re-run, and it
-- upgrades a database that only had the original `scan_results` table.
--
-- Trust model: the Scanner Engine connects with the SERVICE ROLE key, which
-- bypasses RLS. Every policy below therefore exists to constrain the *browser*
-- (anon / authenticated keys), never the engine. The service-role key must stay
-- server-side.
-- =============================================================================

-- --------------------------------------------------------------------------- 
-- profiles — one row per auth user
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
    id                  uuid primary key references auth.users on delete cascade,
    email               text,
    plan                text        not null default 'free',
    monthly_scan_quota  integer     not null default 100,
    created_at          timestamptz not null default now()
);

-- Create the profile automatically when someone signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.profiles (id, email)
    values (new.id, new.email)
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- domains — what a user chose to keep an eye on
-- ---------------------------------------------------------------------------
create table if not exists public.domains (
    id              bigint generated always as identity primary key,
    user_id         uuid        not null references auth.users on delete cascade,
    domain          text        not null,
    label           text,
    created_at      timestamptz not null default now(),
    last_scanned_at timestamptz,
    unique (user_id, domain)
);

create index if not exists domains_user_idx on public.domains (user_id);

-- ---------------------------------------------------------------------------
-- scans — one row per "the user pressed Scan", ties the modules together
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
    id          bigint generated always as identity primary key,
    domain      text        not null,
    user_id     uuid        references auth.users on delete set null,
    domain_id   bigint      references public.domains on delete set null,
    trigger     text        not null default 'manual'
                            check (trigger in ('manual', 'scheduled', 'api')),
    score       integer     check (score between 0 and 100),
    grade       text        check (grade in ('A', 'B', 'C', 'D', 'F')),
    duration_ms integer,
    created_at  timestamptz not null default now()
);

create index if not exists scans_domain_idx     on public.scans (domain, created_at desc);
create index if not exists scans_user_idx       on public.scans (user_id, created_at desc);

-- ---------------------------------------------------------------------------
-- scan_results — raw per-module output (created by the original schema)
-- ---------------------------------------------------------------------------
create table if not exists public.scan_results (
    id          bigint generated always as identity primary key,
    domain      text        not null,
    scan_type   text        not null,
    status      text        not null,
    summary     text,
    findings    jsonb       not null default '[]'::jsonb,
    raw_data    jsonb       not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);

-- Upgrade path for databases created before scans/scores existed.
alter table public.scan_results add column if not exists scan_id bigint
    references public.scans on delete cascade;
alter table public.scan_results add column if not exists user_id uuid
    references auth.users on delete set null;

-- Re-assert the value constraints so adding a module only means editing here.
alter table public.scan_results drop constraint if exists scan_results_scan_type_check;
alter table public.scan_results add  constraint scan_results_scan_type_check
    check (scan_type in ('dnssec', 'email', 'tls', 'dkim'));

alter table public.scan_results drop constraint if exists scan_results_status_check;
alter table public.scan_results add  constraint scan_results_status_check
    check (status in ('pass', 'warn', 'fail', 'error'));

create index if not exists scan_results_domain_idx     on public.scan_results (domain);
create index if not exists scan_results_created_at_idx on public.scan_results (created_at desc);
create index if not exists scan_results_scan_idx       on public.scan_results (scan_id);

-- ---------------------------------------------------------------------------
-- scores — the graded breakdown, one row per scan, for plotting history
-- ---------------------------------------------------------------------------
create table if not exists public.scores (
    id                bigint generated always as identity primary key,
    scan_id           bigint      not null unique references public.scans on delete cascade,
    domain            text        not null,
    user_id           uuid        references auth.users on delete set null,
    score             integer     not null check (score between 0 and 100),
    grade             text        not null check (grade in ('A', 'B', 'C', 'D', 'F')),
    -- Share of the scoring model we could actually evaluate (1.0 = all of it).
    coverage          numeric(4, 3) not null default 1.0,
    -- Per-component detail: [{key, label, status, weight, credit, points}, ...]
    breakdown         jsonb       not null default '[]'::jsonb,
    created_at        timestamptz not null default now()
);

create index if not exists scores_domain_idx on public.scores (domain, created_at desc);
create index if not exists scores_user_idx   on public.scores (user_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Row Level Security
--
-- Default deny. A user reads only their own rows; the engine uses the service
-- role and is unaffected by everything below.
-- ---------------------------------------------------------------------------
alter table public.profiles     enable row level security;
alter table public.domains      enable row level security;
alter table public.scans        enable row level security;
alter table public.scan_results enable row level security;
alter table public.scores       enable row level security;

drop policy if exists "own profile"        on public.profiles;
create policy "own profile" on public.profiles
    for all to authenticated
    using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "own domains"        on public.domains;
create policy "own domains" on public.domains
    for all to authenticated
    using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "own scans"          on public.scans;
create policy "own scans" on public.scans
    for select to authenticated
    using (user_id = auth.uid());

drop policy if exists "own scan results"   on public.scan_results;
create policy "own scan results" on public.scan_results
    for select to authenticated
    using (
        user_id = auth.uid()
        or exists (
            select 1 from public.scans s
            where s.id = scan_results.scan_id and s.user_id = auth.uid()
        )
    );

drop policy if exists "own scores"         on public.scores;
create policy "own scores" on public.scores
    for select to authenticated
    using (
        user_id = auth.uid()
        or exists (
            select 1 from public.scans s
            where s.id = scores.scan_id and s.user_id = auth.uid()
        )
    );

-- Anonymous scans (user_id is null) are readable by nobody through the API;
-- the dashboard returns them from the scan response itself instead.

-- ---------------------------------------------------------------------------
-- Convenience view: the newest score per domain, for a user's overview page
-- ---------------------------------------------------------------------------
create or replace view public.latest_scores as
select distinct on (domain, user_id)
    domain, user_id, scan_id, score, grade, coverage, breakdown, created_at
from public.scores
order by domain, user_id, created_at desc;
