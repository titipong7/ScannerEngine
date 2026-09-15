-- Table the Scanner Engine writes to.
create table if not exists public.scan_results (
    id          bigint generated always as identity primary key,
    domain      text        not null,
    scan_type   text        not null check (scan_type in ('dnssec', 'email', 'tls')),
    status      text        not null check (status in ('pass', 'warn', 'fail', 'error')),
    summary     text,
    findings    jsonb       not null default '[]'::jsonb,
    raw_data    jsonb       not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);

create index if not exists scan_results_domain_idx     on public.scan_results (domain);
create index if not exists scan_results_created_at_idx on public.scan_results (created_at desc);

-- The engine authenticates with the service-role key, which bypasses RLS.
-- Keep RLS on so that anon/authenticated clients cannot read rows by default.
alter table public.scan_results enable row level security;
