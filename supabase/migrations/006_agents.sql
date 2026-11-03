create table if not exists agents (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id),
  org_id uuid references organisations(id) on delete cascade,
  name varchar(120) not null,
  hostname varchar(255),
  platform varchar(64),
  version varchar(32),
  token_hash char(64) not null unique,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists agent_pairing_codes (
  code_hash char(64) primary key,
  user_id uuid not null references auth.users(id),
  org_id uuid references organisations(id) on delete cascade,
  name varchar(120) not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists agent_devices (
  agent_id uuid not null references agents(id) on delete cascade,
  serial varchar(128) not null,
  device jsonb not null,
  reported_at timestamptz not null default now(),
  primary key (agent_id, serial)
);

alter table wipe_jobs add column if not exists agent_id uuid references agents(id);
alter table wipe_jobs add column if not exists claimed_at timestamptz;
alter table wipe_jobs add column if not exists cancel_requested boolean not null default false;

create index if not exists wipe_jobs_agent_queue_idx on wipe_jobs(agent_id, status, created_at);
create index if not exists agents_user_idx on agents(user_id);
create index if not exists agents_org_idx on agents(org_id);

alter table agents enable row level security;
alter table agent_pairing_codes enable row level security;
alter table agent_devices enable row level security;
