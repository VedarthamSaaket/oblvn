create extension if not exists "uuid-ossp";

create table if not exists organisations (
  id uuid primary key default uuid_generate_v4(),
  name varchar(255) not null,
  approval_gate_enabled boolean default false,
  audit_retention_days integer default 2555,
  anomaly_sensitivity varchar(16) default 'medium' check (anomaly_sensitivity in ('low','medium','high')),
  data_minimisation_config jsonb,
  created_at timestamptz not null default now()
);

create table if not exists org_memberships (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  org_id uuid not null references organisations(id) on delete cascade,
  role varchar(32) not null check (role in ('org_admin','team_lead','operator')),
  team_id uuid,
  invited_at timestamptz not null default now(),
  joined_at timestamptz,
  unique(user_id, org_id)
);

create table if not exists wipe_jobs (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id),
  org_id uuid references organisations(id),
  status varchar(32) not null default 'queued'
    check (status in ('pending_approval','queued','running','completed','failed','cancelled')),
  method varchar(32) not null
    check (method in ('binary_overwrite','crypto_erase','full_sanitization')),
  standard varchar(64) not null,
  device_serial varchar(128) not null,
  device_model varchar(255) not null,
  device_capacity_bytes bigint not null,
  device_type varchar(32) not null
    check (device_type in ('hdd','ssd','nvme','usb_flash','file')),
  smart_snapshot jsonb,
  passes_completed integer default 0,
  verification_passed boolean,
  sha256_hash char(64),
  ots_proof_path text,
  pdf_path text,
  approved_by uuid references auth.users(id),
  error_message text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists audit_log (
  id bigserial primary key,
  org_id uuid references organisations(id),
  user_id uuid not null,
  event_type varchar(64) not null,
  event_payload jsonb not null,
  prev_entry_hash char(64) not null,
  entry_hash char(64) not null,
  is_anomaly boolean default false,
  anomaly_severity varchar(16),
  anomaly_type varchar(64),
  created_at timestamptz not null default now()
);

create index if not exists audit_log_org_id_idx on audit_log(org_id);
create index if not exists audit_log_user_id_idx on audit_log(user_id);
create index if not exists audit_log_created_at_idx on audit_log(created_at);
create index if not exists audit_log_is_anomaly_idx on audit_log(is_anomaly);

create table if not exists anomalies (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organisations(id),
  user_id uuid,
  anomaly_type varchar(64) not null,
  severity varchar(16) not null check (severity in ('low','medium','high','critical')),
  source_event_id text,
  details jsonb,
  status varchar(32) default 'open' check (status in ('open','acknowledged','resolved')),
  acknowledged_by uuid references auth.users(id),
  acknowledged_at timestamptz,
  resolution_note text,
  resolved_at timestamptz,
  detected_at timestamptz not null default now()
);

create index if not exists anomalies_org_id_idx on anomalies(org_id);
create index if not exists anomalies_status_idx on anomalies(status);
create index if not exists anomalies_severity_idx on anomalies(severity);

alter table audit_log enable row level security;
alter table wipe_jobs enable row level security;
alter table org_memberships enable row level security;
alter table organisations enable row level security;
alter table anomalies enable row level security;

create policy "users see own audit entries"
  on audit_log for select
  using (user_id = auth.uid());

create policy "org admins see org audit entries"
  on audit_log for select
  using (
    org_id in (
      select org_id from org_memberships
      where user_id = auth.uid() and role = 'org_admin'
    )
  );

create policy "service role full audit access"
  on audit_log for all
  using (true)
  with check (true);

create policy "users see own jobs"
  on wipe_jobs for select
  using (user_id = auth.uid());

create policy "org members see org jobs"
  on wipe_jobs for select
  using (
    org_id in (
      select org_id from org_memberships where user_id = auth.uid()
    )
  );

create policy "users insert own jobs"
  on wipe_jobs for insert
  with check (user_id = auth.uid());

create policy "service role full job access"
  on wipe_jobs for all
  using (true)
  with check (true);

create policy "org members see their org"
  on organisations for select
  using (
    id in (
      select org_id from org_memberships where user_id = auth.uid()
    )
  );

create policy "org members see memberships"
  on org_memberships for select
  using (
    org_id in (
      select org_id from org_memberships where user_id = auth.uid()
    )
  );

create policy "service role full org access"
  on organisations for all using (true) with check (true);

create policy "service role full membership access"
  on org_memberships for all using (true) with check (true);

create policy "org members see anomalies"
  on anomalies for select
  using (
    user_id = auth.uid()
    or org_id in (
      select org_id from org_memberships where user_id = auth.uid()
    )
  );

create policy "service role full anomaly access"
  on anomalies for all using (true) with check (true);

create or replace function enforce_audit_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'Audit log is append-only. Updates and deletes are forbidden.';
end;
$$;

create trigger audit_log_immutable
  before update or delete on audit_log
  for each row execute function enforce_audit_append_only();

alter publication supabase_realtime add table wipe_jobs;
alter publication supabase_realtime add table anomalies;
