alter table wipe_jobs add column if not exists file_paths jsonb;
alter table wipe_jobs add column if not exists options jsonb not null default '{}'::jsonb;
alter table wipe_jobs add column if not exists technique varchar(64);
alter table wipe_jobs add column if not exists nist_category varchar(32)
  check (nist_category is null or nist_category in ('purge','clear','none','not_applicable'));
alter table wipe_jobs add column if not exists wipe_record jsonb;
alter table wipe_jobs add column if not exists bytes_written bigint;
alter table wipe_jobs add column if not exists duration_seconds numeric(14,3);
alter table wipe_jobs add column if not exists throughput_mbps numeric(12,2);

create index if not exists wipe_jobs_status_idx on wipe_jobs(status);
create index if not exists wipe_jobs_org_completed_idx on wipe_jobs(org_id, completed_at);
