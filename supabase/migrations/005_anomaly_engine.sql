alter table anomalies add column if not exists dedupe_key text;
alter table anomalies add column if not exists detector varchar(32) not null default 'rule';
alter table anomalies add column if not exists model_score double precision;
alter table anomalies add column if not exists feedback varchar(16)
  check (feedback is null or feedback in ('true_positive','false_positive'));
alter table anomalies add column if not exists feedback_by uuid references auth.users(id);
alter table anomalies add column if not exists feedback_at timestamptz;

create unique index if not exists anomalies_active_dedupe_uidx
  on anomalies(dedupe_key)
  where dedupe_key is not null and status in ('open','acknowledged');
create index if not exists anomalies_feedback_idx on anomalies(org_id, anomaly_type, feedback);

alter table organisations add column if not exists timezone text not null default 'UTC';
alter table organisations add column if not exists work_start_hour smallint not null default 7
  check (work_start_hour between 0 and 23);
alter table organisations add column if not exists work_end_hour smallint not null default 20
  check (work_end_hour between 1 and 24);
