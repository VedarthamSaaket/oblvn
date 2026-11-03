alter table audit_log alter column user_id drop not null;

alter table audit_log
  add column if not exists chain_key text generated always as (coalesce(org_id::text, 'global')) stored;

create index if not exists audit_log_chain_key_idx on audit_log(chain_key, id);

do $$
declare
  last_id bigint;
begin
  select coalesce(max(id), 0) into last_id from audit_log;
  execute format(
    'create unique index if not exists audit_log_chain_prev_uidx on audit_log(chain_key, prev_entry_hash) where id > %s',
    last_id
  );
end $$;
