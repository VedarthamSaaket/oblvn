drop policy if exists "service role full audit access" on audit_log;
drop policy if exists "service role full job access" on wipe_jobs;
drop policy if exists "service role full org access" on organisations;
drop policy if exists "service role full membership access" on org_memberships;
drop policy if exists "service role full anomaly access" on anomalies;
drop policy if exists "users insert own jobs" on wipe_jobs;

drop policy if exists "org admins see org audit entries" on audit_log;
drop policy if exists "org members see org jobs" on wipe_jobs;
drop policy if exists "org members see their org" on organisations;
drop policy if exists "org members see memberships" on org_memberships;
drop policy if exists "org members see anomalies" on anomalies;

create or replace function public.oblvn_user_org_ids(uid uuid, min_rank int default 1)
returns setof uuid
language sql
security definer
stable
set search_path = public
as $$
  select org_id
  from org_memberships
  where user_id = uid
    and (case role when 'org_admin' then 3 when 'team_lead' then 2 else 1 end) >= min_rank
$$;

revoke all on function public.oblvn_user_org_ids(uuid, int) from public, anon;
grant execute on function public.oblvn_user_org_ids(uuid, int) to authenticated;

create policy "org admins see org audit entries"
  on audit_log for select to authenticated
  using (org_id in (select public.oblvn_user_org_ids(auth.uid(), 3)));

create policy "org members see org jobs"
  on wipe_jobs for select to authenticated
  using (org_id in (select public.oblvn_user_org_ids(auth.uid(), 1)));

create policy "org members see their org"
  on organisations for select to authenticated
  using (id in (select public.oblvn_user_org_ids(auth.uid(), 1)));

create policy "org members see memberships"
  on org_memberships for select to authenticated
  using (user_id = auth.uid() or org_id in (select public.oblvn_user_org_ids(auth.uid(), 1)));

create policy "org members see anomalies"
  on anomalies for select to authenticated
  using (user_id = auth.uid() or org_id in (select public.oblvn_user_org_ids(auth.uid(), 1)));

alter policy "users see own audit entries" on audit_log to authenticated;
alter policy "users see own jobs" on wipe_jobs to authenticated;
