from datetime import datetime, timedelta, timezone

from ml import behaviour, datasource, drive_health, wipe_duration
from ml.feedback import cutoff_multiplier
from ml.paths import scope_name


def score_job(job: dict, record: dict) -> list[dict]:
    org_id = job.get("org_id")
    scope = scope_name(org_id)
    found = wipe_duration.score(job, record, scope, cutoff_multiplier(org_id, "ml_wipe_too_fast"))
    history = datasource.user_jobs(job["user_id"])
    found += behaviour.score_job(job, history, datasource.first_job_at(job["user_id"]),
                                 datasource.org_timezone(org_id), scope,
                                 cutoff_multiplier(org_id, "ml_unusual_job_behaviour"))
    return found


def score_login(user_id: str, org_id: str | None, ip: str, at: datetime) -> list[dict]:
    logins = datasource.user_logins(user_id)
    email = logins[0]["event_payload"].get("email") if logins else None
    prior = logins[1:]
    since = (at - timedelta(minutes=15)).astimezone(timezone.utc).isoformat()
    failed = sum(1 for e in datasource.failed_logins_since(since) if email and e["event_payload"].get("email") == email)
    return behaviour.score_login(user_id, at, ip, prior, failed, datasource.org_timezone(org_id),
                                 scope_name(org_id), cutoff_multiplier(org_id, "ml_unusual_login"))


def score_smart(serial: str, snapshot: dict, capacity_bytes: int | None = None) -> list[dict]:
    return drive_health.score(serial, snapshot, capacity_bytes)
