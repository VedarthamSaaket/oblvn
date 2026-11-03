import json
from datetime import datetime, timedelta, timezone

from backend.audit import fetch_all
from backend.db import get_service_client

JOB_COLUMNS = (
    "id,user_id,org_id,status,method,standard,device_type,device_capacity_bytes,device_serial,"
    "technique,nist_category,passes_completed,duration_seconds,bytes_written,throughput_mbps,"
    "approved_by,created_at,started_at,completed_at,wipe_record"
)


def _json(value, default):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value if value is not None else default


def _scoped(q, org_id: str | None):
    return q.eq("org_id", org_id) if org_id else q.is_("org_id", "null")


def org_ids() -> list[str]:
    svc = get_service_client()
    return [o["id"] for o in fetch_all(lambda: svc.table("organisations").select("id").order("id"))]


def jobs(org_id: str | None, all_scopes: bool = False) -> list[dict]:
    svc = get_service_client()

    def build():
        q = svc.table("wipe_jobs").select(JOB_COLUMNS).order("created_at")
        return q if all_scopes else _scoped(q, org_id)
    rows = fetch_all(build)
    for r in rows:
        r["wipe_record"] = _json(r.get("wipe_record"), {})
    return rows


def user_jobs(user_id: str, before: str | None = None, days: int = 90) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    q = (get_service_client().table("wipe_jobs").select("id,status,created_at,approved_by")
         .eq("user_id", user_id).gte("created_at", since).order("created_at"))
    if before:
        q = q.lt("created_at", before)
    return q.execute().data or []


def first_job_at(user_id: str) -> str | None:
    r = (get_service_client().table("wipe_jobs").select("created_at")
         .eq("user_id", user_id).order("created_at").limit(1).execute())
    return r.data[0]["created_at"] if r.data else None


def logins(org_id: str | None, all_scopes: bool = False) -> list[dict]:
    svc = get_service_client()

    def build():
        q = (svc.table("audit_log").select("user_id,org_id,event_type,event_payload,created_at")
             .in_("event_type", ["login_success", "login_failed"]).order("id"))
        return q if all_scopes else _scoped(q, org_id)
    rows = fetch_all(build)
    for r in rows:
        r["event_payload"] = _json(r.get("event_payload"), {})
    return rows


def user_logins(user_id: str, limit: int = 200) -> list[dict]:
    rows = (get_service_client().table("audit_log").select("created_at,event_payload")
            .eq("user_id", user_id).eq("event_type", "login_success")
            .order("created_at", desc=True).limit(limit).execute().data or [])
    for r in rows:
        r["event_payload"] = _json(r.get("event_payload"), {})
    return rows


def failed_logins_since(since: str) -> list[dict]:
    rows = (get_service_client().table("audit_log").select("created_at,event_payload")
            .eq("event_type", "login_failed").gte("created_at", since).execute().data or [])
    for r in rows:
        r["event_payload"] = _json(r.get("event_payload"), {})
    return rows


def labelled_anomalies(org_id: str | None) -> list[dict]:
    svc = get_service_client()

    def build():
        q = svc.table("anomalies").select("anomaly_type,feedback").not_.is_("feedback", "null").order("id")
        return _scoped(q, org_id)
    return fetch_all(build)


def org_timezone(org_id: str | None) -> str:
    if not org_id:
        return "UTC"
    r = get_service_client().table("organisations").select("timezone").eq("id", org_id).maybe_single().execute()
    return ((r.data if r else None) or {}).get("timezone") or "UTC"
