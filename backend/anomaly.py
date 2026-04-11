import json
import statistics
from datetime import datetime, timezone, timedelta
from typing import Any

import numpy as np
from scipy import stats

from backend.config import config
from backend.supabase_client import get_service_client

SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 15}

SENSITIVITY_THRESHOLDS = {
    "low": {
        "failed_logins": 10,
        "smart_reallocated": 5,
        "smart_temp": 65,
        "smart_power_on_hours": 60000,
        "repeat_wipe_hours": 1,
        "z_score_cutoff": 3.5,
    },
    "medium": {
        "failed_logins": 5,
        "smart_reallocated": 1,
        "smart_temp": 55,
        "smart_power_on_hours": 50000,
        "repeat_wipe_hours": 6,
        "z_score_cutoff": 2.5,
    },
    "high": {
        "failed_logins": 3,
        "smart_reallocated": 0,
        "smart_temp": 50,
        "smart_power_on_hours": 40000,
        "repeat_wipe_hours": 24,
        "z_score_cutoff": 2.0,
    },
}

SEEDED_BASELINE = {
    "wipe_duration_seconds": {"mean": 3600, "std": 900},
    "jobs_per_day": {"mean": 4.2, "std": 2.1},
    "login_hour": {"mean": 10.5, "std": 3.2},
}


def _get_thresholds(org_id: str | None) -> dict:
    if not org_id:
        return SENSITIVITY_THRESHOLDS["medium"]
    svc = get_service_client()
    r = (svc.table("organisations")
         .select("anomaly_sensitivity")
         .eq("id", org_id)
         .maybe_single()
         .execute())
    sensitivity = (r.data or {}).get("anomaly_sensitivity", "medium")
    return SENSITIVITY_THRESHOLDS.get(sensitivity, SENSITIVITY_THRESHOLDS["medium"])


def _get_event_count(org_id: str | None) -> int:
    svc = get_service_client()
    q = svc.table("audit_log").select("id", count="exact")
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    return r.count or 0


def _record_anomaly(anomaly_type: str, severity: str, source_event_id: str | None,
                    details: dict, org_id: str | None, user_id: str | None) -> dict:
    svc = get_service_client()
    from backend.audit import log_event

    row = {
        "anomaly_type": anomaly_type,
        "severity": severity,
        "source_event_id": source_event_id,
        "details": json.dumps(details),
        "org_id": org_id,
        "user_id": user_id,  # None is fine — anomalies.user_id is nullable
        "status": "open",
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    svc.table("anomalies").insert(row).execute()

    log_event(
        event_type="anomaly_detected",
        payload={"anomaly_type": anomaly_type, "severity": severity, "details": details},
        user_id=user_id,   # pass None, not "system" — audit_log.user_id is NOT NULL only for real events
        org_id=org_id,
        is_anomaly=True,
        anomaly_severity=severity,
        anomaly_type=anomaly_type,
    )

    return row


def check_failed_logins(email: str, org_id: str | None) -> dict | None:
    """
    Count failed login attempts for this email within the last 15 minutes.
    Queries event_payload->>'email' to avoid casting an email to UUID.
    """
    thresholds = _get_thresholds(org_id)
    svc = get_service_client()
    window = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

    # Filter by event_type and timestamp only — email is in the JSON payload
    r = (svc.table("audit_log")
         .select("id,event_payload", count="exact")
         .eq("event_type", "login_failed")
         .gte("created_at", window)
         .execute())

    # Count rows where event_payload contains this email
    count = 0
    for entry in (r.data or []):
        payload = entry.get("event_payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                continue
        if payload.get("email") == email:
            count += 1

    if count >= thresholds["failed_logins"]:
        return _record_anomaly(
            "brute_force_login",
            "critical" if count >= thresholds["failed_logins"] * 2 else "high",
            None,
            {"failed_count": count, "window_minutes": 15, "email": email},
            org_id,
            None,  # no UUID available for unauthenticated failed logins
        )
    return None


def check_new_ip(user_id: str, org_id: str | None, current_ip: str) -> dict | None:
    svc = get_service_client()
    r = (svc.table("audit_log")
         .select("event_payload")
         .eq("user_id", user_id)
         .eq("event_type", "login_success")
         .order("created_at", desc=True)
         .limit(20)
         .execute())

    known_ips = set()
    for entry in (r.data or []):
        payload = entry.get("event_payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                continue
        ip = payload.get("ip_address")
        if ip:
            known_ips.add(ip)

    if known_ips and current_ip not in known_ips:
        return _record_anomaly(
            "new_ip_login",
            "medium",
            None,
            {"new_ip": current_ip, "known_ips": list(known_ips)[:5]},
            org_id,
            user_id,
        )
    return None


def check_unusual_login_hour(user_id: str, org_id: str | None, login_dt: datetime) -> dict | None:
    event_count = _get_event_count(org_id)
    thresholds = _get_thresholds(org_id)
    hour = login_dt.hour

    if event_count < config.ANOMALY_BASELINE_MIN_EVENTS:
        mean = SEEDED_BASELINE["login_hour"]["mean"]
        std = SEEDED_BASELINE["login_hour"]["std"]
    else:
        svc = get_service_client()
        r = (svc.table("audit_log")
             .select("created_at")
             .eq("user_id", user_id)
             .eq("event_type", "login_success")
             .order("created_at", desc=True)
             .limit(50)
             .execute())
        hours = []
        for entry in (r.data or []):
            try:
                dt = datetime.fromisoformat(entry["created_at"].replace("Z", "+00:00"))
                hours.append(dt.hour)
            except Exception:
                continue
        if len(hours) < 5:
            mean = SEEDED_BASELINE["login_hour"]["mean"]
            std = SEEDED_BASELINE["login_hour"]["std"]
        else:
            mean = statistics.mean(hours)
            std = statistics.stdev(hours) or 1.0

    z = abs(hour - mean) / std
    if z > thresholds["z_score_cutoff"]:
        return _record_anomaly(
            "unusual_login_hour",
            "medium",
            None,
            {"hour": hour, "z_score": round(z, 2), "mean_hour": round(mean, 1)},
            org_id,
            user_id,
        )
    return None


def check_role_escalation(user_id: str, org_id: str | None,
                           old_role: str, new_role: str) -> dict | None:
    role_ranks = {"operator": 1, "team_lead": 2, "org_admin": 3}
    if role_ranks.get(new_role, 0) > role_ranks.get(old_role, 0):
        return _record_anomaly(
            "role_escalation",
            "high",
            None,
            {"old_role": old_role, "new_role": new_role},
            org_id,
            user_id,
        )
    return None


def check_verification_failure(job_id: str, org_id: str | None, user_id: str) -> dict | None:
    return _record_anomaly(
        "wipe_verification_failure",
        "critical",
        job_id,
        {"job_id": job_id, "message": "Overwrite verification read-back failed"},
        org_id,
        user_id,
    )


def check_off_hours_wipe(job_id: str, org_id: str | None, user_id: str,
                          submitted_at: datetime) -> dict | None:
    hour = submitted_at.hour
    if hour < 7 or hour > 20:
        return _record_anomaly(
            "off_hours_wipe",
            "medium",
            job_id,
            {"hour": hour, "submitted_at": submitted_at.isoformat()},
            org_id,
            user_id,
        )
    return None


def check_repeat_wipe(device_serial: str, org_id: str | None, user_id: str) -> dict | None:
    thresholds = _get_thresholds(org_id)
    svc = get_service_client()
    window = (datetime.now(timezone.utc) - timedelta(hours=thresholds["repeat_wipe_hours"])).isoformat()

    q = (svc.table("wipe_jobs")
         .select("id", count="exact")
         .eq("device_serial", device_serial)
         .eq("status", "completed")
         .gte("completed_at", window))
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    count = r.count or 0

    if count >= 2:
        return _record_anomaly(
            "repeat_wipe",
            "medium",
            None,
            {"device_serial": device_serial, "count": count,
             "window_hours": thresholds["repeat_wipe_hours"]},
            org_id,
            user_id,
        )
    return None


def check_new_operator(user_id: str, org_id: str | None, job_id: str) -> dict | None:
    svc = get_service_client()
    r = (svc.table("wipe_jobs")
         .select("id", count="exact")
         .eq("user_id", user_id)
         .eq("status", "completed")
         .execute())
    count = r.count or 0
    if count == 0:
        return _record_anomaly(
            "new_operator_first_wipe",
            "low",
            job_id,
            {"user_id": user_id, "message": "First wipe job submitted by this operator"},
            org_id,
            user_id,
        )
    return None


def check_smart_anomalies(device_serial: str, smart_snapshot: dict,
                           org_id: str | None, user_id: str) -> list[dict]:
    thresholds = _get_thresholds(org_id)
    anomalies = []

    if not smart_snapshot or not smart_snapshot.get("available"):
        return anomalies

    for attr in smart_snapshot.get("attributes", []):
        if attr["name"] == "Reallocated_Sector_Ct":
            raw_val = int(str(attr["raw"]).split()[0]) if attr["raw"] else 0
            if raw_val > thresholds["smart_reallocated"]:
                anomalies.append(_record_anomaly(
                    "smart_reallocated_sectors",
                    "high" if raw_val > 10 else "medium",
                    None,
                    {"device_serial": device_serial, "reallocated_count": raw_val},
                    org_id, user_id,
                ))

        if attr["name"] in ("Temperature_Celsius", "Airflow_Temperature_Cel"):
            temp = int(str(attr["raw"]).split()[0]) if attr["raw"] else 0
            if temp > thresholds["smart_temp"]:
                anomalies.append(_record_anomaly(
                    "smart_high_temperature",
                    "high",
                    None,
                    {"device_serial": device_serial, "temperature": temp},
                    org_id, user_id,
                ))

        if attr["name"] == "Power_On_Hours":
            hours = int(str(attr["raw"]).split()[0]) if attr["raw"] else 0
            if hours > thresholds["smart_power_on_hours"]:
                anomalies.append(_record_anomaly(
                    "smart_high_power_on_hours",
                    "medium",
                    None,
                    {"device_serial": device_serial, "power_on_hours": hours},
                    org_id, user_id,
                ))

        flags = str(attr.get("flags", "")).upper()
        if "FAILING_NOW" in flags or attr.get("value", 0) < attr.get("threshold", 0):
            anomalies.append(_record_anomaly(
                "smart_attribute_failed",
                "critical",
                None,
                {"device_serial": device_serial, "attribute": attr["name"],
                 "value": attr.get("value"), "threshold": attr.get("threshold")},
                org_id, user_id,
            ))

    return anomalies


def run_statistical_batch(org_id: str | None = None) -> list[dict]:
    event_count = _get_event_count(org_id)
    if event_count < config.ANOMALY_BASELINE_MIN_EVENTS:
        return []

    svc = get_service_client()
    thresholds = _get_thresholds(org_id)
    anomalies = []

    q = (svc.table("wipe_jobs")
         .select("id,user_id,started_at,completed_at,org_id")
         .eq("status", "completed"))
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    jobs = r.data or []

    durations = []
    for j in jobs:
        try:
            start = datetime.fromisoformat(j["started_at"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(j["completed_at"].replace("Z", "+00:00"))
            durations.append((j["id"], (end - start).total_seconds()))
        except Exception:
            continue

    if len(durations) >= 10:
        times = [d[1] for d in durations]
        mean_t = statistics.mean(times)
        std_t = statistics.stdev(times) or 1.0
        cutoff = thresholds["z_score_cutoff"]

        for job_id, dur in durations[-20:]:
            z = abs(dur - mean_t) / std_t
            if z > cutoff:
                anomalies.append(_record_anomaly(
                    "statistical_wipe_duration_outlier",
                    "medium",
                    job_id,
                    {"duration_seconds": dur, "z_score": round(z, 2),
                     "mean_seconds": round(mean_t, 1)},
                    org_id,
                    None,
                ))

    return anomalies


def compute_risk_score(org_id: str | None) -> dict:
    svc = get_service_client()
    q = (svc.table("anomalies")
         .select("severity")
         .eq("status", "open"))
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    open_anomalies = r.data or []

    total_weight = sum(SEVERITY_WEIGHTS.get(a["severity"], 1) for a in open_anomalies)
    score = min(100, total_weight)

    if score >= 60:
        level = "critical"
        colour = "#c44a42"
    elif score >= 30:
        level = "high"
        colour = "#c4901a"
    elif score >= 10:
        level = "medium"
        colour = "#c4b48a"
    else:
        level = "low"
        colour = "#4a5442"

    return {
        "score": score,
        "level": level,
        "colour": colour,
        "open_count": len(open_anomalies),
    }


def acknowledge_anomaly(anomaly_id: str, user_id: str, note: str | None,
                         resolved: bool) -> dict:
    svc = get_service_client()
    update = {
        "status": "resolved" if resolved else "acknowledged",
        "acknowledged_by": user_id,
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
    }
    if note:
        update["resolution_note"] = note
    if resolved:
        update["resolved_at"] = datetime.now(timezone.utc).isoformat()

    r = (svc.table("anomalies")
         .update(update)
         .eq("id", anomaly_id)
         .execute())
    return r.data[0] if r.data else {}