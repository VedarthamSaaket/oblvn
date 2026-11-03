import json
import math
import statistics
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from backend.db import get_service_client

SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 15}
ACTIVE_STATUSES = ("open", "acknowledged")

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
    "wipe_seconds_per_gib_pass": {"mean": 9.0, "std": 4.0},
    "login_hour": {"mean": 10.5, "std": 3.2},
}
MIN_USER_LOGINS = 10
MIN_DURATION_SAMPLES = 10
_settings_cache: dict[str, tuple[float, dict]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _payload(entry: dict) -> dict:
    payload = entry.get("event_payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return {}
    return payload if isinstance(payload, dict) else {}


def org_settings(org_id: str | None) -> dict:
    defaults = {"anomaly_sensitivity": "medium", "timezone": "UTC", "work_start_hour": 7, "work_end_hour": 20}
    if not org_id:
        return defaults
    cached = _settings_cache.get(org_id)
    if cached and time.monotonic() - cached[0] < 60:
        return cached[1]
    r = (get_service_client().table("organisations")
         .select("anomaly_sensitivity,timezone,work_start_hour,work_end_hour")
         .eq("id", org_id).maybe_single().execute())
    settings = {**defaults, **{k: v for k, v in (r.data or {}).items() if v is not None}}
    _settings_cache[org_id] = (time.monotonic(), settings)
    return settings


def _get_thresholds(org_id: str | None) -> dict:
    sensitivity = org_settings(org_id).get("anomaly_sensitivity", "medium")
    return SENSITIVITY_THRESHOLDS.get(sensitivity, SENSITIVITY_THRESHOLDS["medium"])


def _zone(org_id: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(org_settings(org_id).get("timezone") or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def _cutoff(org_id: str | None, anomaly_type: str) -> float:
    base = _get_thresholds(org_id)["z_score_cutoff"]
    try:
        from ml.feedback import cutoff_multiplier
        return base * cutoff_multiplier(org_id, anomaly_type)
    except Exception:
        return base


def primary_org(user_id: str | None) -> str | None:
    if not user_id:
        return None
    r = (get_service_client().table("org_memberships")
         .select("org_id").eq("user_id", user_id).order("invited_at").limit(1).execute())
    return r.data[0]["org_id"] if r.data else None


def _existing(dedupe_key: str) -> dict | None:
    r = (get_service_client().table("anomalies").select("*")
         .eq("dedupe_key", dedupe_key).in_("status", list(ACTIVE_STATUSES)).limit(1).execute())
    return r.data[0] if r.data else None


def _record_anomaly(anomaly_type: str, severity: str, source_event_id: str | None,
                    details: dict, org_id: str | None, user_id: str | None,
                    dedupe_key: str | None = None, model: dict | None = None) -> dict:
    from backend.audit import log_event

    if dedupe_key:
        found = _existing(dedupe_key)
        if found:
            return found
    row = {
        "anomaly_type": anomaly_type,
        "severity": severity,
        "source_event_id": source_event_id,
        "details": details,
        "org_id": org_id,
        "user_id": user_id,
        "status": "open",
        "dedupe_key": dedupe_key,
        "detector": (model or {}).get("detector", "rule"),
        "model_score": (model or {}).get("score"),
        "detected_at": _now().isoformat(),
    }
    try:
        r = get_service_client().table("anomalies").insert(row).execute()
        row = r.data[0] if r.data else row
    except Exception as exc:
        if dedupe_key and ("23505" in str(exc) or "duplicate key" in str(exc)):
            return _existing(dedupe_key) or row
        raise
    log_event(
        event_type="anomaly_detected",
        payload={"anomaly_type": anomaly_type, "severity": severity, "details": details},
        user_id=user_id,
        org_id=org_id,
        is_anomaly=True,
        anomaly_severity=severity,
        anomaly_type=anomaly_type,
    )
    return row


def record_model_anomaly(finding: dict, org_id: str | None, user_id: str | None) -> dict:
    return _record_anomaly(
        finding["anomaly_type"], finding["severity"], finding.get("source_event_id"),
        finding.get("details", {}), org_id, user_id,
        dedupe_key=finding.get("dedupe_key"),
        model={"detector": finding.get("detector", "model"), "score": finding.get("score")},
    )


def check_failed_logins(email: str, org_id: str | None, ip: str | None = None) -> list[dict]:
    thresholds = _get_thresholds(org_id)
    window = (_now() - timedelta(minutes=15)).isoformat()
    r = (get_service_client().table("audit_log").select("event_payload")
         .eq("event_type", "login_failed").gte("created_at", window).execute())
    by_email = 0
    by_ip = 0
    emails_from_ip = set()
    for entry in r.data or []:
        p = _payload(entry)
        if p.get("email") == email:
            by_email += 1
        if ip and p.get("ip_address") == ip:
            by_ip += 1
            emails_from_ip.add(p.get("email"))
    found = []
    limit = thresholds["failed_logins"]
    bucket = _now().strftime("%Y%m%d%H") + str(_now().minute // 15)
    if by_email >= limit:
        found.append(_record_anomaly(
            "brute_force_login", "critical" if by_email >= limit * 2 else "high", None,
            {"failed_count": by_email, "window_minutes": 15, "email": email, "ip_address": ip},
            org_id, None, dedupe_key=f"brute_force:{email}:{bucket}",
        ))
    if ip and by_ip >= limit * 2 and len(emails_from_ip) > 1:
        found.append(_record_anomaly(
            "credential_stuffing", "critical", None,
            {"failed_count": by_ip, "distinct_emails": len(emails_from_ip), "window_minutes": 15, "ip_address": ip},
            org_id, None, dedupe_key=f"stuffing:{ip}:{bucket}",
        ))
    return found


def _login_history(user_id: str, limit: int = 100) -> list[dict]:
    r = (get_service_client().table("audit_log").select("created_at,event_payload")
         .eq("user_id", user_id).eq("event_type", "login_success")
         .order("created_at", desc=True).limit(limit).execute())
    return r.data or []


def _geo(ip: str | None) -> dict | None:
    try:
        from ml import geo
        return geo.lookup(ip)
    except Exception:
        return None


def check_new_ip(user_id: str, org_id: str | None, current_ip: str) -> dict | None:
    history = _login_history(user_id, 50)[1:]
    known = {_payload(e).get("ip_address") for e in history} - {None}
    if known and current_ip not in known:
        here = _geo(current_ip) or {}
        countries = {g.get("country") for g in (_geo(i) for i in known) if g}
        new_country = bool(here.get("country") and countries and here["country"] not in countries)
        return _record_anomaly(
            "new_ip_login", "high" if new_country else "medium", None,
            {"new_ip": current_ip, "known_ips": sorted(known)[:5], "country": here.get("country"),
             "city": here.get("city"), "asn": here.get("asn"), "asn_org": here.get("asn_org"),
             "new_country": new_country, "known_countries": sorted(c for c in countries if c)},
            org_id, user_id, dedupe_key=f"new_ip:{user_id}:{current_ip}",
        )
    return None


def check_impossible_travel(user_id: str, org_id: str | None, current_ip: str, at: datetime) -> dict | None:
    history = _login_history(user_id, 5)[1:]
    if not history:
        return None
    prev = history[0]
    prev_ip = _payload(prev).get("ip_address")
    prev_at = _parse_ts(prev.get("created_at"))
    if not prev_ip or prev_ip == current_ip or not prev_at:
        return None
    try:
        from ml import geo
    except Exception:
        return None
    a, b = geo.lookup(prev_ip), geo.lookup(current_ip)
    trip = geo.travel(a, b, (at - prev_at).total_seconds() / 3600)
    if not trip or not trip["impossible"]:
        return None
    return _record_anomaly(
        "impossible_travel", "high", None,
        {"from_ip": prev_ip, "to_ip": current_ip,
         "from": {"country": a.get("country"), "city": a.get("city")},
         "to": {"country": b.get("country"), "city": b.get("city")},
         "distance_km": trip["km"], "hours_between": trip["hours"], "implied_kmh": trip["kmh"],
         "limit_kmh": geo.MAX_PLAUSIBLE_KMH},
        org_id, user_id, dedupe_key=f"travel:{user_id}:{prev_ip}:{current_ip}",
    )


def circular_hour_stats(hours: list[float]) -> tuple[float, float]:
    angles = [h / 24 * 2 * math.pi for h in hours]
    s = sum(math.sin(a) for a in angles) / len(angles)
    c = sum(math.cos(a) for a in angles) / len(angles)
    mean = (math.atan2(s, c) / (2 * math.pi) * 24) % 24
    r = min(max(math.hypot(s, c), 1e-9), 1.0)
    std = math.sqrt(-2 * math.log(r)) / (2 * math.pi) * 24
    return mean, max(std, 1.0)


def hour_distance(a: float, b: float) -> float:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def check_unusual_login_hour(user_id: str, org_id: str | None, login_dt: datetime) -> dict | None:
    zone = _zone(org_id)
    local = login_dt.astimezone(zone)
    hour = local.hour + local.minute / 60
    history = _login_history(user_id)[1:]
    hours = []
    for e in history:
        ts = _parse_ts(e.get("created_at"))
        if ts:
            t = ts.astimezone(zone)
            hours.append(t.hour + t.minute / 60)
    if len(hours) >= MIN_USER_LOGINS:
        mean, std = circular_hour_stats(hours)
        baseline = "user"
    else:
        mean, std = SEEDED_BASELINE["login_hour"]["mean"], SEEDED_BASELINE["login_hour"]["std"]
        baseline = "seeded"
    z = hour_distance(hour, mean) / std
    if z > _cutoff(org_id, "unusual_login_hour"):
        return _record_anomaly(
            "unusual_login_hour", "medium", None,
            {"local_hour": round(hour, 2), "timezone": str(zone), "z_score": round(z, 2),
             "mean_hour": round(mean, 2), "std_hours": round(std, 2), "baseline": baseline},
            org_id, user_id, dedupe_key=f"login_hour:{user_id}:{local.date().isoformat()}",
        )
    return None


def check_role_escalation(user_id: str, org_id: str | None, old_role: str, new_role: str) -> dict | None:
    ranks = {"operator": 1, "team_lead": 2, "org_admin": 3}
    if ranks.get(new_role, 0) > ranks.get(old_role, 0):
        return _record_anomaly(
            "role_escalation", "high", None,
            {"old_role": old_role, "new_role": new_role}, org_id, user_id,
        )
    return None


def check_verification_failure(job_id: str, org_id: str | None, user_id: str) -> dict | None:
    return _record_anomaly(
        "wipe_verification_failure", "critical", job_id,
        {"job_id": job_id, "message": "Overwrite verification read-back failed"},
        org_id, user_id, dedupe_key=f"verify_fail:{job_id}",
    )


def check_off_hours_wipe(job_id: str, org_id: str | None, user_id: str, submitted_at: datetime) -> dict | None:
    settings = org_settings(org_id)
    local = submitted_at.astimezone(_zone(org_id))
    start, end = int(settings["work_start_hour"]), int(settings["work_end_hour"])
    if local.hour < start or local.hour >= end:
        return _record_anomaly(
            "off_hours_wipe", "medium", job_id,
            {"local_hour": local.hour, "timezone": settings["timezone"],
             "working_hours": f"{start:02d}:00-{end:02d}:00", "submitted_at": submitted_at.isoformat()},
            org_id, user_id, dedupe_key=f"off_hours:{job_id}",
        )
    return None


def check_repeat_wipe(device_serial: str, org_id: str | None, user_id: str) -> dict | None:
    hours = _get_thresholds(org_id)["repeat_wipe_hours"]
    window = (_now() - timedelta(hours=hours)).isoformat()
    q = (get_service_client().table("wipe_jobs").select("id", count="exact")
         .eq("device_serial", device_serial).eq("status", "completed").gte("completed_at", window))
    q = q.eq("org_id", org_id) if org_id else q.eq("user_id", user_id)
    count = q.execute().count or 0
    if count >= 2:
        return _record_anomaly(
            "repeat_wipe", "medium", None,
            {"device_serial": device_serial, "count": count, "window_hours": hours},
            org_id, user_id, dedupe_key=f"repeat:{device_serial}:{_now().strftime('%Y%m%d')}",
        )
    return None


def check_new_operator(user_id: str, org_id: str | None, job_id: str) -> dict | None:
    r = (get_service_client().table("wipe_jobs").select("id", count="exact")
         .eq("user_id", user_id).neq("id", job_id).execute())
    if (r.count or 0) == 0:
        return _record_anomaly(
            "new_operator_first_wipe", "low", job_id,
            {"user_id": user_id, "message": "First wipe job submitted by this operator"},
            org_id, user_id, dedupe_key=f"new_operator:{user_id}",
        )
    return None


def _raw_int(raw) -> int:
    try:
        return int(str(raw).split()[0])
    except (ValueError, IndexError):
        return 0


def check_smart_anomalies(device_serial: str, smart_snapshot: dict,
                          org_id: str | None, user_id: str) -> list[dict]:
    if not smart_snapshot or not smart_snapshot.get("available"):
        return []
    t = _get_thresholds(org_id)
    found = []

    def add(kind, severity, details, key):
        found.append(_record_anomaly(kind, severity, None, {"device_serial": device_serial, **details},
                                     org_id, user_id, dedupe_key=f"smart:{device_serial}:{key}"))

    for attr in smart_snapshot.get("attributes", []):
        name = attr.get("name")
        raw = _raw_int(attr.get("raw"))
        if name == "Reallocated_Sector_Ct" and raw > t["smart_reallocated"]:
            add("smart_reallocated_sectors", "high" if raw > 10 else "medium", {"reallocated_count": raw}, "realloc")
        if name in ("Temperature_Celsius", "Airflow_Temperature_Cel") and raw > t["smart_temp"]:
            add("smart_high_temperature", "high", {"temperature": raw}, "temp")
        if name == "Power_On_Hours" and raw > t["smart_power_on_hours"]:
            add("smart_high_power_on_hours", "medium", {"power_on_hours": raw}, "poh")
        failing = "FAILING_NOW" in str(attr.get("when_failed", "")).upper()
        if failing or (attr.get("threshold", 0) > 0 and attr.get("value", 0) <= attr.get("threshold", 0)):
            add("smart_attribute_failed", "critical",
                {"attribute": name, "value": attr.get("value"), "threshold": attr.get("threshold")}, f"failed:{name}")

    nvme = smart_snapshot.get("nvme") or {}
    if nvme:
        if nvme.get("critical_warning"):
            add("smart_nvme_critical_warning", "critical", {"critical_warning": nvme["critical_warning"]}, "nvme_cw")
        spare, spare_t = nvme.get("available_spare"), nvme.get("available_spare_threshold")
        if spare is not None and spare_t is not None and spare <= spare_t:
            add("smart_nvme_spare_low", "high", {"available_spare": spare, "threshold": spare_t}, "nvme_spare")
        if (nvme.get("percentage_used") or 0) >= 100:
            add("smart_nvme_worn_out", "high", {"percentage_used": nvme["percentage_used"]}, "nvme_wear")
        if (nvme.get("media_errors") or 0) > 0:
            add("smart_nvme_media_errors", "medium", {"media_errors": nvme["media_errors"]}, "nvme_media")
        temp = nvme.get("temperature")
        if temp and temp > t["smart_temp"] + 15:
            add("smart_high_temperature", "high", {"temperature": temp}, "temp")

    if smart_snapshot.get("health") == "Failed":
        add("smart_overall_failed", "critical", {"health": "Failed"}, "overall")

    history = []
    try:
        history = smart_history(device_serial)
        record_smart_snapshot(device_serial, smart_snapshot, org_id)
    except Exception as exc:
        print(f"[ANOMALY] smart history unavailable: {exc}")
    try:
        from ml.scoring import score_smart
        for finding in score_smart(device_serial, smart_snapshot, None, history):
            found.append(record_model_anomaly(finding, org_id, user_id))
    except Exception as exc:
        print(f"[ANOMALY] drive health model skipped: {exc}")
    return found


def smart_history(serial: str, days: int = 45) -> list[dict]:
    since = (_now() - timedelta(days=days)).isoformat()
    r = (get_service_client().table("smart_history").select("captured_at,snapshot")
         .eq("serial", serial).gte("captured_at", since).order("captured_at").execute())
    return r.data or []


def record_smart_snapshot(serial: str, snapshot: dict, org_id: str | None) -> None:
    today = _now().date().isoformat()
    svc = get_service_client()
    exists = svc.table("smart_history").select("serial").eq("serial", serial).eq("captured_on", today).limit(1).execute()
    if exists.data:
        return
    keep = {k: snapshot.get(k) for k in ("model", "serial", "rotation_rate", "attributes", "nvme", "health")}
    try:
        svc.table("smart_history").insert({"serial": serial, "captured_on": today, "captured_at": _now().isoformat(),
                                           "org_id": org_id, "snapshot": keep}).execute()
    except Exception as exc:
        if "23505" not in str(exc) and "duplicate key" not in str(exc):
            raise


def seconds_per_gib_pass(job: dict) -> float | None:
    seconds = job.get("duration_seconds")
    if seconds is None:
        start, end = _parse_ts(job.get("started_at")), _parse_ts(job.get("completed_at"))
        if not start or not end:
            return None
        seconds = (end - start).total_seconds()
    gib = (job.get("device_capacity_bytes") or 0) / 2 ** 30
    passes = max(int(job.get("passes_completed") or 1), 1)
    if gib <= 0:
        return None
    return float(seconds) / gib / passes


def _completed_jobs(org_id: str | None) -> list[dict]:
    from backend.audit import fetch_all
    svc = get_service_client()

    def build():
        q = (svc.table("wipe_jobs")
             .select("id,user_id,org_id,started_at,completed_at,duration_seconds,device_capacity_bytes,"
                     "passes_completed,technique,device_type,method")
             .eq("status", "completed").order("completed_at"))
        return q.eq("org_id", org_id) if org_id else q.is_("org_id", "null")
    return fetch_all(build)


def _org_scopes() -> list[str | None]:
    from backend.audit import fetch_all
    svc = get_service_client()
    return [None] + [o["id"] for o in fetch_all(lambda: svc.table("organisations").select("id").order("id"))]


def duration_outliers(org_id: str | None) -> list[dict]:
    jobs = _completed_jobs(org_id)
    groups: dict[str, list[tuple[dict, float]]] = {}
    for j in jobs:
        technique = j.get("technique") or j.get("method") or "unknown"
        if technique.startswith(("nvme_sanitize_crypto", "nvme_format_crypto", "ata_sanitize_crypto",
                                 "scsi_sanitize_crypto", "sed_psid_revert")) and "+overwrite" not in technique:
            continue
        rate = seconds_per_gib_pass(j)
        if rate is not None and rate > 0:
            groups.setdefault(f"{j.get('device_type')}:{technique}", []).append((j, math.log(rate)))
    found = []
    cutoff = _cutoff(org_id, "statistical_wipe_duration_outlier")
    for key, rows in groups.items():
        if len(rows) < MIN_DURATION_SAMPLES:
            continue
        values = [v for _, v in rows]
        mean, std = statistics.mean(values), statistics.stdev(values) or 1e-6
        for job, v in rows[-50:]:
            z = (v - mean) / std
            if abs(z) > cutoff:
                found.append(_record_anomaly(
                    "statistical_wipe_duration_outlier", "high" if z < 0 else "medium", job["id"],
                    {"group": key, "seconds_per_gib_pass": round(math.exp(v), 3), "z_score": round(z, 2),
                     "group_median": round(math.exp(statistics.median(values)), 3),
                     "direction": "too_fast" if z < 0 else "too_slow"},
                    org_id, job.get("user_id"), dedupe_key=f"duration:{job['id']}",
                ))
    return found


def run_statistical_batch(org_id: str | None = None) -> list[dict]:
    scopes = [org_id] if org_id else _org_scopes()
    found = []
    for scope in scopes:
        try:
            found.extend(duration_outliers(scope))
        except Exception as exc:
            print(f"[ANOMALY] batch failed for {scope or 'individuals'}: {exc}")
    return found


def score_completed_job(job: dict, record: dict) -> list[dict]:
    try:
        from ml.scoring import score_job
    except Exception as exc:
        print(f"[ANOMALY] ml scoring unavailable: {exc}")
        return []
    return [record_model_anomaly(f, job.get("org_id"), job.get("user_id")) for f in score_job(job, record)]


def score_login(user_id: str, org_id: str | None, ip: str, at: datetime) -> list[dict]:
    try:
        from ml.scoring import score_login as model_score
    except Exception as exc:
        print(f"[ANOMALY] ml scoring unavailable: {exc}")
        return []
    return [record_model_anomaly(f, org_id, user_id) for f in model_score(user_id, org_id, ip, at)]


def compute_risk_score(org_id: str | None, user_id: str | None = None) -> dict:
    q = get_service_client().table("anomalies").select("severity").eq("status", "open")
    if org_id:
        q = q.eq("org_id", org_id)
    elif user_id:
        q = q.eq("user_id", user_id)
    open_anomalies = q.execute().data or []
    score = min(100, sum(SEVERITY_WEIGHTS.get(a["severity"], 1) for a in open_anomalies))
    if score >= 60:
        level, colour = "critical", "#c44a42"
    elif score >= 30:
        level, colour = "high", "#c4901a"
    elif score >= 10:
        level, colour = "medium", "#c4b48a"
    else:
        level, colour = "low", "#4a5442"
    return {"score": score, "level": level, "colour": colour, "open_count": len(open_anomalies)}


def acknowledge_anomaly(anomaly_id: str, user_id: str, note: str | None,
                        resolved: bool, feedback: str | None = None) -> dict:
    update = {
        "status": "resolved" if resolved else "acknowledged",
        "acknowledged_by": user_id,
        "acknowledged_at": _now().isoformat(),
    }
    if note:
        update["resolution_note"] = note
    if resolved:
        update["resolved_at"] = _now().isoformat()
    if feedback in ("true_positive", "false_positive"):
        update["feedback"] = feedback
        update["feedback_by"] = user_id
        update["feedback_at"] = _now().isoformat()
    r = get_service_client().table("anomalies").update(update).eq("id", anomaly_id).execute()
    return r.data[0] if r.data else {}
