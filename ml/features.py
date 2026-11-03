import math
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEVICE_TYPES = ["hdd", "ssd", "nvme", "usb_flash", "file"]
METHODS = ["binary_overwrite", "crypto_erase", "full_sanitization"]
TRANSPORTS = ["nvme", "sata", "sas", "usb", "unknown"]
FAMILIES = ["overwrite", "firmware_crypto", "firmware_block", "firmware_overwrite",
            "firmware_secure_erase", "firmware_plus_overwrite", "file_overwrite", "free_space_fill", "other"]

DURATION_FEATURES = (
    ["log2_gib", "overwrite_passes"]
    + [f"type_{d}" for d in DEVICE_TYPES]
    + [f"family_{f}" for f in FAMILIES]
    + [f"transport_{t}" for t in TRANSPORTS]
)

JOB_BEHAVIOUR_FEATURES = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "log2_gib", "tenure_log_days",
    "jobs_last_1h", "jobs_last_24h", "cancel_rate_30d", "is_file",
] + [f"method_{m}" for m in METHODS] + [f"type_{d}" for d in DEVICE_TYPES]

LOGIN_FEATURES = [
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "new_ip", "new_subnet",
    "distinct_ips_30d", "failed_before_15m", "log_hours_since_last",
]

SMART_IDS = [1, 3, 4, 5, 7, 9, 10, 12, 187, 188, 189, 190, 192, 193, 194, 196, 197, 198, 199, 240, 241, 242]
SMART_FEATURES = [f"smart_{i}_raw" for i in SMART_IDS] + ["log2_capacity_gib"]


def ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def cyclical(value: float, period: float) -> tuple[float, float]:
    angle = 2 * math.pi * value / period
    return math.sin(angle), math.cos(angle)


def log2_gib(capacity_bytes) -> float:
    gib = (capacity_bytes or 0) / 2 ** 30
    return math.log2(gib) if gib > 0 else -10.0


def technique_family(technique: str | None, device_type: str | None = None) -> str:
    t = technique or ""
    if "+overwrite" in t:
        return "firmware_plus_overwrite"
    if t == "overwrite":
        return "overwrite"
    if t == "file_overwrite" or device_type == "file":
        return "file_overwrite"
    if t == "free_space_fill":
        return "free_space_fill"
    if "secure_erase" in t:
        return "firmware_secure_erase"
    if t.endswith("_crypto") or t == "sed_psid_revert":
        return "firmware_crypto"
    if t.endswith("_block"):
        return "firmware_block"
    if t.endswith("_overwrite"):
        return "firmware_overwrite"
    return "other"


def _onehot(prefix: str, value: str, options: list[str]) -> dict:
    return {f"{prefix}_{o}": 1.0 if value == o else 0.0 for o in options}


def duration_row(job: dict) -> dict | None:
    record = job.get("wipe_record") or {}
    tel = record.get("telemetry") or {}
    seconds = tel.get("total_seconds") or job.get("duration_seconds")
    if not seconds or float(seconds) <= 0:
        return None
    device = record.get("device") or {}
    transport = device.get("transport") or "unknown"
    row = {
        "log2_gib": log2_gib(tel.get("size_bytes") or job.get("device_capacity_bytes")),
        "overwrite_passes": float(tel.get("overwrite_passes") or 0),
        **_onehot("type", job.get("device_type") or "", DEVICE_TYPES),
        **_onehot("family", technique_family(job.get("technique") or record.get("technique"), job.get("device_type")), FAMILIES),
        **_onehot("transport", transport if transport in TRANSPORTS else "unknown", TRANSPORTS),
    }
    row["target"] = math.log1p(float(seconds))
    return row


def job_behaviour_row(job: dict, history: list[dict], first_at: str | None, tz: str) -> dict:
    created = ts(job.get("created_at")) or datetime.now().astimezone()
    local = created.astimezone(zone(tz))
    hs, hc = cyclical(local.hour + local.minute / 60, 24)
    ds, dc = cyclical(local.weekday(), 7)
    prior = [h for h in history if (ts(h["created_at"]) or created) < created]
    last_1h = sum(1 for h in prior if created - ts(h["created_at"]) <= timedelta(hours=1))
    last_24h = sum(1 for h in prior if created - ts(h["created_at"]) <= timedelta(hours=24))
    recent = [h for h in prior if created - ts(h["created_at"]) <= timedelta(days=30)]
    cancel_rate = sum(1 for h in recent if h.get("status") == "cancelled") / len(recent) if recent else 0.0
    first = ts(first_at) or created
    tenure = max((created - first).total_seconds() / 86400, 0.0)
    return {
        "hour_sin": hs, "hour_cos": hc, "dow_sin": ds, "dow_cos": dc,
        "log2_gib": log2_gib(job.get("device_capacity_bytes")),
        "tenure_log_days": math.log1p(tenure),
        "jobs_last_1h": float(last_1h),
        "jobs_last_24h": float(last_24h),
        "cancel_rate_30d": cancel_rate,
        "is_file": 1.0 if job.get("device_type") == "file" else 0.0,
        **_onehot("method", job.get("method") or "", METHODS),
        **_onehot("type", job.get("device_type") or "", DEVICE_TYPES),
    }


def _subnet(ip: str | None) -> str | None:
    if not ip:
        return None
    if ":" in ip:
        return ":".join(ip.split(":")[:4])
    return ".".join(ip.split(".")[:3])


def login_row(at: datetime, ip: str | None, prior: list[dict], failed_before: int, tz: str) -> dict:
    local = at.astimezone(zone(tz))
    hs, hc = cyclical(local.hour + local.minute / 60, 24)
    ds, dc = cyclical(local.weekday(), 7)
    ips = [p["event_payload"].get("ip_address") for p in prior]
    month = [p["event_payload"].get("ip_address") for p in prior
             if (ts(p["created_at"]) and at - ts(p["created_at"]) <= timedelta(days=30))]
    last = max((ts(p["created_at"]) for p in prior if ts(p["created_at"])), default=None)
    hours_since = (at - last).total_seconds() / 3600 if last else 24 * 30
    return {
        "hour_sin": hs, "hour_cos": hc, "dow_sin": ds, "dow_cos": dc,
        "new_ip": 0.0 if not prior or ip in ips else 1.0,
        "new_subnet": 0.0 if not prior or _subnet(ip) in {_subnet(i) for i in ips} else 1.0,
        "distinct_ips_30d": float(len(set(filter(None, month)))),
        "failed_before_15m": float(failed_before),
        "log_hours_since_last": math.log1p(max(hours_since, 0.0)),
    }


def smart_row(snapshot: dict, capacity_bytes: int | None = None) -> dict:
    raw = {}
    for a in snapshot.get("attributes") or []:
        try:
            raw[int(a["id"])] = float(str(a.get("raw", "")).split()[0])
        except (ValueError, IndexError, KeyError, TypeError):
            continue
    row = {f"smart_{i}_raw": raw.get(i, math.nan) for i in SMART_IDS}
    row["log2_capacity_gib"] = log2_gib(capacity_bytes) if capacity_bytes else math.nan
    return row


def vector(row: dict, names: list[str]) -> list[float]:
    return [float(row.get(n, math.nan)) for n in names]
