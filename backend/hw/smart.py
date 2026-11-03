from backend.hw.runner import ToolError, have, run

UNAVAILABLE = {"available": False, "health": "Unknown", "attributes": []}


def _attr(row: dict) -> dict:
    raw = row.get("raw") or {}
    flags = row.get("flags") or {}
    return {
        "id": int(row.get("id", 0)),
        "name": row.get("name", ""),
        "value": int(row.get("value") or 0),
        "worst": int(row.get("worst") or 0),
        "threshold": int(row.get("thresh") or 0),
        "raw": str(raw.get("value", raw.get("string", "0"))),
        "flags": flags.get("string", ""),
        "when_failed": row.get("when_failed", ""),
    }


def normalize(data: dict) -> dict:
    if not data or "smart_status" not in data and "ata_smart_attributes" not in data \
            and "nvme_smart_health_information_log" not in data:
        return dict(UNAVAILABLE)
    status = data.get("smart_status") or {}
    passed = status.get("passed")
    snapshot = {
        "available": True,
        "health": "Passed" if passed else "Failed" if passed is False else "Unknown",
        "serial": data.get("serial_number"),
        "model": data.get("model_name"),
        "firmware": data.get("firmware_version"),
        "temperature": (data.get("temperature") or {}).get("current"),
        "power_on_hours": (data.get("power_on_time") or {}).get("hours"),
        "rotation_rate": data.get("rotation_rate"),
        "attributes": [_attr(r) for r in (data.get("ata_smart_attributes") or {}).get("table", [])],
    }
    nvme = data.get("nvme_smart_health_information_log")
    if nvme:
        snapshot["nvme"] = {
            "critical_warning": nvme.get("critical_warning", 0),
            "available_spare": nvme.get("available_spare"),
            "available_spare_threshold": nvme.get("available_spare_threshold"),
            "percentage_used": nvme.get("percentage_used"),
            "media_errors": nvme.get("media_errors", 0),
            "num_err_log_entries": nvme.get("num_err_log_entries", 0),
            "unsafe_shutdowns": nvme.get("unsafe_shutdowns", 0),
            "power_on_hours": nvme.get("power_on_hours"),
            "temperature": nvme.get("temperature"),
        }
    return snapshot


def snapshot(node: str) -> dict:
    if not have("smartctl"):
        return dict(UNAVAILABLE)
    try:
        r = run(["smartctl", "-j", "-a", node], timeout=30)
    except ToolError:
        return dict(UNAVAILABLE)
    return normalize(r.json())
