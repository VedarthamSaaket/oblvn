import json
import time
from collections import defaultdict

from ml.paths import MODELS_DIR, scope_name

MIN_LABELS = 10
FILE = "calibration.json"
_cache: dict[str, tuple[float, dict]] = {}


def calibrate(org_id: str | None, labelled: list[dict]) -> dict:
    counts: dict[str, dict] = defaultdict(lambda: {"true_positive": 0, "false_positive": 0})
    for row in labelled:
        if row.get("feedback") in ("true_positive", "false_positive"):
            counts[row["anomaly_type"]][row["feedback"]] += 1
    table = {}
    for anomaly_type, c in counts.items():
        total = c["true_positive"] + c["false_positive"]
        precision = c["true_positive"] / total if total else None
        table[anomaly_type] = {**c, "labels": total, "precision": precision, "multiplier": multiplier(precision, total)}
    folder = MODELS_DIR / scope_name(org_id)
    folder.mkdir(parents=True, exist_ok=True)
    out = {"scope": scope_name(org_id), "min_labels": MIN_LABELS, "types": table}
    (folder / FILE).write_text(json.dumps(out, indent=2))
    _cache.pop(scope_name(org_id), None)
    return out


def multiplier(precision: float | None, labels: int) -> float:
    if precision is None or labels < MIN_LABELS:
        return 1.0
    if precision < 0.5:
        return round(min(1.5, 1.0 + (0.5 - precision)), 3)
    if precision > 0.9:
        return 0.9
    return 1.0


def _table(org_id: str | None) -> dict:
    scope = scope_name(org_id)
    cached = _cache.get(scope)
    if cached and time.monotonic() - cached[0] < 300:
        return cached[1]
    path = MODELS_DIR / scope / FILE
    data = json.loads(path.read_text()).get("types", {}) if path.exists() else {}
    _cache[scope] = (time.monotonic(), data)
    return data


def cutoff_multiplier(org_id: str | None, anomaly_type: str) -> float:
    return float(_table(org_id).get(anomaly_type, {}).get("multiplier", 1.0))
