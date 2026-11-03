import math

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_absolute_error

from ml import registry
from ml.features import DURATION_FEATURES, duration_row, technique_family, vector

NAME = "wipe_duration"
MIN_SAMPLES = 50
QUANTILES = (0.05, 0.5, 0.95)
BASE_MARGIN = 0.15
CEILING_MBPS = {"usb": 1250, "sata": 650, "sas": 1300, "nvme": 16000, "unknown": 16000}
PARAMS = dict(n_estimators=300, max_depth=3, learning_rate=0.05, subsample=0.8, min_samples_leaf=5, random_state=42)


def dataset(jobs: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    rows = [r for r in (duration_row(j) for j in jobs if j.get("status") == "completed") if r]
    if not rows:
        return np.empty((0, len(DURATION_FEATURES))), np.empty(0)
    return np.array([vector(r, DURATION_FEATURES) for r in rows]), np.array([r["target"] for r in rows])


def train(jobs: list[dict], scope: str) -> dict | None:
    X, y = dataset(jobs)
    if len(y) < MIN_SAMPLES:
        return None
    order = np.arange(len(y))
    split = int(len(y) * 0.8)
    train_idx, test_idx = order[:split], order[split:]
    models = {}
    for q in QUANTILES:
        m = GradientBoostingRegressor(loss="quantile", alpha=q, **PARAMS)
        m.fit(X[train_idx], y[train_idx])
        models[q] = m
    lo, mid, hi = (models[q].predict(X[test_idx]) for q in QUANTILES)
    coverage = float(np.mean((y[test_idx] >= lo) & (y[test_idx] <= hi))) if len(test_idx) else None
    mae = float(mean_absolute_error(y[test_idx], mid)) if len(test_idx) else None
    incumbent = None
    current = registry.load(scope, NAME)
    if current and current["meta"].get("features") == DURATION_FEATURES and len(test_idx):
        incumbent = float(mean_absolute_error(y[test_idx], current["model"][0.5].predict(X[test_idx])))
    for q in QUANTILES:
        models[q].fit(X, y)
    meta = {
        "samples": int(len(y)),
        "features": DURATION_FEATURES,
        "quantiles": list(QUANTILES),
        "params": PARAMS,
        "holdout": {"size": int(len(test_idx)), "interval_coverage_90": coverage, "median_mae_log_seconds": mae},
    }
    return registry.promote(scope, NAME, models, meta, mae, incumbent, "holdout median MAE (log seconds)",
                            higher_is_better=False, tolerance=0.02)


def physics_findings(job: dict, record: dict) -> list[dict]:
    tel = record.get("telemetry") or {}
    device = record.get("device") or {}
    family = technique_family(record.get("technique"), job.get("device_type"))
    found = []
    if family not in ("overwrite", "firmware_plus_overwrite") or job.get("device_type") == "file":
        return found
    transport = device.get("transport") or "unknown"
    mbps = tel.get("throughput_mbps")
    ceiling = CEILING_MBPS.get(transport, CEILING_MBPS["unknown"])
    if mbps and mbps > ceiling * 1.2:
        found.append({
            "anomaly_type": "impossible_wipe_throughput", "severity": "critical", "detector": "physics",
            "source_event_id": job["id"], "dedupe_key": f"throughput:{job['id']}",
            "details": {"throughput_mbps": mbps, "interface_ceiling_mbps": ceiling, "transport": transport,
                        "message": "overwrite finished faster than the interface can carry data"},
        })
    expected = (tel.get("size_bytes") or 0) * (tel.get("overwrite_passes") or 0)
    written = tel.get("bytes_written") or 0
    if expected and written < expected * 0.99:
        found.append({
            "anomaly_type": "incomplete_wipe_write", "severity": "critical", "detector": "physics",
            "source_event_id": job["id"], "dedupe_key": f"incomplete:{job['id']}",
            "details": {"bytes_written": written, "bytes_expected": expected},
        })
    return found


def score(job: dict, record: dict, scope: str, margin_multiplier: float = 1.0) -> list[dict]:
    found = physics_findings(job, record)
    bundle = registry.load_scoped(scope, NAME)
    row = duration_row({**job, "wipe_record": record})
    if not bundle or not row:
        return found
    x = np.array([vector(row, DURATION_FEATURES)])
    models = bundle["model"]
    lo, mid, hi = (float(models[q].predict(x)[0]) for q in QUANTILES)
    observed = row["target"]
    margin = BASE_MARGIN * margin_multiplier
    seconds = math.expm1(observed)
    details = {
        "observed_seconds": round(seconds, 2),
        "expected_seconds_p50": round(math.expm1(mid), 2),
        "expected_seconds_p05": round(math.expm1(lo), 2),
        "expected_seconds_p95": round(math.expm1(hi), 2),
        "model_scope": bundle["meta"]["scope"],
        "model_trained_at": bundle["meta"]["trained_at"],
    }
    if observed < lo - margin:
        found.append({
            "anomaly_type": "ml_wipe_too_fast", "severity": "high", "detector": "wipe_duration_model",
            "score": round(lo - observed, 4), "source_event_id": job["id"], "dedupe_key": f"ml_fast:{job['id']}",
            "details": {**details, "message": "wipe finished well below the expected time for this drive and method"},
        })
    elif observed > hi + margin:
        found.append({
            "anomaly_type": "ml_wipe_too_slow", "severity": "medium", "detector": "wipe_duration_model",
            "score": round(observed - hi, 4), "source_event_id": job["id"], "dedupe_key": f"ml_slow:{job['id']}",
            "details": {**details, "message": "wipe took far longer than expected; the drive may be failing"},
        })
    return found
