from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from ml import registry
from ml.explain import robust_stats, top_contributors
from ml.features import (JOB_BEHAVIOUR_FEATURES, LOGIN_FEATURES, job_behaviour_row, login_row, ts, vector)

JOBS = "behaviour_jobs"
LOGINS = "behaviour_logins"
MIN_SAMPLES = 50
BASE_PERCENTILE = 1.0
SEVERE_PERCENTILE = 0.1
PARAMS = dict(n_estimators=200, contamination="auto", random_state=42)


def _fit(X: np.ndarray, names: list[str], scope: str, name: str, extra: dict) -> dict | None:
    if len(X) < MIN_SAMPLES:
        return None
    model = IsolationForest(max_samples=min(256, len(X)), **PARAMS)
    model.fit(X)
    scores = model.score_samples(X)
    meta = {
        "samples": int(len(X)),
        "features": names,
        "params": {**PARAMS, "max_samples": min(256, len(X))},
        "score_percentiles": {str(p): float(np.percentile(scores, p)) for p in (0.1, 0.5, 1, 2, 5, 10)},
        "stats": robust_stats(X),
        **extra,
    }
    return registry.save(scope, name, model, meta)


def job_matrix(jobs: list[dict], tz: str) -> np.ndarray:
    by_user: dict[str, list[dict]] = defaultdict(list)
    for j in jobs:
        by_user[j["user_id"]].append(j)
    rows = []
    for user_jobs in by_user.values():
        user_jobs.sort(key=lambda j: j["created_at"])
        first = user_jobs[0]["created_at"]
        for j in user_jobs:
            rows.append(vector(job_behaviour_row(j, user_jobs, first, tz), JOB_BEHAVIOUR_FEATURES))
    return np.array(rows) if rows else np.empty((0, len(JOB_BEHAVIOUR_FEATURES)))


def login_matrix(events: list[dict], tz: str) -> np.ndarray:
    failures = [(ts(e["created_at"]), e["event_payload"].get("email")) for e in events if e["event_type"] == "login_failed"]
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "login_success" and e.get("user_id"):
            by_user[e["user_id"]].append(e)
    rows = []
    for logins in by_user.values():
        logins.sort(key=lambda e: e["created_at"])
        for i, e in enumerate(logins):
            at = ts(e["created_at"])
            if not at:
                continue
            email = e["event_payload"].get("email")
            failed = sum(1 for t, em in failures if t and em == email and timedelta(0) <= at - t <= timedelta(minutes=15))
            rows.append(vector(login_row(at, e["event_payload"].get("ip_address"), logins[:i], failed, tz), LOGIN_FEATURES))
    return np.array(rows) if rows else np.empty((0, len(LOGIN_FEATURES)))


def train(jobs: list[dict], logins: list[dict], scope: str, tz: str) -> dict:
    return {
        JOBS: _fit(job_matrix(jobs, tz), JOB_BEHAVIOUR_FEATURES, scope, JOBS, {"timezone": tz}),
        LOGINS: _fit(login_matrix(logins, tz), LOGIN_FEATURES, scope, LOGINS, {"timezone": tz}),
    }


def _threshold(meta: dict, percentile: float) -> float:
    table = {float(k): v for k, v in meta["score_percentiles"].items()}
    nearest = min(table, key=lambda p: abs(p - percentile))
    return table[nearest]


def _score(scope: str, name: str, row: dict, names: list[str], multiplier: float) -> tuple[float, dict, list] | None:
    bundle = registry.load(scope, name)
    if not bundle:
        return None
    x = np.array(vector(row, names))
    s = float(bundle["model"].score_samples(x.reshape(1, -1))[0])
    meta = bundle["meta"]
    if s >= _threshold(meta, BASE_PERCENTILE / max(multiplier, 0.1)):
        return None
    severity = "high" if s < _threshold(meta, SEVERE_PERCENTILE) else "medium"
    return s, {"severity": severity, "trained_at": meta["trained_at"], "samples": meta["samples"]}, \
        top_contributors(x, meta["stats"], names)


def score_job(job: dict, history: list[dict], first_at: str | None, tz: str, scope: str,
              multiplier: float = 1.0) -> list[dict]:
    row = job_behaviour_row(job, history, first_at, tz)
    hit = _score(scope, JOBS, row, JOB_BEHAVIOUR_FEATURES, multiplier)
    if not hit:
        return []
    s, info, reasons = hit
    return [{
        "anomaly_type": "ml_unusual_job_behaviour", "severity": info["severity"], "detector": "isolation_forest",
        "score": round(s, 4), "source_event_id": job["id"], "dedupe_key": f"ml_job:{job['id']}",
        "details": {"isolation_score": round(s, 4), "top_reasons": reasons, "model_samples": info["samples"],
                    "model_trained_at": info["trained_at"]},
    }]


def score_login(user_id: str, at: datetime, ip: str | None, prior: list[dict], failed_before: int,
                tz: str, scope: str, multiplier: float = 1.0) -> list[dict]:
    row = login_row(at, ip, prior, failed_before, tz)
    hit = _score(scope, LOGINS, row, LOGIN_FEATURES, multiplier)
    if not hit:
        return []
    s, info, reasons = hit
    return [{
        "anomaly_type": "ml_unusual_login", "severity": info["severity"], "detector": "isolation_forest",
        "score": round(s, 4), "dedupe_key": f"ml_login:{user_id}:{at.strftime('%Y%m%d%H')}",
        "details": {"isolation_score": round(s, 4), "ip_address": ip, "top_reasons": reasons,
                    "model_samples": info["samples"], "model_trained_at": info["trained_at"]},
    }]
