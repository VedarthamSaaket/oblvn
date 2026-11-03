import math

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score

from ml import registry
from ml.features import SMART_FEATURES, smart_row, vector
from ml.paths import GLOBAL, PROCESSED_DIR

NAME = "drive_health"
DATASET = PROCESSED_DIR / "drive_health.parquet"
PARAMS = dict(max_iter=300, learning_rate=0.05, max_leaf_nodes=31, l2_regularization=1.0,
              class_weight="balanced", random_state=42)
HIGH = 0.5
MEDIUM = 0.2


def _metrics(y: np.ndarray, p: np.ndarray) -> dict:
    pred = p >= HIGH
    return {
        "rows": int(len(y)),
        "positives": int(y.sum()),
        "base_rate": float(y.mean()) if len(y) else None,
        "average_precision": float(average_precision_score(y, p)) if y.any() else None,
        "roc_auc": float(roc_auc_score(y, p)) if 0 < y.sum() < len(y) else None,
        "precision_at_0_5": float(precision_score(y, pred, zero_division=0)),
        "recall_at_0_5": float(recall_score(y, pred, zero_division=0)),
    }


def train(path=DATASET, test_fraction: float = 0.2) -> dict:
    df = pd.read_parquet(path)
    df = df.sort_values("date")
    cutoff = df["date"].quantile(1 - test_fraction)
    train_df, test_df = df[df["date"] < cutoff], df[df["date"] >= cutoff]
    X_train, y_train = train_df[SMART_FEATURES].to_numpy(float), train_df["label"].to_numpy(int)
    X_test, y_test = test_df[SMART_FEATURES].to_numpy(float), test_df["label"].to_numpy(int)
    model = HistGradientBoostingClassifier(**PARAMS)
    model.fit(X_train, y_train)
    holdout = _metrics(y_test, model.predict_proba(X_test)[:, 1])
    shared = set(train_df["serial_number"]) & set(test_df["serial_number"])
    unseen = test_df[~test_df["serial_number"].isin(shared)]
    unseen_metrics = _metrics(unseen["label"].to_numpy(int),
                              model.predict_proba(unseen[SMART_FEATURES].to_numpy(float))[:, 1]) if len(unseen) else None
    model.fit(df[SMART_FEATURES].to_numpy(float), df["label"].to_numpy(int))
    meta = {
        "dataset": str(path),
        "rows": int(len(df)),
        "drives": int(df["serial_number"].nunique()),
        "date_range": [str(df["date"].min()), str(df["date"].max())],
        "label": "drive fails within the next 30 days",
        "sampling": "all rows within 30 days before a failure, a random share of rows from drives that never failed, "
                    "and no negative rows from the last 30 days (their future is unknown)",
        "features": SMART_FEATURES,
        "params": PARAMS,
        "split": {"type": "time", "test_from": str(cutoff), "test_fraction": test_fraction},
        "holdout": holdout,
        "holdout_unseen_drives": unseen_metrics,
        "thresholds": {"high": HIGH, "medium": MEDIUM},
    }
    return registry.save(GLOBAL, NAME, model, meta)


def is_hard_drive(snapshot: dict) -> bool:
    if snapshot.get("nvme"):
        return False
    rate = snapshot.get("rotation_rate")
    if rate == 0 or (isinstance(rate, str) and "solid" in rate.lower()):
        return False
    return True


def score(serial: str, snapshot: dict, capacity_bytes: int | None = None) -> list[dict]:
    if not snapshot or not snapshot.get("attributes") or not is_hard_drive(snapshot):
        return []
    bundle = registry.load(GLOBAL, NAME)
    if not bundle:
        return []
    row = smart_row(snapshot, capacity_bytes)
    known = sum(1 for k, v in row.items() if k.startswith("smart_") and not math.isnan(v))
    if known < 4:
        return []
    p = float(bundle["model"].predict_proba(np.array([vector(row, SMART_FEATURES)]))[0, 1])
    if p < MEDIUM:
        return []
    return [{
        "anomaly_type": "ml_drive_failure_risk",
        "severity": "high" if p >= HIGH else "medium",
        "detector": "drive_health_model",
        "score": round(p, 4),
        "dedupe_key": f"smart:{serial}:health_model",
        "details": {
            "device_serial": serial,
            "risk_score": round(p, 4),
            "message": "drive shows SMART patterns seen in the 30 days before real failures; a firmware wipe "
                       "may not complete, consider physical destruction",
            "score_note": "relative risk score from a model trained on 1 percent of healthy rows, not a calibrated probability",
            "model_trained_at": bundle["meta"]["trained_at"],
            "model_holdout_average_precision": (bundle["meta"].get("holdout") or {}).get("average_precision"),
        },
    }]
