import json
import math
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

from ml import registry
from ml.features import MAKERS, SMART_FEATURES, smart_row, vector
from ml.paths import GLOBAL, PROCESSED_DIR

NAME = "drive_health"
DATASET = PROCESSED_DIR / "drive_health.parquet"
PARAMS = dict(max_iter=400, learning_rate=0.05, max_leaf_nodes=31, l2_regularization=1.0,
              min_samples_leaf=40, early_stopping=False, random_state=42)
HIGH = 0.30
MEDIUM = 0.10
THRESHOLDS = (0.02, 0.05, 0.10, 0.20, 0.30, 0.50)


class CalibratedDriveModel:
    def __init__(self, base, iso, features):
        self.base = base
        self.iso = iso
        self.features = features

    def raw(self, X: np.ndarray) -> np.ndarray:
        return self.base.predict_proba(X)[:, 1]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        p = self.iso.predict(self.raw(X))
        return np.column_stack([1 - p, p])


def _ece(y: np.ndarray, p: np.ndarray, w: np.ndarray, bins: int = 10) -> float:
    edges = np.quantile(p, np.linspace(0, 1, bins + 1))
    idx = np.clip(np.searchsorted(edges, p, side="right") - 1, 0, bins - 1)
    total = w.sum()
    err = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            err += w[m].sum() / total * abs(np.average(y[m], weights=w[m]) - np.average(p[m], weights=w[m]))
    return float(err)


def _at(y: np.ndarray, p: np.ndarray, w: np.ndarray, t: float) -> dict:
    flag = p >= t
    tp = float(w[flag & (y == 1)].sum())
    fp = float(w[flag & (y == 0)].sum())
    pos = float(w[y == 1].sum())
    return {
        "threshold": t,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / pos, 4) if pos else None,
        "flagged_per_10k_drive_days": round((tp + fp) / w.sum() * 10000, 2),
    }


def metrics(y: np.ndarray, p: np.ndarray, w: np.ndarray) -> dict:
    out = {
        "rows": int(len(y)),
        "positives": int(y.sum()),
        "represented_drive_days": int(round(w.sum())),
        "true_base_rate": round(float(np.average(y, weights=w)), 6),
    }
    if 0 < y.sum() < len(y):
        out.update({
            "average_precision": round(float(average_precision_score(y, p, sample_weight=w)), 4),
            "roc_auc": round(float(roc_auc_score(y, p, sample_weight=w)), 4),
            "brier": round(float(brier_score_loss(y, p, sample_weight=w)), 6),
            "ece": round(_ece(y, p, w), 6),
            "at_thresholds": [_at(y, p, w, t) for t in THRESHOLDS],
        })
    return out


def calibration_table(y: np.ndarray, p: np.ndarray, w: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.unique(np.quantile(p, np.linspace(0, 1, bins + 1)))
    idx = np.clip(np.searchsorted(edges, p, side="right") - 1, 0, len(edges) - 2)
    rows = []
    for b in range(len(edges) - 1):
        m = idx == b
        if m.any():
            rows.append({"predicted": round(float(np.average(p[m], weights=w[m])), 5),
                         "observed": round(float(np.average(y[m], weights=w[m])), 5),
                         "rows": int(m.sum())})
    return rows


def splits(df: pd.DataFrame, calib_days: int = 90, test_days: int = 61, censor: pd.Timestamp | None = None) -> dict:
    meta_path = DATASET.with_suffix(".meta.json")
    if censor is None:
        if meta_path.exists() and pd.Timestamp(json.loads(meta_path.read_text())["censor_from"]) <= df["date"].max():
            censor = pd.Timestamp(json.loads(meta_path.read_text())["censor_from"])
        else:
            censor = df["date"].max()
    test_start = censor - pd.Timedelta(days=test_days - 1)
    calib_start = test_start - pd.Timedelta(days=calib_days)
    return {
        "train": df["date"] < calib_start,
        "calibration": (df["date"] >= calib_start) & (df["date"] < test_start),
        "test": (df["date"] >= test_start) & (df["date"] <= censor),
        "bounds": {"train_until": str(calib_start.date()), "calibration": [str(calib_start.date()), str(test_start.date())],
                   "test": [str(test_start.date()), str(censor.date())]},
    }


def fit(df: pd.DataFrame, features: list[str], parts: dict) -> tuple[CalibratedDriveModel, dict]:
    started = time.monotonic()
    tr, ca = df[parts["train"]], df[parts["calibration"]]
    base = HistGradientBoostingClassifier(**PARAMS)
    base.fit(tr[features].to_numpy(float), tr["label"].to_numpy(int), sample_weight=tr["weight"].to_numpy(float))
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(base.predict_proba(ca[features].to_numpy(float))[:, 1], ca["label"].to_numpy(int),
            sample_weight=ca["weight"].to_numpy(float))
    return CalibratedDriveModel(base, iso, features), {"fit_seconds": round(time.monotonic() - started, 1)}


def evaluate(model: CalibratedDriveModel, df: pd.DataFrame, mask) -> dict:
    te = df[mask]
    X = te[model.features].to_numpy(float)
    y, w = te["label"].to_numpy(int), te["weight"].to_numpy(float)
    p = model.predict_proba(X)[:, 1]
    raw = model.raw(X)
    out = {"calibrated": metrics(y, p, w),
           "uncalibrated_brier": round(float(brier_score_loss(y, raw, sample_weight=w)), 6),
           "calibration_table": calibration_table(y, p, w), "by_maker": {}}
    for m in MAKERS:
        sel = (te["maker"] == m).to_numpy()
        if sel.sum() and 0 < y[sel].sum() < sel.sum():
            out["by_maker"][m] = metrics(y[sel], p[sel], w[sel])
    return out


def load_dataset(path=DATASET, features: list[str] | None = None) -> pd.DataFrame:
    df = pd.read_parquet(path).sort_values("date")
    if "weight" not in df:
        df["weight"] = 1.0
    if "maker" not in df:
        df["maker"] = "other"
    for f in features or SMART_FEATURES:
        if f not in df:
            df[f] = np.nan
    return df


def train(path=DATASET, features: list[str] | None = None, name: str = NAME, guard: bool = True,
          df: pd.DataFrame | None = None) -> dict:
    features = features or SMART_FEATURES
    df = df if df is not None else load_dataset(path, features)
    parts = splits(df)
    model, info = fit(df, features, parts)
    result = evaluate(model, df, parts["test"])
    meta = {
        "dataset": str(path),
        "rows": int(len(df)),
        "drives": int(df["serial_number"].nunique()),
        "date_range": [str(df["date"].min().date()), str(df["date"].max().date())],
        "label": "drive fails within the next 30 days",
        "sampling": "all rows within 30 days before a failure, a random share of rows from drives that never failed "
                    "weighted back to their real count, and no negative rows from the last 30 days",
        "features": features,
        "params": PARAMS,
        "calibration": "isotonic regression fitted on the calibration window, sample weighted",
        "split": {**parts["bounds"], "rows": {k: int(parts[k].sum()) for k in ("train", "calibration", "test")}},
        "holdout": result["calibrated"],
        "uncalibrated_brier": result["uncalibrated_brier"],
        "calibration_table": result["calibration_table"],
        "by_maker": result["by_maker"],
        "thresholds": {"high": HIGH, "medium": MEDIUM},
        **info,
    }
    if not guard:
        return {**meta, "model": model}
    incumbent = None
    current = registry.load(GLOBAL, name)
    if current and getattr(current["model"], "features", None) == features:
        incumbent = evaluate(current["model"], df, parts["test"])["calibrated"].get("average_precision")
    return registry.promote(GLOBAL, name, model, meta, meta["holdout"].get("average_precision"), incumbent,
                            "holdout weighted average precision", higher_is_better=True, tolerance=0.01)


def is_hard_drive(snapshot: dict) -> bool:
    if snapshot.get("nvme"):
        return False
    rate = snapshot.get("rotation_rate")
    if rate == 0 or (isinstance(rate, str) and "solid" in rate.lower()):
        return False
    return True


def score(serial: str, snapshot: dict, capacity_bytes: int | None = None,
          history: list[dict] | None = None) -> list[dict]:
    if not snapshot or not snapshot.get("attributes") or not is_hard_drive(snapshot):
        return []
    bundle = registry.load(GLOBAL, NAME)
    if not bundle:
        return []
    model = bundle["model"]
    features = getattr(model, "features", None) or bundle["meta"].get("features") or SMART_FEATURES
    row = smart_row(snapshot, capacity_bytes, history)
    known = sum(1 for k, v in row.items() if k.endswith("_raw") and not math.isnan(v))
    if known < 4:
        return []
    p = float(model.predict_proba(np.array([vector(row, features)]))[0, 1])
    thresholds = bundle["meta"].get("thresholds") or {"high": HIGH, "medium": MEDIUM}
    if p < thresholds["medium"]:
        return []
    trends = {k: v for k, v in row.items() if "_delta_" in k and not math.isnan(v) and v != 0}
    calibrated = isinstance(model, CalibratedDriveModel)
    return [{
        "anomaly_type": "ml_drive_failure_risk",
        "severity": "high" if p >= thresholds["high"] else "medium",
        "detector": "drive_health_model",
        "score": round(p, 4),
        "dedupe_key": f"smart:{serial}:health_model",
        "details": {
            "device_serial": serial,
            ("failure_probability_30d" if calibrated else "risk_score"): round(p, 4),
            "message": ("calibrated chance this hard drive fails within 30 days" if calibrated
                        else "relative risk score, not a calibrated probability")
                       + ", learned from Backblaze; a firmware wipe may not complete on a failing drive, "
                         "consider physical destruction",
            "trend_changes": trends,
            "model_trained_at": bundle["meta"]["trained_at"],
            "model_holdout_average_precision": (bundle["meta"].get("holdout") or {}).get("average_precision"),
        },
    }]
