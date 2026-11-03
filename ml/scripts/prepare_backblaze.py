import argparse
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import MAKERS, SMART_FEATURES, SMART_IDS, TREND_IDS, TREND_LAGS, manufacturer
from ml.paths import PROCESSED_DIR, RAW_DIR

HORIZON_DAYS = 30
RAW_COLUMNS = [f"smart_{i}_raw" for i in SMART_IDS]
TREND_COLUMNS = [f"smart_{i}_raw" for i in TREND_IDS]


def _files(quarters: list[str]) -> list[Path]:
    files = []
    for q in quarters:
        files.extend(sorted((RAW_DIR / q).glob("*.csv")))
    if not files:
        raise SystemExit(f"no CSVs found under {RAW_DIR} for {quarters}; run fetch_backblaze first")
    return sorted(files, key=lambda f: f.stem)


def failures(files: list[Path]) -> dict[str, pd.Timestamp]:
    out: dict[str, pd.Timestamp] = {}
    for f in files:
        df = pd.read_csv(f, usecols=["date", "serial_number", "failure"])
        for serial, date in df.loc[df["failure"] == 1, ["serial_number", "date"]].itertuples(index=False):
            out.setdefault(serial, pd.Timestamp(date))
    return out


def _sample(files: list[Path], failed: dict, censor_from: pd.Timestamp, negative_rate: float,
            rng: np.random.Generator) -> pd.DataFrame:
    parts = []
    for f in files:
        header = pd.read_csv(f, nrows=0).columns
        cols = ["date", "serial_number", "model", "capacity_bytes"] + [c for c in RAW_COLUMNS if c in header]
        df = pd.read_csv(f, usecols=cols)
        df["date"] = pd.to_datetime(df["date"])
        fail_at = df["serial_number"].map(failed)
        days = (fail_at - df["date"]).dt.days
        positive = days.between(0, HORIZON_DAYS)
        known_future = df["date"] <= censor_from
        negative = (rng.random(len(df)) < negative_rate) & fail_at.isna() & known_future
        df = df[positive | negative].copy()
        df["label"] = positive[positive | negative].astype(int).to_numpy()
        for c in RAW_COLUMNS:
            if c not in df:
                df[c] = np.nan
        parts.append(df)
        print(f"{f.name}: kept {len(df)} rows, {int(df['label'].sum())} positive", flush=True)
    return pd.concat(parts, ignore_index=True)


def _add_trends(df: pd.DataFrame, files: list[Path]) -> pd.DataFrame:
    by_day = {pd.Timestamp(f.stem): f for f in files}
    wanted: dict[pd.Timestamp, set] = defaultdict(set)
    for lag in TREND_LAGS:
        for serial, day in zip(df["serial_number"], df["date"] - pd.Timedelta(days=lag)):
            if day in by_day:
                wanted[day].add(serial)
    lookup: dict[tuple, np.ndarray] = {}
    for day in sorted(wanted):
        header = pd.read_csv(by_day[day], nrows=0).columns
        cols = [c for c in TREND_COLUMNS if c in header]
        past = pd.read_csv(by_day[day], usecols=["serial_number"] + cols)
        past = past[past["serial_number"].isin(wanted[day])]
        for c in TREND_COLUMNS:
            if c not in past:
                past[c] = np.nan
        for row in past.itertuples(index=False):
            lookup[(row[0], day)] = tuple(row[1:])
    for lag in TREND_LAGS:
        keys = zip(df["serial_number"], df["date"] - pd.Timedelta(days=lag))
        empty = (np.nan,) * len(TREND_COLUMNS)
        past = np.array([lookup.get(k, empty) for k in keys], dtype=float).reshape(len(df), len(TREND_COLUMNS))
        now = df[TREND_COLUMNS].to_numpy(float)
        for j, i in enumerate(TREND_IDS):
            df[f"smart_{i}_delta_{lag}d"] = now[:, j] - past[:, j]
    print(f"trend lookups: {len(lookup)} past rows from {len(wanted)} days", flush=True)
    return df


def build(quarters: list[str], negative_rate: float, seed: int) -> Path:
    started = time.monotonic()
    files = _files(quarters)
    failed = failures(files)
    last_day = pd.Timestamp(files[-1].stem)
    censor_from = last_day - pd.Timedelta(days=HORIZON_DAYS)
    rng = np.random.default_rng(seed)
    df = _sample(files, failed, censor_from, negative_rate, rng)
    df = _add_trends(df, files)
    cap = df["capacity_bytes"].where(df["capacity_bytes"] > 0) / 2 ** 30
    df["log2_capacity_gib"] = np.log2(cap)
    makers = df["model"].map(manufacturer)
    for m in MAKERS:
        df[f"maker_{m}"] = (makers == m).astype(float)
    df["maker"] = makers
    df["weight"] = np.where(df["label"] == 1, 1.0, 1.0 / negative_rate)
    out = df[["date", "serial_number", "model", "maker", "label", "weight"] + SMART_FEATURES]
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    path = PROCESSED_DIR / "drive_health.parquet"
    out.to_parquet(path, index=False)
    meta = {"quarters": quarters, "negative_rate": negative_rate, "seed": seed, "files": len(files),
            "first_day": str(pd.Timestamp(files[0].stem).date()), "last_day": str(last_day.date()),
            "censor_from": str(censor_from.date()), "failed_drives": len(failed), "rows": len(out),
            "positive_rows": int(out["label"].sum()), "drives": int(out["serial_number"].nunique()),
            "seconds": round(time.monotonic() - started, 1)}
    (PROCESSED_DIR / "drive_health.meta.json").write_text(pd.Series(meta).to_json(indent=2))
    print(f"wrote {meta['rows']} rows ({meta['positive_rows']} positive, {meta['drives']} drives, "
          f"{meta['failed_drives']} failed drives) to {path} in {meta['seconds']}s")
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description="Turn Backblaze daily CSVs into the drive health training set")
    ap.add_argument("--quarter", action="append", required=True)
    ap.add_argument("--negative-rate", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    build(args.quarter, args.negative_rate, args.seed)


if __name__ == "__main__":
    main()
