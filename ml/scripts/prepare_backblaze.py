import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import SMART_IDS, SMART_FEATURES
from ml.paths import PROCESSED_DIR, RAW_DIR

HORIZON_DAYS = 30
RAW_COLUMNS = [f"smart_{i}_raw" for i in SMART_IDS]


def _files(quarters: list[str]) -> list[Path]:
    files = []
    for q in quarters:
        files.extend(sorted((RAW_DIR / q).glob("*.csv")))
    if not files:
        raise SystemExit(f"no CSVs found under {RAW_DIR} for {quarters}; run fetch_backblaze first")
    return files


def failures(files: list[Path]) -> dict[str, pd.Timestamp]:
    out: dict[str, pd.Timestamp] = {}
    for f in files:
        df = pd.read_csv(f, usecols=["date", "serial_number", "failure"])
        for serial, date in df.loc[df["failure"] == 1, ["serial_number", "date"]].itertuples(index=False):
            out.setdefault(serial, pd.Timestamp(date))
    return out


def build(quarters: list[str], negative_rate: float, seed: int) -> Path:
    files = _files(quarters)
    failed = failures(files)
    last_day = pd.Timestamp(pd.read_csv(files[-1], usecols=["date"], nrows=1)["date"].iloc[0])
    censor_from = last_day - pd.Timedelta(days=HORIZON_DAYS)
    rng = np.random.default_rng(seed)
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
        keep = positive | (rng.random(len(df)) < negative_rate) & fail_at.isna() & known_future
        df = df[keep].copy()
        df["label"] = positive[keep].astype(int)
        for c in RAW_COLUMNS:
            if c not in df:
                df[c] = np.nan
        cap = df["capacity_bytes"].where(df["capacity_bytes"] > 0) / 2 ** 30
        df["log2_capacity_gib"] = np.log2(cap)
        parts.append(df[["date", "serial_number", "model", "label"] + SMART_FEATURES])
        print(f"{f.name}: kept {len(df)} rows, {int(df['label'].sum())} positive")
    out = pd.concat(parts, ignore_index=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    path = PROCESSED_DIR / "drive_health.parquet"
    out.to_parquet(path, index=False)
    print(f"wrote {len(out)} rows ({int(out['label'].sum())} positive, {out['serial_number'].nunique()} drives) to {path}")
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
