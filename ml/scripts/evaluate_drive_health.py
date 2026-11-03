import argparse
import json
import time

from ml import drive_health
from ml.features import BASE_SMART_FEATURES, MAKER_FEATURES, MAKERS, SMART_FEATURES, TREND_FEATURES
from ml.paths import MODELS_DIR

VARIANTS = {
    "base": BASE_SMART_FEATURES,
    "base+maker": BASE_SMART_FEATURES + MAKER_FEATURES,
    "base+trend": BASE_SMART_FEATURES + TREND_FEATURES,
    "full": SMART_FEATURES,
}
KEYS = ("average_precision", "roc_auc", "brier", "ece")


def _pick(m: dict) -> dict:
    out = {k: m.get(k) for k in KEYS}
    for t in m.get("at_thresholds", []):
        if t["threshold"] in (0.10, 0.30):
            out[f"precision@{t['threshold']}"] = t["precision"]
            out[f"recall@{t['threshold']}"] = t["recall"]
    return out


def run(min_family_failures: int = 200) -> dict:
    started = time.monotonic()
    df = drive_health.load_dataset()
    parts = drive_health.splits(df)
    report = {"split": parts["bounds"], "variants": {}, "families": {}}
    models = {}
    for name, feats in VARIANTS.items():
        t = time.monotonic()
        model, _ = drive_health.fit(df, feats, parts)
        res = drive_health.evaluate(model, df, parts["test"])
        models[name] = model
        report["variants"][name] = {"features": len(feats), **_pick(res["calibrated"]),
                                    "uncalibrated_brier": res["uncalibrated_brier"],
                                    "seconds": round(time.monotonic() - t, 1)}
        print(name, report["variants"][name], flush=True)
    full = models["full"]
    for maker in MAKERS:
        fam = df["maker"] == maker
        fam_parts = {k: (v & fam) if k != "bounds" else v for k, v in parts.items()}
        failures = int(df[fam_parts["train"] & (df["label"] == 1)]["serial_number"].nunique())
        if failures < min_family_failures or not df[fam_parts["test"]]["label"].any():
            report["families"][maker] = {"skipped": f"{failures} failed drives in training"}
            continue
        own, _ = drive_health.fit(df, SMART_FEATURES, fam_parts)
        report["families"][maker] = {
            "failed_drives_in_training": failures,
            "single_model": _pick(drive_health.evaluate(full, df, fam_parts["test"])["calibrated"]),
            "family_model": _pick(drive_health.evaluate(own, df, fam_parts["test"])["calibrated"]),
        }
        print(maker, report["families"][maker], flush=True)
    report["seconds"] = round(time.monotonic() - started, 1)
    out = MODELS_DIR / "global" / "drive_health_evaluation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"saved {out} in {report['seconds']}s")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Feature ablation and per-family comparison for the drive health model")
    ap.add_argument("--min-family-failures", type=int, default=200)
    run(ap.parse_args().min_family_failures)


if __name__ == "__main__":
    main()
