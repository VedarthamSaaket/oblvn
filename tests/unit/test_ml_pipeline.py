import json

import pandas as pd

from ml import train
from ml.scripts import prepare_backblaze
from tests.unit.test_ml import synthetic_jobs


def test_prepare_backblaze_labels_30_days_before_failure(tmp_path, monkeypatch):
    raw = tmp_path / "raw" / "Q1_2024"
    raw.mkdir(parents=True)
    monkeypatch.setattr(prepare_backblaze, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(prepare_backblaze, "PROCESSED_DIR", tmp_path / "processed")
    for day in range(1, 41):
        rows = []
        for serial in ("FAIL1", "OK1", "OK2"):
            rows.append({"date": f"2024-01-{day:02d}" if day <= 31 else f"2024-02-{day - 31:02d}",
                         "serial_number": serial, "model": "M", "capacity_bytes": 4 * 2 ** 40,
                         "failure": 1 if serial == "FAIL1" and day == 40 else 0,
                         "smart_5_raw": 100 if serial == "FAIL1" else 0, "smart_9_raw": day})
        pd.DataFrame(rows).to_csv(raw / f"day{day:02d}.csv", index=False)
    path = prepare_backblaze.build(["Q1_2024"], negative_rate=1.0, seed=1)
    df = pd.read_parquet(path)
    fail = df[df["serial_number"] == "FAIL1"]
    assert fail["label"].eq(1).all() and len(fail) == 31
    assert df[df["serial_number"] != "FAIL1"]["label"].eq(0).all()
    assert df["smart_197_raw"].isna().all()


def test_train_run_writes_report(fake_db, models_dir):
    jobs = synthetic_jobs(80)
    for j in jobs:
        j["wipe_record"] = json.dumps(j["wipe_record"])
    fake_db.tables["wipe_jobs"] = jobs
    fake_db.tables["organisations"] = []
    fake_db.tables["anomalies"] = [{"id": f"a{i}", "org_id": None, "anomaly_type": "off_hours_wipe",
                                    "feedback": "false_positive"} for i in range(12)]
    reports = train.run()
    by_scope = {r["scope"]: r for r in reports}
    assert by_scope["global"]["duration"]["samples"] == 80
    assert by_scope["individual"]["behaviour"]["behaviour_jobs"]["samples"] == 80
    assert by_scope["individual"]["feedback"]["types"]["off_hours_wipe"]["multiplier"] == 1.5
    assert (models_dir / "last_training_report.json").exists()
