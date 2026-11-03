import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from ml import behaviour, drive_health, feedback, wipe_duration
from ml.features import SMART_FEATURES, technique_family


def synthetic_jobs(n=120, seed=7):
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
    jobs = []
    for i in range(n):
        gib = rng.choice([64, 128, 256, 512, 1024])
        passes = rng.choice([1, 3])
        seconds = gib * passes * rng.uniform(4.5, 5.5)
        created = start + timedelta(hours=i * 7 % 2000, minutes=rng.randint(0, 50))
        jobs.append({
            "id": f"job-{i}", "user_id": f"user-{i % 4}", "org_id": None, "status": "completed",
            "method": "binary_overwrite", "device_type": "hdd", "technique": "overwrite",
            "device_capacity_bytes": gib * 2 ** 30, "passes_completed": passes,
            "created_at": created.replace(hour=9 + i % 8).isoformat(),
            "wipe_record": {"technique": "overwrite", "device": {"transport": "sata"},
                            "telemetry": {"total_seconds": seconds, "size_bytes": gib * 2 ** 30,
                                          "overwrite_passes": passes, "bytes_written": gib * 2 ** 30 * passes,
                                          "throughput_mbps": gib * 2 ** 30 * passes / 1e6 / seconds}},
        })
    return jobs


def test_technique_family():
    assert technique_family("nvme_sanitize_crypto") == "firmware_crypto"
    assert technique_family("ata_sanitize_block+overwrite") == "firmware_plus_overwrite"
    assert technique_family("ata_secure_erase_enhanced") == "firmware_secure_erase"
    assert technique_family(None, "file") == "file_overwrite"


def test_wipe_duration_flags_too_fast(models_dir):
    meta = wipe_duration.train(synthetic_jobs(), "individual")
    assert meta["samples"] == 120 and meta["holdout"]["interval_coverage_90"] > 0.5
    job = synthetic_jobs(1, seed=99)[0]
    record = dict(job["wipe_record"])
    record["telemetry"] = {**record["telemetry"], "total_seconds": 2.0}
    found = wipe_duration.score(job, record, "individual")
    assert "ml_wipe_too_fast" in [f["anomaly_type"] for f in found]
    normal = wipe_duration.score(job, job["wipe_record"], "individual")
    assert "ml_wipe_too_fast" not in [f["anomaly_type"] for f in normal]


def test_physics_rules():
    job = {"id": "j", "device_type": "hdd"}
    record = {"technique": "overwrite", "device": {"transport": "sata"},
              "telemetry": {"throughput_mbps": 5000, "size_bytes": 100, "overwrite_passes": 1, "bytes_written": 50}}
    types = {f["anomaly_type"] for f in wipe_duration.physics_findings(job, record)}
    assert types == {"impossible_wipe_throughput", "incomplete_wipe_write"}
    assert wipe_duration.physics_findings(job, {**record, "technique": "nvme_sanitize_crypto"}) == []


def test_too_few_samples_returns_none(models_dir):
    assert wipe_duration.train(synthetic_jobs(10), "individual") is None


def test_behaviour_flags_burst_at_night(models_dir):
    jobs = synthetic_jobs(200)
    result = behaviour.train(jobs, [], "individual", "UTC")
    assert result[behaviour.JOBS]["samples"] == 200 and result[behaviour.LOGINS] is None
    history = [{"created_at": (datetime(2026, 6, 1, 3, tzinfo=timezone.utc) - timedelta(minutes=m)).isoformat(),
                "status": "cancelled"} for m in range(1, 30)]
    odd = {"id": "odd", "user_id": "user-x", "method": "crypto_erase", "device_type": "usb_flash",
           "device_capacity_bytes": 2 ** 30, "created_at": datetime(2026, 6, 1, 3, tzinfo=timezone.utc).isoformat()}
    found = behaviour.score_job(odd, history, odd["created_at"], "UTC", "individual")
    assert found and found[0]["anomaly_type"] == "ml_unusual_job_behaviour"
    assert found[0]["details"]["top_reasons"]


def test_feedback_multiplier(models_dir):
    labels = [{"anomaly_type": "off_hours_wipe", "feedback": "false_positive"}] * 9 + \
             [{"anomaly_type": "off_hours_wipe", "feedback": "true_positive"}] * 3
    out = feedback.calibrate(None, labels)
    assert out["types"]["off_hours_wipe"]["precision"] == 0.25
    assert feedback.cutoff_multiplier(None, "off_hours_wipe") == 1.25
    assert feedback.cutoff_multiplier(None, "unknown_type") == 1.0
    assert feedback.multiplier(0.95, 20) == 0.9 and feedback.multiplier(0.2, 3) == 1.0


def test_drive_health_train_and_score(models_dir, tmp_path):
    rng = np.random.default_rng(0)
    n = 4000
    df = pd.DataFrame({c: rng.integers(0, 5, n).astype(float) for c in SMART_FEATURES})
    label = rng.random(n) < 0.05
    df.loc[label, "smart_5_raw"] = rng.integers(50, 500, label.sum())
    df.loc[label, "smart_197_raw"] = rng.integers(10, 100, label.sum())
    df["label"] = label.astype(int)
    df["date"] = pd.date_range("2024-01-01", periods=n, freq="h")
    df["serial_number"] = [f"S{i % 400}" for i in range(n)]
    df["model"] = "TEST"
    path = tmp_path / "dh.parquet"
    df.to_parquet(path)
    meta = drive_health.train(path)
    assert meta["holdout"]["average_precision"] > 0.5
    bad = {"attributes": [{"id": 5, "raw": "300"}, {"id": 197, "raw": "40"}, {"id": 9, "raw": "2"},
                          {"id": 1, "raw": "1"}, {"id": 194, "raw": "3"}]}
    found = drive_health.score("SER", bad)
    assert found and found[0]["anomaly_type"] == "ml_drive_failure_risk"
    good = {"attributes": [{"id": i, "raw": "1"} for i in (1, 5, 9, 194, 197)]}
    assert drive_health.score("SER2", good) == []
    assert drive_health.score("SER3", {"attributes": [{"id": 5, "raw": "1"}]}) == []


def test_behaviour_falls_back_to_global_model(models_dir):
    behaviour.train(synthetic_jobs(200), [], "global", "UTC")
    odd = {"id": "odd2", "user_id": "u", "method": "crypto_erase", "device_type": "usb_flash",
           "device_capacity_bytes": 2 ** 30, "created_at": datetime(2026, 6, 1, 3, tzinfo=timezone.utc).isoformat()}
    history = [{"created_at": (datetime(2026, 6, 1, 3, tzinfo=timezone.utc) - timedelta(minutes=m)).isoformat(),
                "status": "cancelled"} for m in range(1, 30)]
    found = behaviour.score_job(odd, history, odd["created_at"], "UTC", "some-org-without-a-model")
    assert found and found[0]["details"]["model_scope"] == "global"


def test_registry_promotion_guard(models_dir):
    from ml import registry
    first = registry.promote("global", "toy", {"v": 1}, {"samples": 1}, 0.80, None, "ap")
    assert first["promotion"]["decision"] == "promoted"
    worse = registry.promote("global", "toy", {"v": 2}, {"samples": 2}, 0.70, 0.80, "ap")
    assert worse["promotion"]["decision"] == "rejected"
    assert registry.load("global", "toy")["model"] == {"v": 1}
    better = registry.promote("global", "toy", {"v": 3}, {"samples": 3}, 0.795, 0.80, "ap")
    assert better["promotion"]["decision"] == "promoted" and registry.load("global", "toy")["model"] == {"v": 3}
    history = sorted(p.name for p in (models_dir / "global" / "history").glob("toy-*.joblib"))
    assert len(history) == 2 and any("rejected" in h for h in history)
    lines = (models_dir / "global" / "promotions.jsonl").read_text().splitlines()
    assert [__import__("json").loads(l)["decision"] for l in lines] == ["promoted", "rejected", "promoted"]


def test_duration_retrain_reports_promotion(models_dir):
    first = wipe_duration.train(synthetic_jobs(), "individual")
    second = wipe_duration.train(synthetic_jobs(seed=8), "individual")
    assert first["promotion"]["decision"] == "promoted"
    assert second["promotion"]["incumbent"] is not None


def test_drive_health_skips_ssd_and_nvme():
    assert drive_health.is_hard_drive({"rotation_rate": 7200, "attributes": [1]})
    assert drive_health.is_hard_drive({"attributes": [1]})
    assert not drive_health.is_hard_drive({"rotation_rate": 0, "attributes": [1]})
    assert not drive_health.is_hard_drive({"rotation_rate": "Solid State Device", "attributes": [1]})
    assert not drive_health.is_hard_drive({"nvme": {"percentage_used": 3}, "attributes": []})
    assert drive_health.score("SSD", {"rotation_rate": 0, "attributes": [{"id": 5, "raw": "900"}] * 5}) == []
