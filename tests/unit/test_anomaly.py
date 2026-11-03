from datetime import datetime, timezone

import pytest

from backend import anomaly

ORG = "44444444-4444-4444-4444-444444444444"
USER = "55555555-5555-5555-5555-555555555555"


def test_circular_mean_wraps_midnight():
    mean, std = anomaly.circular_hour_stats([23.0, 1.0, 0.0, 23.5, 0.5])
    assert anomaly.hour_distance(mean, 0.0) < 0.2
    assert std >= 1.0
    assert anomaly.hour_distance(23, 1) == 2


def test_dedupe_returns_existing_open_anomaly(fake_db):
    a = anomaly._record_anomaly("x", "low", None, {}, None, None, dedupe_key="k1")
    b = anomaly._record_anomaly("x", "low", None, {}, None, None, dedupe_key="k1")
    assert a["id"] == b["id"] and len(fake_db.tables["anomalies"]) == 1
    fake_db.svc.table("anomalies").update({"status": "resolved"}).eq("id", a["id"]).execute()
    anomaly._record_anomaly("x", "low", None, {}, None, None, dedupe_key="k1")
    assert len(fake_db.tables["anomalies"]) == 2


def test_smart_checks_are_deduped_and_cover_nvme(fake_db):
    snap = {"available": True, "health": "Passed", "attributes": [
        {"id": 5, "name": "Reallocated_Sector_Ct", "value": 90, "worst": 90, "threshold": 10, "raw": "20"}],
        "nvme": {"critical_warning": 1, "available_spare": 5, "available_spare_threshold": 10,
                 "percentage_used": 101, "media_errors": 2}}
    first = anomaly.check_smart_anomalies("SER", snap, None, USER)
    anomaly.check_smart_anomalies("SER", snap, None, USER)
    types = {a["anomaly_type"] for a in first}
    assert {"smart_reallocated_sectors", "smart_nvme_critical_warning", "smart_nvme_spare_low",
            "smart_nvme_worn_out", "smart_nvme_media_errors"} <= types
    assert len(fake_db.tables["anomalies"]) == len(first)


def test_off_hours_uses_org_timezone(fake_db):
    fake_db.tables["organisations"] = [{"id": ORG, "timezone": "Asia/Kolkata", "work_start_hour": 9,
                                        "work_end_hour": 18, "anomaly_sensitivity": "medium"}]
    at_10_ist = datetime(2026, 11, 3, 4, 30, tzinfo=timezone.utc)
    at_23_ist = datetime(2026, 11, 3, 17, 30, tzinfo=timezone.utc)
    assert anomaly.check_off_hours_wipe("job-1", ORG, USER, at_10_ist) is None
    assert anomaly.check_off_hours_wipe("job-2", ORG, USER, at_23_ist)["details"]["local_hour"] == 23


def test_new_operator_ignores_current_job(fake_db):
    fake_db.tables["wipe_jobs"] = [{"id": "j1", "user_id": USER}]
    assert anomaly.check_new_operator(USER, None, "j1")["anomaly_type"] == "new_operator_first_wipe"
    fake_db.tables.append("wipe_jobs", {"id": "j2", "user_id": USER})
    fake_db.tables["anomalies"] = []
    assert anomaly.check_new_operator(USER, None, "j2") is None


def test_failed_logins_by_email_and_ip(fake_db):
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        {"event_type": "login_failed", "created_at": now,
         "event_payload": {"email": f"u{i % 3}@x.io", "ip_address": "9.9.9.9"}} for i in range(12)
    ] + [{"event_type": "login_failed", "created_at": now,
          "event_payload": {"email": "a@x.io", "ip_address": "1.1.1.1"}} for _ in range(5)]
    for i, row in enumerate(rows):
        row.update({"id": i + 1, "prev_entry_hash": f"{i:064d}", "entry_hash": f"{i + 1:064d}", "org_id": None})
    fake_db.tables["audit_log"] = rows
    fake_db.db.counters.insert_one({"_id": "audit_log", "seq": len(rows)})
    found = anomaly.check_failed_logins("a@x.io", None, "1.1.1.1")
    assert [f["anomaly_type"] for f in found] == ["brute_force_login"]
    stuffing = anomaly.check_failed_logins("u0@x.io", None, "9.9.9.9")
    assert "credential_stuffing" in [f["anomaly_type"] for f in stuffing]


def test_seconds_per_gib_pass():
    job = {"duration_seconds": 200, "device_capacity_bytes": 10 * 2 ** 30, "passes_completed": 2}
    assert anomaly.seconds_per_gib_pass(job) == pytest.approx(10.0)


def test_duration_outlier_is_capacity_normalised(fake_db):
    jobs = []
    for i in range(20):
        cap = (i % 4 + 1) * 100 * 2 ** 30
        jobs.append({"id": f"j{i}", "user_id": USER, "org_id": None, "status": "completed", "device_type": "hdd",
                     "technique": "overwrite", "passes_completed": 1, "device_capacity_bytes": cap,
                     "duration_seconds": cap / 2 ** 30 * (9 + i % 3 * 0.2), "completed_at": f"2026-10-{i + 1:02d}"})
    jobs.append({"id": "fast", "user_id": USER, "org_id": None, "status": "completed", "device_type": "hdd",
                 "technique": "overwrite", "passes_completed": 1, "device_capacity_bytes": 400 * 2 ** 30,
                 "duration_seconds": 30, "completed_at": "2026-10-30"})
    fake_db.tables["wipe_jobs"] = jobs
    found = anomaly.duration_outliers(None)
    assert [f["source_event_id"] for f in found] == ["fast"]
    assert found[0]["details"]["direction"] == "too_fast"


def test_acknowledge_records_feedback(fake_db):
    a = anomaly._record_anomaly("x", "low", None, {}, None, USER)
    out = anomaly.acknowledge_anomaly(a["id"], USER, "checked", True, "false_positive")
    assert out["status"] == "resolved" and out["feedback"] == "false_positive"
