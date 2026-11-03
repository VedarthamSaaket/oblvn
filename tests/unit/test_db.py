import mongomock
import pytest

from backend.db import AppendOnly, DuplicateKey, ServiceClient, UserClient, ValidationError
from backend.db.schema import ensure_schema

U1, U2, ORG = "11111111-0000-0000-0000-000000000001", "11111111-0000-0000-0000-000000000002", "22222222-0000-0000-0000-000000000001"


@pytest.fixture
def db():
    d = mongomock.MongoClient(tz_aware=True).oblvn
    ensure_schema(d)
    return d


def job(**kw):
    return {"user_id": U1, "method": "crypto_erase", "standard": "nist_800_88", "device_serial": "S",
            "device_model": "M", "device_capacity_bytes": 10, "device_type": "nvme", **kw}


def test_insert_defaults_id_and_select(db):
    svc = ServiceClient(db)
    row = svc.table("wipe_jobs").insert(job()).execute().data[0]
    assert row["status"] == "queued" and row["passes_completed"] == 0 and row["options"] == {} and len(row["id"]) == 36
    got = svc.table("wipe_jobs").select("*").eq("id", row["id"]).maybe_single().execute().data
    assert got["id"] == row["id"] and "_id" not in got
    assert svc.table("wipe_jobs").select("id").eq("id", "missing").maybe_single().execute().data is None


def test_filters_order_range_count(db):
    svc = ServiceClient(db)
    for i in range(7):
        svc.table("wipe_jobs").insert(job(device_serial=f"S{i}", created_at=f"2026-11-0{i + 1}",
                                          org_id=ORG if i % 2 else None)).execute()
    q = svc.table("wipe_jobs").select("*", count="exact").is_("org_id", "null").order("created_at", desc=True)
    r = q.execute()
    assert r.count == 4 and [x["device_serial"] for x in r.data] == ["S6", "S4", "S2", "S0"]
    page = svc.table("wipe_jobs").select("*").order("created_at").range(2, 4).execute().data
    assert [x["device_serial"] for x in page] == ["S2", "S3", "S4"]
    assert len(svc.table("wipe_jobs").select("*").in_("device_serial", ["S1", "S2"]).execute().data) == 2
    assert len(svc.table("wipe_jobs").select("*").gte("created_at", "2026-11-05").lt("created_at", "2026-11-07").execute().data) == 2
    assert len(svc.table("wipe_jobs").select("*").not_.is_("org_id", "null").execute().data) == 3
    assert len(svc.table("wipe_jobs").select("*").neq("device_serial", "S0").execute().data) == 6


def test_update_returns_rows_and_validates(db):
    svc = ServiceClient(db)
    row = svc.table("wipe_jobs").insert(job()).execute().data[0]
    out = svc.table("wipe_jobs").update({"status": "running"}).eq("id", row["id"]).eq("status", "queued").execute()
    assert out.data[0]["status"] == "running"
    assert svc.table("wipe_jobs").update({"status": "completed"}).eq("id", row["id"]).eq("status", "queued").execute().data == []
    with pytest.raises(ValidationError):
        svc.table("wipe_jobs").update({"status": "exploded"}).eq("id", row["id"]).execute()
    with pytest.raises(ValidationError):
        svc.table("wipe_jobs").insert({"user_id": U1}).execute()


def test_anomaly_dedupe_index_follows_status(db):
    svc = ServiceClient(db)
    a = svc.table("anomalies").insert({"anomaly_type": "x", "severity": "low", "dedupe_key": "k"}).execute().data[0]
    with pytest.raises(DuplicateKey) as e:
        svc.table("anomalies").insert({"anomaly_type": "x", "severity": "low", "dedupe_key": "k"}).execute()
    assert "23505" in str(e.value)
    svc.table("anomalies").update({"status": "resolved"}).eq("id", a["id"]).execute()
    svc.table("anomalies").insert({"anomaly_type": "x", "severity": "low", "dedupe_key": "k"}).execute()
    svc.table("anomalies").insert({"anomaly_type": "y", "severity": "low"}).execute()
    assert db.anomalies.count_documents({}) == 3


def test_audit_log_serial_ids_append_only_and_chain_fork(db):
    svc = ServiceClient(db)
    first = svc.table("audit_log").insert({"event_type": "a", "event_payload": "{}", "prev_entry_hash": "0" * 64,
                                           "entry_hash": "1" * 64}).execute().data[0]
    second = svc.table("audit_log").insert({"event_type": "b", "event_payload": "{}", "prev_entry_hash": "1" * 64,
                                            "entry_hash": "2" * 64}).execute().data[0]
    assert (first["id"], second["id"]) == (1, 2) and first["chain_key"] == "global"
    with pytest.raises(DuplicateKey):
        svc.table("audit_log").insert({"event_type": "c", "event_payload": "{}", "prev_entry_hash": "1" * 64,
                                       "entry_hash": "3" * 64}).execute()
    with pytest.raises(AppendOnly):
        svc.table("audit_log").update({"event_type": "x"}).eq("id", 1).execute()
    with pytest.raises(AppendOnly):
        svc.table("audit_log").delete().eq("id", 1).execute()


def test_user_client_applies_policies_and_is_read_only(db):
    svc = ServiceClient(db)
    svc.table("org_memberships").insert({"user_id": U1, "org_id": ORG, "role": "operator"}).execute()
    svc.table("wipe_jobs").insert(job(user_id=U1)).execute()
    svc.table("wipe_jobs").insert(job(user_id=U2)).execute()
    svc.table("wipe_jobs").insert(job(user_id=U2, org_id=ORG)).execute()
    svc.table("audit_log").insert({"event_type": "e", "event_payload": "{}", "prev_entry_hash": "0" * 64,
                                   "entry_hash": "9" * 64, "org_id": ORG, "user_id": U2}).execute()
    mine = UserClient(db, U1)
    assert len(mine.table("wipe_jobs").select("*").execute().data) == 2
    assert len(UserClient(db, U2).table("wipe_jobs").select("*").execute().data) == 2
    assert mine.table("audit_log").select("*").execute().data == []
    assert mine.table("agents").select("*").execute().data == []
    with pytest.raises(PermissionError):
        mine.table("wipe_jobs").update({"status": "cancelled"}).execute()
