from datetime import datetime, timedelta, timezone

import pytest

from ml import geo

pytestmark = pytest.mark.skipif(not geo.available(), reason="DB-IP database not downloaded")
USER = "abababab-abab-abab-abab-abababababab"


def test_lookup_public_and_private():
    g = geo.lookup("8.8.8.8")
    assert g["country"] == "US" and g["asn"] == 15169
    assert geo.lookup("10.0.0.1") is None and geo.lookup("127.0.0.1") is None and geo.lookup("nonsense") is None


def test_travel_speed():
    us, india = geo.lookup("8.8.8.8"), geo.lookup("49.207.0.1")
    fast = geo.travel(us, india, 1.0)
    assert fast["km"] > 12000 and fast["impossible"]
    assert not geo.travel(us, india, 24.0)["impossible"]
    assert geo.travel(None, india, 1.0) is None


def test_login_row_geo_features():
    from ml.features import login_row
    at = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
    prior = [{"created_at": (at - timedelta(hours=1)).isoformat(), "event_payload": {"ip_address": "8.8.8.8"}}]
    row = login_row(at, "49.207.0.1", prior, 0, "UTC")
    assert row["new_country"] == 1.0 and row["new_asn"] == 1.0 and row["log_travel_kmh"] > 9
    same = login_row(at, "8.8.8.8", prior, 0, "UTC")
    assert same["new_country"] == 0.0 and same["log_travel_kmh"] == 0.0


def test_impossible_travel_rule(fake_db):
    from backend import anomaly
    now = datetime.now(timezone.utc)
    fake_db.tables["audit_log"] = [
        {"id": 2, "user_id": USER, "event_type": "login_success", "created_at": now.isoformat(),
         "event_payload": {"ip_address": "49.207.0.1"}, "entry_hash": "b" * 64, "prev_entry_hash": "a" * 64},
        {"id": 1, "user_id": USER, "event_type": "login_success",
         "created_at": (now - timedelta(minutes=40)).isoformat(),
         "event_payload": {"ip_address": "8.8.8.8"}, "entry_hash": "a" * 64, "prev_entry_hash": "0" * 64},
    ]
    found = anomaly.check_impossible_travel(USER, None, "49.207.0.1", now)
    assert found["anomaly_type"] == "impossible_travel" and found["details"]["implied_kmh"] > 10000
    new_ip = anomaly.check_new_ip(USER, None, "49.207.0.1")
    assert new_ip["severity"] == "high" and new_ip["details"]["new_country"] is True
