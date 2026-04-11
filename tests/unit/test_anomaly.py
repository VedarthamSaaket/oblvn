import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


def _mock_svc(count=0, data=None):
    svc = MagicMock()
    r = MagicMock()
    r.count = count
    r.data = data or []
    chain = svc.table.return_value
    for attr in ["select", "eq", "gte", "lte", "order", "limit", "maybe_single", "insert", "update"]:
        chain = getattr(chain, attr).return_value
    chain.execute.return_value = r
    svc.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value = r
    svc.table.return_value.select.return_value.eq.return_value.eq.return_value.eq.return_value.execute.return_value = r
    svc.table.return_value.insert.return_value.execute.return_value.data = [{"id": "test-id"}]
    return svc


def test_compute_risk_score_no_anomalies():
    with patch("backend.anomaly.get_service_client") as mock_get:
        svc = _mock_svc(count=0, data=[])
        mock_get.return_value = svc
        from backend.anomaly import compute_risk_score
        result = compute_risk_score(None)
        assert result["score"] == 0
        assert result["level"] == "low"
        assert result["open_count"] == 0


def test_compute_risk_score_critical():
    anomalies = [{"severity": "critical"}] * 5
    with patch("backend.anomaly.get_service_client") as mock_get:
        svc = MagicMock()
        r = MagicMock()
        r.data = anomalies
        svc.table.return_value.select.return_value.eq.return_value.execute.return_value = r
        mock_get.return_value = svc
        from backend.anomaly import compute_risk_score
        result = compute_risk_score(None)
        assert result["score"] == 75
        assert result["level"] == "critical"


def test_check_smart_no_snapshot():
    with patch("backend.anomaly.get_service_client"):
        from backend.anomaly import check_smart_anomalies
        result = check_smart_anomalies("SER123", {}, None, "u1")
        assert result == []


def test_check_smart_unavailable():
    with patch("backend.anomaly.get_service_client"):
        from backend.anomaly import check_smart_anomalies
        result = check_smart_anomalies("SER123", {"available": False, "attributes": []}, None, "u1")
        assert result == []


def test_check_smart_high_temp():
    with patch("backend.anomaly.get_service_client") as mock_get:
        svc = MagicMock()
        svc.table.return_value.insert.return_value.execute.return_value.data = [{"id": "x"}]
        mock_get.return_value = svc
        with patch("backend.anomaly.log_event"):
            from backend.anomaly import check_smart_anomalies
            snapshot = {
                "available": True,
                "attributes": [
                    {"name": "Temperature_Celsius", "raw": "60", "value": 40, "worst": 40, "threshold": 0, "flags": ""},
                ]
            }
            result = check_smart_anomalies("SER123", snapshot, None, "u1")
            assert len(result) >= 1


def test_sensitivity_thresholds():
    from backend.anomaly import SENSITIVITY_THRESHOLDS
    assert "low" in SENSITIVITY_THRESHOLDS
    assert "medium" in SENSITIVITY_THRESHOLDS
    assert "high" in SENSITIVITY_THRESHOLDS
    assert SENSITIVITY_THRESHOLDS["high"]["failed_logins"] < SENSITIVITY_THRESHOLDS["low"]["failed_logins"]


def test_seeded_baseline_structure():
    from backend.anomaly import SEEDED_BASELINE
    assert "wipe_duration_seconds" in SEEDED_BASELINE
    assert "jobs_per_day" in SEEDED_BASELINE
    assert "login_hour" in SEEDED_BASELINE
    for k, v in SEEDED_BASELINE.items():
        assert "mean" in v
        assert "std" in v
