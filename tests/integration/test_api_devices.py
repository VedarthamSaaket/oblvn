import pytest
from unittest.mock import patch, MagicMock
from backend.detector import DeviceDetectionError


FAKE_DEVICES = [
    {
        "serial": "TEST-SERIAL-001",
        "model": "Test SSD 1TB",
        "manufacturer": "TestCo",
        "capacity_bytes": 1_000_000_000,
        "capacity_human": "1.0 GB",
        "device_type": "ssd",
        "interface": "SATA",
        "filesystem": "ext4",
        "node": "/dev/sda",
        "health": "Passed",
        "smart_available": False,
        "smart_snapshot": {"available": False, "health": "Unknown", "attributes": []},
        "detected_at": "2026-01-01T00:00:00+00:00",
        "anomalies": [],
    }
]


def _auth_mock():
    mock = MagicMock()
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    return mock


def test_devices_list_returns_devices(client):
    from unittest.mock import patch
    import jwt
    token = jwt.encode({"sub": "user-123", "exp": 9999999999}, "test-anon-key", algorithm="HS256")

    with patch("backend.detector.detect_devices", return_value=FAKE_DEVICES), \
         patch("backend.anomaly.check_smart_anomalies", return_value=[]), \
         patch("backend.auth.get_service_client", return_value=_auth_mock()):
        res = client.get("/api/devices", headers={"Authorization": f"Bearer {token}"})

    assert res.status_code == 200
    data = res.get_json()
    assert "devices" in data
    assert len(data["devices"]) == 1
    assert data["devices"][0]["serial"] == "TEST-SERIAL-001"


def test_devices_list_returns_empty_on_error(client):
    import jwt
    token = jwt.encode({"sub": "user-123", "exp": 9999999999}, "test-anon-key", algorithm="HS256")

    with patch("backend.detector.detect_devices", side_effect=DeviceDetectionError("No drives")), \
         patch("backend.auth.get_service_client", return_value=_auth_mock()):
        res = client.get("/api/devices", headers={"Authorization": f"Bearer {token}"})

    assert res.status_code == 200
    data = res.get_json()
    assert data["devices"] == []
    assert "No drives" in data["error"]


def test_devices_refresh(client):
    import jwt
    token = jwt.encode({"sub": "user-123", "exp": 9999999999}, "test-anon-key", algorithm="HS256")

    with patch("backend.detector.detect_devices", return_value=FAKE_DEVICES), \
         patch("backend.auth.get_service_client", return_value=_auth_mock()):
        res = client.post("/api/devices/refresh", headers={"Authorization": f"Bearer {token}"})

    assert res.status_code == 200
    assert len(res.get_json()["devices"]) == 1
