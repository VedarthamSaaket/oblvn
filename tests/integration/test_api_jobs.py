import jwt
import pytest
from unittest.mock import patch, MagicMock


def _token():
    return jwt.encode({"sub": "user-123", "exp": 9999999999}, "test-anon-key", algorithm="HS256")


def _svc_mock(job_data=None):
    mock = MagicMock()
    mock.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    mock.table.return_value.select.return_value.order.return_value.execute.return_value.data = job_data or []
    mock.table.return_value.insert.return_value.execute.return_value.data = [
        {"id": "job-abc", "status": "queued", "device_serial": "SER-001", "device_model": "Test Drive",
         "method": "nist_800_88", "standard": "nist_800_88", "device_capacity_bytes": 1000000, "device_type": "ssd",
         "user_id": "user-123", "org_id": None, "passes_completed": 0, "created_at": "2026-01-01T00:00:00Z"}
    ]
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []
    return mock


def test_list_jobs(client):
    jobs = [{"id": "j1", "status": "completed", "device_model": "Test", "device_serial": "S1",
             "method": "nist_800_88", "standard": "nist_800_88"}]
    mock = _svc_mock()
    mock.table.return_value.select.return_value.order.return_value.execute.return_value.data = jobs
    mock.table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = jobs

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock):
        res = client.get("/api/jobs", headers={"Authorization": f"Bearer {_token()}"})

    assert res.status_code == 200
    assert "jobs" in res.get_json()


def test_create_job_device_not_found(client):
    mock = _svc_mock()
    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock), \
         patch("backend.server.detect_devices", side_effect=Exception("No devices")):
        res = client.post("/api/jobs",
                          json={"device_serial": "GHOST", "method": "nist_800_88", "standard": "nist_800_88"},
                          headers={"Authorization": f"Bearer {_token()}"})
    assert res.status_code in (404, 503)


def test_get_job_not_found(client):
    mock = _svc_mock()
    mock.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock):
        res = client.get("/api/jobs/nonexistent", headers={"Authorization": f"Bearer {_token()}"})

    assert res.status_code == 404


def test_cancel_job_not_queued(client):
    mock = _svc_mock()
    mock.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {
        "status": "running", "user_id": "user-123"
    }

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock):
        res = client.post("/api/jobs/job-running/cancel", headers={"Authorization": f"Bearer {_token()}"})

    assert res.status_code == 400
