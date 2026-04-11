import pytest
from unittest.mock import patch, MagicMock


def test_login_success(client):
    mock_svc = MagicMock()
    mock_svc.auth.sign_in_with_password.return_value.user.id = "user-123"
    mock_svc.auth.sign_in_with_password.return_value.session.access_token = "tok-abc"
    mock_svc.auth.sign_in_with_password.return_value.session.refresh_token = "ref-xyz"
    mock_svc.table.return_value.insert.return_value.execute.return_value.data = [{}]
    mock_svc.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = []

    with patch("backend.server.get_service_client", return_value=mock_svc), \
         patch("backend.audit.get_service_client", return_value=mock_svc), \
         patch("backend.anomaly.get_service_client", return_value=mock_svc):
        res = client.post("/api/auth/login", json={"email": "test@test.com", "password": "pass123"})

    assert res.status_code == 200
    data = res.get_json()
    assert "access_token" in data


def test_login_failure(client):
    mock_svc = MagicMock()
    mock_svc.auth.sign_in_with_password.side_effect = Exception("Invalid credentials")
    mock_svc.table.return_value.insert.return_value.execute.return_value.data = [{}]
    mock_svc.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = []

    with patch("backend.server.get_service_client", return_value=mock_svc), \
         patch("backend.audit.get_service_client", return_value=mock_svc), \
         patch("backend.anomaly.get_service_client", return_value=mock_svc):
        res = client.post("/api/auth/login", json={"email": "bad@test.com", "password": "wrong"})

    assert res.status_code == 401


def test_devices_requires_auth(client):
    res = client.get("/api/devices")
    assert res.status_code == 401


def test_jobs_requires_auth(client):
    res = client.get("/api/jobs")
    assert res.status_code == 401


def test_audit_requires_auth(client):
    res = client.get("/api/audit")
    assert res.status_code == 401


def test_anomalies_requires_auth(client):
    res = client.get("/api/anomalies")
    assert res.status_code == 401


def test_verify_endpoint_public(client):
    mock_svc = MagicMock()
    mock_svc.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    with patch("backend.server.get_service_client", return_value=mock_svc):
        res = client.get("/verify/nonexistent-cert-id")
    assert res.status_code == 404
    data = res.get_json()
    assert data["verified"] is False


def test_password_reset_endpoint(client):
    mock_svc = MagicMock()
    mock_svc.auth.reset_password_email.return_value = None
    with patch("backend.server.get_service_client", return_value=mock_svc):
        res = client.post("/api/auth/password/reset", json={"email": "test@test.com"})
    assert res.status_code == 200
