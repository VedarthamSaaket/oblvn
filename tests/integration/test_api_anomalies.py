import jwt
import pytest
from unittest.mock import patch, MagicMock


def _token():
    return jwt.encode({"sub": "user-123", "exp": 9999999999}, "test-anon-key", algorithm="HS256")


def test_risk_score_endpoint(client):
    mock = MagicMock()
    mock.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock), \
         patch("backend.anomaly.get_service_client", return_value=mock):
        res = client.get("/api/anomalies/risk-score", headers={"Authorization": f"Bearer {_token()}"})

    assert res.status_code == 200
    data = res.get_json()
    assert "score" in data
    assert "level" in data
    assert "colour" in data
    assert 0 <= data["score"] <= 100


def test_list_anomalies(client):
    mock = MagicMock()
    mock.table.return_value.select.return_value.order.return_value.execute.return_value.data = []
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock):
        res = client.get("/api/anomalies", headers={"Authorization": f"Bearer {_token()}"})

    assert res.status_code == 200
    assert "anomalies" in res.get_json()


def test_acknowledge_anomaly(client):
    mock = MagicMock()
    mock.table.return_value.update.return_value.eq.return_value.execute.return_value.data = [{"id": "anom-1", "status": "resolved"}]
    mock.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    mock.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = []
    mock.table.return_value.insert.return_value.execute.return_value.data = [{}]

    with patch("backend.server.get_service_client", return_value=mock), \
         patch("backend.auth.get_service_client", return_value=mock), \
         patch("backend.anomaly.get_service_client", return_value=mock), \
         patch("backend.audit.get_service_client", return_value=mock):
        res = client.post(
            "/api/anomalies/anom-1/acknowledge",
            json={"note": "Investigated, false positive", "resolved": True},
            headers={"Authorization": f"Bearer {_token()}"},
        )

    assert res.status_code == 200
