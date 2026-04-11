import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch


def _make_mock_svc(entries=None):
    svc = MagicMock()
    entries = entries or []
    svc.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = entries
    svc.table.return_value.select.return_value.order.return_value.execute.return_value.data = entries
    svc.table.return_value.insert.return_value.execute.return_value.data = [{"id": 1}]
    return svc


def test_hash_entry_deterministic():
    from backend.audit import _hash_entry
    payload = {"event_type": "test", "payload": {}, "user_id": "u1", "org_id": None}
    h1 = _hash_entry(payload, "0" * 64)
    h2 = _hash_entry(payload, "0" * 64)
    assert h1 == h2
    assert len(h1) == 64


def test_hash_entry_changes_with_prev():
    from backend.audit import _hash_entry
    payload = {"event_type": "test", "payload": {}, "user_id": "u1", "org_id": None}
    h1 = _hash_entry(payload, "0" * 64)
    h2 = _hash_entry(payload, "1" * 64)
    assert h1 != h2


def test_export_csv_empty():
    with patch("backend.audit.get_service_client") as mock_get:
        mock_get.return_value = _make_mock_svc([])
        from backend.audit import export_csv
        result = export_csv()
        assert result == ""


def test_export_json_returns_list():
    entries = [{"id": 1, "event_type": "login_success", "user_id": "u1",
                "org_id": None, "event_payload": "{}", "prev_entry_hash": "0"*64,
                "entry_hash": "a"*64, "created_at": "2026-01-01T00:00:00Z",
                "is_anomaly": False, "anomaly_severity": None, "anomaly_type": None}]
    with patch("backend.audit.get_service_client") as mock_get:
        svc = MagicMock()
        svc.table.return_value.select.return_value.order.return_value.execute.return_value.data = entries
        mock_get.return_value = svc
        from backend.audit import export_json
        result = export_json()
        assert isinstance(result, list)
        assert len(result) == 1


def test_verify_chain_intact():
    import hashlib
    import json
    from backend.audit import _hash_entry

    e1_payload = {"event_type": "login_success", "payload": {}, "user_id": "u1", "org_id": None}
    e1_hash = _hash_entry(e1_payload, "0" * 64)

    e2_payload = {"event_type": "wipe_completed", "payload": {}, "user_id": "u1", "org_id": None}
    e2_hash = _hash_entry(e2_payload, e1_hash)

    entries = [
        {"id": 1, "event_type": "login_success", "event_payload": json.dumps({}),
         "user_id": "u1", "org_id": None, "prev_entry_hash": "0"*64, "entry_hash": e1_hash,
         "created_at": "2026-01-01T00:00:00Z"},
        {"id": 2, "event_type": "wipe_completed", "event_payload": json.dumps({}),
         "user_id": "u1", "org_id": None, "prev_entry_hash": e1_hash, "entry_hash": e2_hash,
         "created_at": "2026-01-01T01:00:00Z"},
    ]

    with patch("backend.audit.get_service_client") as mock_get:
        svc = MagicMock()
        svc.table.return_value.select.return_value.order.return_value.execute.return_value.data = entries
        mock_get.return_value = svc
        from backend.audit import verify_chain
        result = verify_chain()
        assert result["intact"] is True
        assert result["total_entries"] == 2


def test_verify_chain_detects_tampering():
    import json
    entries = [
        {"id": 1, "event_type": "login_success", "event_payload": json.dumps({}),
         "user_id": "u1", "org_id": None, "prev_entry_hash": "0"*64,
         "entry_hash": "wrong_hash_tampered",
         "created_at": "2026-01-01T00:00:00Z"},
    ]
    with patch("backend.audit.get_service_client") as mock_get:
        svc = MagicMock()
        svc.table.return_value.select.return_value.order.return_value.execute.return_value.data = entries
        mock_get.return_value = svc
        from backend.audit import verify_chain
        result = verify_chain()
        assert result["intact"] is False
        assert result["broken_at_entry"] == 0
