import hashlib
import json
import pytest
from unittest.mock import patch, MagicMock
from backend.reporter import _compute_hash, _generate_qr


def test_compute_hash_deterministic():
    fields = {"certificate_id": "abc", "device_serial": "XYZ", "issued_at": "2026-01-01T00:00:00Z"}
    h1 = _compute_hash(fields)
    h2 = _compute_hash(fields)
    assert h1 == h2
    assert len(h1) == 64


def test_compute_hash_changes_with_fields():
    fields_a = {"certificate_id": "abc"}
    fields_b = {"certificate_id": "def"}
    assert _compute_hash(fields_a) != _compute_hash(fields_b)


def test_compute_hash_canonical_key_order():
    fields_1 = {"b": "2", "a": "1"}
    fields_2 = {"a": "1", "b": "2"}
    assert _compute_hash(fields_1) == _compute_hash(fields_2)


def test_generate_qr_returns_base64():
    import base64
    qr = _generate_qr("https://verify.oblvn.com/test-id")
    decoded = base64.b64decode(qr)
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_compute_hash_matches_manual_sha256():
    fields = {"a": "1", "b": "2"}
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert _compute_hash(fields) == expected
