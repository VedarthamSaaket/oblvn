import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


def test_stamp_returns_dict_on_calendar_error(tmp_path):
    with patch("backend.config.config.DATA_DIR", tmp_path):
        (tmp_path / "ots").mkdir(parents=True, exist_ok=True)

        with patch("backend.timestamps._ots_stamp", side_effect=Exception("network error")):
            from backend.timestamps import stamp_certificate
            result = stamp_certificate("a" * 64, "test-cert-id")

    assert result["cert_id"] == "test-cert-id"
    assert result["cert_hash"] == "a" * 64
    assert "error" in result


def test_stamp_returns_ots_path_on_success(tmp_path):
    with patch("backend.config.config.DATA_DIR", tmp_path):
        (tmp_path / "ots").mkdir(parents=True, exist_ok=True)

        def fake_ots_stamp(digest_hex, ots_path):
            ots_path.write_bytes(b"fake-ots-data")
            return {"ots_file": str(ots_path), "attestations": [], "pending": True, "note": "test"}

        with patch("backend.timestamps._ots_stamp", side_effect=fake_ots_stamp):
            from backend.timestamps import stamp_certificate
            result = stamp_certificate("b" * 64, "cert-456")

    assert result["pending"] is True
    assert result["cert_id"] == "cert-456"


def test_verify_timestamp_missing_command(tmp_path):
    ots_path = tmp_path / "test.ots"
    ots_path.write_bytes(b"fake")

    with patch("subprocess.run", side_effect=FileNotFoundError):
        from backend.timestamps import verify_timestamp
        result = verify_timestamp(ots_path)

    assert result["verified"] is False
    assert "ots command not found" in result["error"]
