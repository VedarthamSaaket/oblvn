import hashlib
import json
import pytest
from unittest.mock import patch, MagicMock
from backend.reporter import _compute_hash, _get_qr_base64, _verification_method


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
    qr = _get_qr_base64("https://verify.oblvn.com/test-id")
    decoded = base64.b64decode(qr)
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_compute_hash_matches_manual_sha256():
    fields = {"a": "1", "b": "2"}
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert _compute_hash(fields) == expected


def test_verification_method_pattern():
    text = _verification_method({"check": "pattern", "mode": "sample", "samples": 4096, "mismatches": 0})
    assert "4096 blocks" in text and "0 mismatches" in text


def test_verification_method_changed_and_simulated():
    assert "indeterminate" in _verification_method({"check": "changed", "changed": 5, "unchanged": 0, "indeterminate": 2})
    assert _verification_method({"simulated": True}) == "simulated (dry run)"
    assert _verification_method(None) is None


def test_certificate_renders_single_landscape_page_with_artwork(tmp_path, monkeypatch):
    import pymupdf
    import backend.reporter as rep
    monkeypatch.setattr(rep.config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(rep, "stamp_certificate", lambda h, cid: {"pending": True})
    job = {"id": "5f1c2a9e-7d3b-4e61-9a20-8c4b1e7f3d55", "device_serial": "S" * 200, "device_model": "M" * 200,
           "device_capacity_bytes": 10 ** 12, "device_type": "nvme", "method": "crypto_erase",
           "standard": "nist_800_88", "passes_completed": 1, "verification_passed": True}
    record = {"technique": "nvme_sanitize_crypto", "nist_category": "purge",
              "verification": {"check": "changed", "changed": 10, "unchanged": 0, "indeterminate": 0, "passed": True}}
    out = rep.generate_certificate(job, {"id": "u", "email": "a@b.c"}, None, None, record)
    doc = pymupdf.open(out["pdf_path"])
    assert len(doc) == 1
    assert round(doc[0].rect.width) == 842 and round(doc[0].rect.height) == 595
    assert doc[0].get_images()
    fonts = " ".join(f[3] for f in doc[0].get_fonts())
    assert "Playfair" in fonts and "Plex-Mono" in fonts
    assert out["fields"]["nist_800_88_category"] == "purge"
