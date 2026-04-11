import os
import tempfile
import pytest
from unittest.mock import patch


def test_generate_key_length():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        from backend.crypto_erase import generate_key
        key = generate_key()
        assert len(key) == 32


def test_generate_key_unique():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        from backend.crypto_erase import generate_key
        assert generate_key() != generate_key()


def test_destroy_key_zeroes_memory():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        from backend.crypto_erase import generate_key, destroy_key
        key = generate_key()
        assert len(key) == 32
        destroy_key(key)


def test_encrypt_device_dry_run():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.crypto_erase as ce
        importlib.reload(ce)
        key = ce.generate_key()
        events = []
        result = ce.encrypt_device("/dev/null", key, progress_cb=lambda p, l: events.append(p))
        assert result["dry_run"] is True
        assert result["encrypted"] is True
        assert len(events) > 0


def test_run_crypto_erase_dry_run_returns_key():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.crypto_erase as ce
        importlib.reload(ce)
        result = ce.run_crypto_erase("/dev/null")
        assert "key_displayed_once" in result
        assert len(result["key_displayed_once"]) == 64
        assert result["method"] == "aes_256_cbc"
        assert result["fips_140_2"] is True


def test_encrypt_real_file():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        import importlib
        import backend.crypto_erase as ce
        importlib.reload(ce)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 1024)
            path = f.name
        try:
            key = ce.generate_key()
            result = ce.encrypt_device(path, key)
            assert result["encrypted"] is True
            assert result["dry_run"] is False
            with open(path, "rb") as f:
                data = f.read()
            assert data != b"A" * 1024
        finally:
            os.unlink(path)
