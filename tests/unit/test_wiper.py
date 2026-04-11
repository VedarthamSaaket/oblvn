import os
import tempfile
import pytest
from unittest.mock import patch


def test_dry_run_yields_progress():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        events = list(w.run_wipe("/dev/null", "nist_800_88", "ssd"))
        progress = [e for e in events if e.get("type") != "complete"]
        complete = [e for e in events if e.get("type") == "complete"]
        assert len(progress) > 0
        assert len(complete) == 1


def test_dry_run_overall_pct_reaches_100():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        events = list(w.run_wipe("/dev/null", "dod_5220_22m", "hdd"))
        progress = [e for e in events if e.get("type") != "complete"]
        max_pct = max(e.get("overall_pct", 0) for e in progress)
        assert max_pct > 90


def test_dry_run_dod_has_3_passes():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        events = list(w.run_wipe("/dev/null", "dod_5220_22m", "hdd"))
        complete = next(e for e in events if e.get("type") == "complete")
        assert complete["passes_completed"] == 3


def test_dry_run_gutmann_has_35_passes():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        events = list(w.run_wipe("/dev/null", "gutmann", "hdd"))
        complete = next(e for e in events if e.get("type") == "complete")
        assert complete["passes_completed"] == 35


def test_verify_overwrite_dry_run():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "1"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        assert w.verify_overwrite("/dev/null", "zero") is True


def test_verify_overwrite_real_zeros():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * (512 * 10))
            path = f.name
        try:
            assert w.verify_overwrite(path, "zero", sample_sectors=5) is True
        finally:
            os.unlink(path)


def test_verify_overwrite_detects_mismatch():
    with patch.dict(os.environ, {"OBLVN_DRY_RUN": "0"}):
        import importlib
        import backend.wiper as w
        importlib.reload(w)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * (512 * 10))
            path = f.name
        try:
            assert w.verify_overwrite(path, "zero", sample_sectors=5) is False
        finally:
            os.unlink(path)
