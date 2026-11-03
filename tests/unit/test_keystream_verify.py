import os

import pytest

from backend.hw import verify
from backend.hw.keystream import Keystream, source_for, tiled
from backend.hw.model import Cancelled
from backend.hw.overwrite import overwrite_pass


def test_keystream_is_offset_addressable():
    ks = Keystream()
    whole = ks.at(0, 4096)
    assert ks.at(16, 32) == whole[16:48]
    assert ks.at(5, 11) == whole[5:16]
    assert ks.at(4000, 96) == whole[4000:]


def test_keystream_destroy():
    ks = Keystream()
    assert not ks.destroyed
    ks.destroy()
    assert ks.destroyed


def test_tiled_pattern_is_continuous():
    unit = bytes([1, 2, 3])
    assert tiled(unit, 0, 7) == bytes([1, 2, 3, 1, 2, 3, 1])
    assert tiled(unit, 4, 4) == bytes([2, 3, 1, 2])


def _device(tmp_path, size):
    path = tmp_path / "device.img"
    path.write_bytes(os.urandom(size))
    return str(path)


def test_overwrite_then_sample_and_full_verify(tmp_path):
    size = 3 * 1024 * 1024 + 512
    path = _device(tmp_path, size)
    source, ks = source_for({"pattern": "random"})
    result = overwrite_pass(path, size, source, lambda pct, w: None, lambda: None)
    assert result["bytes"] == size
    assert verify.check_pattern(path, size, verify.sample_offsets(size, 64), source)["passed"]
    assert verify.check_pattern(path, size, None, source)["passed"]
    with open(path, "r+b") as f:
        f.seek(size - 100)
        f.write(b"\x00" * 10)
    full = verify.check_pattern(path, size, None, source)
    assert not full["passed"] and full["mismatches"] == 1
    ks.destroy()


def test_check_changed_reports_unchanged_and_indeterminate(tmp_path):
    size = 64 * 4096
    path = tmp_path / "device.img"
    data = bytearray(os.urandom(size))
    data[0:4096] = bytes(4096)
    path.write_bytes(bytes(data))
    offsets = [0, 4096, 8192]
    before = verify.snapshot(str(path), size, offsets)
    assert verify.check_changed(str(path), size, before)["unchanged"] == 2
    with open(path, "r+b") as f:
        f.seek(4096)
        f.write(os.urandom(8192))
    result = verify.check_changed(str(path), size, before)
    assert result == {**result, "changed": 2, "unchanged": 0, "indeterminate": 1, "passed": True}


def test_overwrite_honours_cancel(tmp_path):
    size = 32 * 1024 * 1024
    path = _device(tmp_path, size)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        if calls["n"] > 1:
            raise Cancelled("stop")
    with pytest.raises(Cancelled):
        overwrite_pass(path, size, source_for({"pattern": "zero"})[0], lambda p, w: None, cancel)


def test_overwrite_refuses_zero_size(tmp_path):
    with pytest.raises(ValueError):
        overwrite_pass(str(tmp_path / "x"), 0, lambda o, n: b"", lambda p, w: None, lambda: None)
