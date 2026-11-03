import os

import pytest

from backend import file_wipe
from backend.hw.model import WipeError


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("OBLVN_FILE_WIPE_ROOTS", str(tmp_path))
    return tmp_path


def test_check_path_rules(root, tmp_path_factory):
    inside = root / "a.txt"
    inside.write_text("x")
    assert file_wipe.check_path(str(inside)) == inside.resolve()
    with pytest.raises(file_wipe.PathRejected, match="absolute"):
        file_wipe.check_path("a.txt")
    with pytest.raises(file_wipe.PathRejected, match="wipe root itself"):
        file_wipe.check_path(str(root))
    outside = tmp_path_factory.mktemp("outside") / "b.txt"
    outside.write_text("y")
    with pytest.raises(file_wipe.PathRejected, match="outside"):
        file_wipe.check_path(str(outside))
    link = root / "link"
    link.symlink_to(outside)
    with pytest.raises(file_wipe.PathRejected, match="symlink"):
        file_wipe.check_path(str(link))


def test_expand_skips_symlinks(root, tmp_path_factory):
    folder = root / "dir"
    (folder / "sub").mkdir(parents=True)
    (folder / "one.bin").write_bytes(b"1")
    (folder / "sub" / "two.bin").write_bytes(b"2")
    target = tmp_path_factory.mktemp("elsewhere") / "secret"
    target.write_text("keep")
    (folder / "escape").symlink_to(target)
    files = file_wipe.expand([str(folder)])
    assert sorted(os.path.basename(f) for f in files) == ["one.bin", "two.bin"]


@pytest.mark.parametrize("method,standard", [
    ("binary_overwrite", "dod_5220_22m"), ("crypto_erase", "nist_800_88"), ("full_sanitization", "nist_800_88"),
])
def test_wipe_file_overwrites_verifies_and_deletes(root, method, standard):
    target = root / "secret.db"
    target.write_bytes(os.urandom(300_000))
    result = file_wipe.wipe_file(str(target), method, standard, lambda p, l: None, lambda: None)
    assert not target.exists()
    assert result["verification"]["passed"] is True
    assert result["bytes_written"] == 300_000 * result["passes"]
    assert list(root.iterdir()) == []


def test_wipe_file_fails_when_verification_fails(root, monkeypatch):
    target = root / "f.bin"
    target.write_bytes(os.urandom(5000))
    monkeypatch.setattr(file_wipe.verify, "check_pattern", lambda *a, **k: {"passed": False})
    with pytest.raises(WipeError, match="verification"):
        file_wipe.wipe_file(str(target), "binary_overwrite", "nist_800_88", lambda p, l: None, lambda: None)
    assert target.exists()


def test_run_file_job_record(root):
    (root / "a").write_bytes(b"a" * 10)
    (root / "b").write_bytes(b"")
    events = []
    record = file_wipe.run_file_job([str(root / "a"), str(root / "b")], "binary_overwrite", "nist_800_88",
                                    events.append, lambda: None)
    assert record["technique"] == "file_overwrite" and record["nist_category"] == "not_applicable"
    assert record["verification"]["passed"] is True and len(record["files"]) == 2
    assert not (root / "a").exists() and not (root / "b").exists()
