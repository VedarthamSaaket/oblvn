import hashlib
import mmap
import os
import platform
import random
import secrets
import subprocess
from collections.abc import Callable

BLOCK = 4096
FULL_READ = 1024 * 1024
SYSTEM = platform.system()


class Reader:
    def __init__(self, path: str):
        self.path = path
        self.direct = False
        self.fd = self._open()
        self.buf = mmap.mmap(-1, FULL_READ)

    def _open(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        direct = getattr(os, "O_DIRECT", 0)
        if direct:
            try:
                fd = os.open(self.path, flags | direct)
                self.direct = True
                return fd
            except OSError:
                pass
        fd = os.open(self.path, flags)
        if SYSTEM == "Darwin":
            import fcntl
            if hasattr(fcntl, "F_NOCACHE"):
                fcntl.fcntl(fd, fcntl.F_NOCACHE, 1)
        if hasattr(os, "posix_fadvise"):
            try:
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            except OSError:
                pass
        return fd

    def read(self, offset: int, length: int) -> bytes:
        if self.direct:
            aligned = (length + BLOCK - 1) // BLOCK * BLOCK
            view = memoryview(self.buf)[:aligned]
            got = os.preadv(self.fd, [view], offset)
            return bytes(view[:min(got, length)])
        os.lseek(self.fd, offset, os.SEEK_SET)
        out = b""
        while len(out) < length:
            chunk = os.read(self.fd, length - len(out))
            if not chunk:
                break
            out += chunk
        return out

    def close(self) -> None:
        os.close(self.fd)
        self.buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def flush_device_cache(path: str) -> None:
    if SYSTEM == "Linux" and path.startswith("/dev/"):
        subprocess.run(["blockdev", "--flushbufs", path], capture_output=True, timeout=30)


def sample_offsets(size: int, count: int = 4096, seed: int | None = None) -> list[int]:
    blocks = max(1, (size + BLOCK - 1) // BLOCK)
    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    picks = {0, blocks - 1}
    while len(picks) < min(count, blocks):
        picks.add(rng.randrange(blocks))
    return sorted(b * BLOCK for b in picks)


def _length(size: int, offset: int) -> int:
    return min(BLOCK, size - offset)


def _uniform(data: bytes) -> bool:
    return bool(data) and data.count(data[:1]) == len(data)


def snapshot(path: str, size: int, offsets: list[int]) -> dict[int, dict]:
    flush_device_cache(path)
    out = {}
    with Reader(path) as r:
        for off in offsets:
            data = r.read(off, _length(size, off))
            out[off] = {"sha256": hashlib.sha256(data).hexdigest(), "uniform": _uniform(data)}
    return out


def check_pattern(path: str, size: int, offsets: list[int] | None,
                  expected: Callable[[int, int], bytes]) -> dict:
    flush_device_cache(path)
    mismatches = 0
    first = None
    checked = 0
    with Reader(path) as r:
        if offsets is None:
            off = 0
            while off < size:
                n = min(FULL_READ, size - off)
                if r.read(off, n) != expected(off, n):
                    mismatches += 1
                    first = off if first is None else first
                checked += 1
                off += n
        else:
            for off in offsets:
                n = _length(size, off)
                if r.read(off, n) != expected(off, n):
                    mismatches += 1
                    first = off if first is None else first
                checked += 1
    return {
        "check": "pattern",
        "mode": "full" if offsets is None else "sample",
        "samples": checked,
        "mismatches": mismatches,
        "first_mismatch_offset": first,
        "passed": mismatches == 0 and checked > 0,
    }


def check_changed(path: str, size: int, before: dict[int, dict]) -> dict:
    flush_device_cache(path)
    changed = unchanged = indeterminate = 0
    with Reader(path) as r:
        for off, prior in before.items():
            digest = hashlib.sha256(r.read(off, _length(size, off))).hexdigest()
            if digest != prior["sha256"]:
                changed += 1
            elif prior["uniform"]:
                indeterminate += 1
            else:
                unchanged += 1
    if unchanged:
        passed = False
    elif changed:
        passed = True
    else:
        passed = None
    return {
        "check": "changed",
        "mode": "sample",
        "samples": len(before),
        "changed": changed,
        "unchanged": unchanged,
        "indeterminate": indeterminate,
        "passed": passed,
    }
