import os
import time
from collections.abc import Callable

CHUNK = 8 * 1024 * 1024


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    done = 0
    while done < len(view):
        done += os.write(fd, view[done:])


def overwrite_pass(
    path: str,
    size: int,
    source: Callable[[int, int], bytes],
    progress: Callable[[float, int], None],
    cancel_check: Callable[[], None],
) -> dict:
    if size <= 0:
        raise ValueError(f"refusing to overwrite {path}: size is {size}")
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    started = time.monotonic()
    written = 0
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while written < size:
            cancel_check()
            n = min(CHUNK, size - written)
            _write_all(fd, source(written, n))
            written += n
            progress(written / size * 100, written)
        os.fsync(fd)
    finally:
        os.close(fd)
    seconds = time.monotonic() - started
    return {
        "bytes": written,
        "seconds": round(seconds, 3),
        "throughput_mbps": round(written / 1e6 / seconds, 2) if seconds > 0 else None,
    }
