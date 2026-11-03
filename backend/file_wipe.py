import os
import secrets
import time
from collections.abc import Callable
from pathlib import Path

from backend.config import config
from backend.hw import verify
from backend.hw.keystream import source_for
from backend.hw.model import WipeError
from backend.hw.overwrite import overwrite_pass
from backend.hw.patterns import NIST_PASSES, passes_for
from backend.platform_env import PROJECT_ROOT

FILE_NOTES = [
    "file-level overwrite of the file's current extents",
    "copies held in filesystem snapshots, copy-on-write extents, journals or flash spare blocks are not reached",
]


class PathRejected(ValueError):
    pass


def _invoking_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (ImportError, KeyError):
            pass
    return Path.home()


def allowed_roots() -> list[Path]:
    raw = os.environ.get("OBLVN_FILE_WIPE_ROOTS", "")
    roots = [Path(r).expanduser() for r in raw.split(os.pathsep) if r.strip()]
    return [r.resolve() for r in (roots or [_invoking_home()])]


def _forbidden() -> list[Path]:
    return [PROJECT_ROOT.resolve(), config.DATA_DIR.resolve()]


def check_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        raise PathRejected(f"{raw}: only absolute paths can be wiped")
    if path.is_symlink():
        raise PathRejected(f"{raw}: symlinks are not followed")
    try:
        real = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise PathRejected(f"{raw}: not found")
    roots = allowed_roots()
    if not any(real.is_relative_to(r) for r in roots):
        raise PathRejected(f"{raw}: outside the allowed wipe roots ({', '.join(map(str, roots))})")
    if real in roots:
        raise PathRejected(f"{raw}: a wipe root itself cannot be wiped")
    if any(real == f or real.is_relative_to(f) for f in _forbidden()):
        raise PathRejected(f"{raw}: OBLVN's own files cannot be wiped")
    return real


def expand(paths: list[str]) -> list[str]:
    files: list[str] = []
    for raw in paths:
        real = check_path(raw)
        if real.is_dir():
            for root, dirs, names in os.walk(real, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for name in names:
                    full = os.path.join(root, name)
                    if not os.path.islink(full) and os.path.isfile(full):
                        files.append(full)
        elif real.is_file():
            files.append(str(real))
    return sorted(set(files))


def _passes(method: str, standard: str) -> list[dict]:
    if method == "crypto_erase":
        return NIST_PASSES
    return passes_for(standard)


def _destroy_name(path: str) -> None:
    target = os.path.join(os.path.dirname(path), secrets.token_hex(16))
    os.rename(path, target)
    with open(target, "r+b") as f:
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())
    os.remove(target)


def wipe_file(path: str, method: str, standard: str,
              progress: Callable[[float, str], None], cancel_check: Callable[[], None]) -> dict:
    size = os.path.getsize(path)
    passes = _passes(method, standard)
    verify_mode = "full" if method == "full_sanitization" else "sample"
    started = time.monotonic()
    written = 0
    keystreams = []
    last_source = None
    try:
        if size > 0:
            for i, p in enumerate(passes):
                source, ks = source_for(p)
                if ks:
                    keystreams.append(ks)
                last_source = source
                label = f"{p['label']}"
                result = overwrite_pass(
                    path, size, source,
                    lambda pct, _w, i=i, label=label: progress((i + pct / 100) / (len(passes) + 0.2) * 100, label),
                    cancel_check,
                )
                written += result["bytes"]
            offsets = None if verify_mode == "full" else verify.sample_offsets(size, count=256)
            verification = verify.check_pattern(path, size, offsets, last_source)
        else:
            verification = {"check": "empty", "passed": True, "samples": 0}
    finally:
        for ks in keystreams:
            ks.destroy()
    if verification["passed"] is False:
        raise WipeError(f"read-back verification failed for {path}")
    _destroy_name(path)
    progress(100.0, "deleted")
    seconds = time.monotonic() - started
    return {
        "path": path,
        "size": size,
        "passes": len(passes),
        "bytes_written": written,
        "seconds": round(seconds, 3),
        "verification": verification,
    }


def run_file_job(paths: list[str], method: str, standard: str,
                 emit: Callable[[dict], None], cancel_check: Callable[[], None],
                 dry_run: bool = False) -> dict:
    files = expand(paths)
    if not files:
        raise WipeError("no files found at the selected paths")
    total = len(files)
    results = []
    skipped = []
    started = time.monotonic()
    last_emit = [0.0]

    for idx, path in enumerate(files, 1):
        cancel_check()
        if not os.path.exists(path):
            skipped.append(path)
            emit({"type": "warning", "message": f"Skipped (not found): {path}", "file_index": idx, "file_total": total})
            continue

        def progress(pct: float, label: str, idx=idx, path=path) -> None:
            now = time.monotonic()
            if pct < 100 and now - last_emit[0] < 0.5:
                return
            last_emit[0] = now
            emit({
                "type": "progress",
                "phase": "file",
                "file_index": idx,
                "file_total": total,
                "file_path": path,
                "pass_num": idx,
                "total_passes": total,
                "pass_pct": round(pct, 2),
                "overall_pct": round(((idx - 1) / total + pct / 100 / total) * 100, 2),
                "label": f"[{idx}/{total}] {label}",
            })

        if dry_run:
            for pct in range(0, 101, 20):
                time.sleep(0.01)
                progress(float(pct), "[DRY RUN] overwrite")
            results.append({"path": path, "size": os.path.getsize(path), "simulated": True,
                            "verification": {"passed": True, "simulated": True}})
            continue
        results.append(wipe_file(path, method, standard, progress, cancel_check))

    if not results:
        raise WipeError("every selected file disappeared before the wipe started")
    seconds = time.monotonic() - started
    written = sum(r.get("bytes_written", 0) for r in results)
    return {
        "technique": "file_overwrite",
        "nist_category": "not_applicable",
        "method": method,
        "standard": standard,
        "dry_run": dry_run,
        "files": results,
        "skipped": skipped,
        "notes": FILE_NOTES,
        "passes_completed": len(_passes(method, standard)),
        "verification": {
            "check": "pattern",
            "mode": "full" if method == "full_sanitization" else "sample",
            "files": len(results),
            "samples": sum((r["verification"] or {}).get("samples", 0) for r in results),
            "passed": all((r["verification"] or {}).get("passed") for r in results),
        },
        "telemetry": {
            "size_bytes": sum(r["size"] for r in results),
            "bytes_written": written,
            "overwrite_seconds": round(seconds, 3),
            "total_seconds": round(seconds, 3),
            "throughput_mbps": round(written / 1e6 / seconds, 2) if seconds > 0 and written else None,
            "overwrite_passes": len(_passes(method, standard)),
        },
    }
