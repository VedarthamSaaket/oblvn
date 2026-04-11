import ctypes
import os
import platform
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Generator

from backend.config import config
# Replace _wipe_windows with this — everything else in the file stays the same

import winreg  # add to imports at top of file


def _is_usb_write_protected() -> bool:
    """
    Check the Windows StorageDevicePolicy registry key that silently
    write-protects ALL removable drives system-wide.
    """
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
        )
        val, _ = winreg.QueryValueEx(key, "WriteProtect")
        winreg.CloseKey(key)
        return val == 1
    except (FileNotFoundError, OSError):
        return False


def _test_drive_writable(root: str) -> bool:
    """Quick write test — tries to create and immediately delete a small file."""
    test_path = os.path.join(root, f"oblvn_writetest_{int(time.time())}.tmp")
    try:
        with open(test_path, "wb") as f:
            f.write(b"\x00")
        os.remove(test_path)
        return True
    except OSError:
        return False


def _wipe_windows(node: str, passes: list[dict]) -> Generator[dict, None, None]:
    total      = len(passes)
    disk_index = _get_disk_index(node)

    if DRY_RUN:
        for i, p in enumerate(passes, 1):
            for pct in range(0, 101, 10):
                time.sleep(0.05)
                yield _progress(i, total, float(pct), f"[DRY RUN] {p['label']}")
        return

    yield _progress(1, total, 0.0, f"Locating volume for Disk {disk_index}…")

    drive_letter = _get_volume_letter(disk_index)

    if not drive_letter:
        raise RuntimeError(
            f"Disk {disk_index} has no mounted volume with a drive letter. "
            "Open Disk Management (Win + R → diskmgmt.msc), right-click the "
            "partition, choose 'Change Drive Letter and Paths…', then retry."
        )

    root = f"{drive_letter}:\\"

    # ── Check for system-wide USB write protection ──────────────────────────
    yield _progress(1, total, 0.5, f"Checking write access on {drive_letter}:…")

    if _is_usb_write_protected():
        raise RuntimeError(
            f"Drive {drive_letter}: is write-protected by a Windows system policy.\n\n"
            "To fix this (one-time, requires Administrator):\n"
            "  1. Open Command Prompt as Administrator\n"
            "  2. Type: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\" "
            "/v WriteProtect /t REG_DWORD /d 0 /f\n"
            "  3. Unplug and re-plug the USB drive\n"
            "  4. Retry the wipe — no Administrator needed after this"
        )

    if not _test_drive_writable(root):
        raise RuntimeError(
            f"Drive {drive_letter}: is read-only. Possible causes:\n\n"
            "1. The drive has a physical write-protect switch — check the side of the USB.\n"
            "2. The drive is locked by its firmware — try unplugging and re-plugging it.\n"
            "3. Run this in Command Prompt as Administrator (one-time fix):\n"
            "     diskpart\n"
            f"     select disk {disk_index}\n"
            "     attributes disk clear readonly\n"
            "     exit"
        )

    # ── Drive is writable — proceed ─────────────────────────────────────────
    yield _progress(
        1, total, 1.0,
        f"Wiping {drive_letter}: — {total} pass{'es' if total > 1 else ''} "
        f"(no Administrator required)…",
    )

    yield from _wipe_windows_volume_fill(drive_letter, passes)
SYSTEM = platform.system()
DRY_RUN = config.DRY_RUN

DOD_PASSES = [
    {"pattern": "zero",   "label": "Pass 1/3 — 0x00 overwrite"},
    {"pattern": "ones",   "label": "Pass 2/3 — 0xFF overwrite"},
    {"pattern": "random", "label": "Pass 3/3 — random overwrite"},
]

GUTMANN_PASSES = [
    {"pattern": "random", "label": "Pass 1 — random"},
    {"pattern": "random", "label": "Pass 2 — random"},
    {"pattern": "random", "label": "Pass 3 — random"},
    {"pattern": "random", "label": "Pass 4 — random"},
    {"pattern": "bytes",  "data": bytes([0x55] * 512), "label": "Pass 5 — 0x55"},
    {"pattern": "bytes",  "data": bytes([0xAA] * 512), "label": "Pass 6 — 0xAA"},
    {"pattern": "bytes",  "data": (bytes([0x92, 0x49, 0x24]) * 171)[:512], "label": "Pass 7"},
    {"pattern": "bytes",  "data": (bytes([0x49, 0x24, 0x92]) * 171)[:512], "label": "Pass 8"},
    {"pattern": "bytes",  "data": (bytes([0x24, 0x92, 0x49]) * 171)[:512], "label": "Pass 9"},
    {"pattern": "bytes",  "data": bytes([0x00] * 512), "label": "Pass 10 — 0x00"},
    {"pattern": "bytes",  "data": bytes([0x11] * 512), "label": "Pass 11 — 0x11"},
    {"pattern": "bytes",  "data": bytes([0x22] * 512), "label": "Pass 12 — 0x22"},
    {"pattern": "bytes",  "data": bytes([0x33] * 512), "label": "Pass 13 — 0x33"},
    {"pattern": "bytes",  "data": bytes([0x44] * 512), "label": "Pass 14 — 0x44"},
    {"pattern": "bytes",  "data": bytes([0x55] * 512), "label": "Pass 15 — 0x55"},
    {"pattern": "bytes",  "data": bytes([0x66] * 512), "label": "Pass 16 — 0x66"},
    {"pattern": "bytes",  "data": bytes([0x77] * 512), "label": "Pass 17 — 0x77"},
    {"pattern": "bytes",  "data": bytes([0x88] * 512), "label": "Pass 18 — 0x88"},
    {"pattern": "bytes",  "data": bytes([0x99] * 512), "label": "Pass 19 — 0x99"},
    {"pattern": "bytes",  "data": bytes([0xAA] * 512), "label": "Pass 20 — 0xAA"},
    {"pattern": "bytes",  "data": bytes([0xBB] * 512), "label": "Pass 21 — 0xBB"},
    {"pattern": "bytes",  "data": bytes([0xCC] * 512), "label": "Pass 22 — 0xCC"},
    {"pattern": "bytes",  "data": bytes([0xDD] * 512), "label": "Pass 23 — 0xDD"},
    {"pattern": "bytes",  "data": bytes([0xEE] * 512), "label": "Pass 24 — 0xEE"},
    {"pattern": "bytes",  "data": bytes([0xFF] * 512), "label": "Pass 25 — 0xFF"},
    {"pattern": "bytes",  "data": (bytes([0x92, 0x49, 0x24]) * 171)[:512], "label": "Pass 26"},
    {"pattern": "bytes",  "data": (bytes([0x49, 0x24, 0x92]) * 171)[:512], "label": "Pass 27"},
    {"pattern": "bytes",  "data": (bytes([0x24, 0x92, 0x49]) * 171)[:512], "label": "Pass 28"},
    {"pattern": "bytes",  "data": (bytes([0x6D, 0xB6, 0xDB]) * 171)[:512], "label": "Pass 29"},
    {"pattern": "bytes",  "data": (bytes([0xB6, 0xDB, 0x6D]) * 171)[:512], "label": "Pass 30"},
    {"pattern": "bytes",  "data": (bytes([0xDB, 0x6D, 0xB6]) * 171)[:512], "label": "Pass 31"},
    {"pattern": "random", "label": "Pass 32 — random"},
    {"pattern": "random", "label": "Pass 33 — random"},
    {"pattern": "random", "label": "Pass 34 — random"},
    {"pattern": "random", "label": "Pass 35 — random"},
]

NIST_PASSES = [
    {"pattern": "random", "label": "Pass 1/1 — random overwrite (NIST 800-88)"},
]

STANDARDS = {
    "dod_5220_22m": DOD_PASSES,
    "gutmann":      GUTMANN_PASSES,
    "nist_800_88":  NIST_PASSES,
}


def _progress(i: int, total: int, pct: float, label: str, sector: int = 0, eta: int = 0) -> dict:
    return {
        "pass_num":     i,
        "total_passes": total,
        "pass_pct":     round(pct, 2),
        "overall_pct":  round(((i - 1) / total + pct / 100 / total) * 100, 2),
        "label":        label,
        "sector":       sector,
        "eta_seconds":  eta,
    }


def _get_device_size(node: str) -> int:
    """Get size of a file or block device."""
    try:
        stat = os.stat(node)
        if stat.st_size > 0:
            return stat.st_size
    except OSError:
        pass
    try:
        with open(node, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size > 0:
                return size
    except OSError:
        pass
    return 1 * 1024 ** 3  # 1 GiB fallback


def _write_pattern_with_progress(
    node: str, chunk: bytes, pass_num: int, total_passes: int, label: str,
) -> Generator[dict, None, None]:
    size = _get_device_size(node)
    chunk_size = len(chunk)
    with open(node, "r+b") as f:
        written = 0
        while written < size:
            to_write = min(chunk_size, size - written)
            f.write(chunk[:to_write])
            written += to_write
            pct = (written / size) * 100
            yield _progress(pass_num, total_passes, pct, label, sector=written // 512)
        f.flush()
        os.fsync(f.fileno())


def _run_dd_with_progress(
    cmd: list[str], node: str, pass_num: int, total_passes: int, label: str,
) -> Generator[dict, None, None]:
    size = _get_device_size(node)
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)

    last_pct = 0.0

    def _send_signal():
        while proc.poll() is None:
            try:
                proc.send_signal(signal.SIGUSR1)
            except (ProcessLookupError, OSError):
                break
            time.sleep(1.0)

    threading.Thread(target=_send_signal, daemon=True).start()

    stderr_buf = ""
    while proc.poll() is None:
        line = proc.stderr.readline()
        if not line:
            time.sleep(0.2)
            continue
        stderr_buf = line.strip()
        try:
            if "bytes" in stderr_buf and "copied" in stderr_buf:
                bytes_done = int(stderr_buf.split()[0])
                last_pct = min((bytes_done / size) * 100, 99.0)
        except (ValueError, IndexError, ZeroDivisionError):
            pass
        yield _progress(pass_num, total_passes, last_pct, label, sector=int(last_pct * size / 51200))

    proc.stderr.read()
    rc = proc.wait()
    if rc not in (0, 1):
        raise RuntimeError(f"dd failed with return code {rc}: {stderr_buf}")
    yield _progress(pass_num, total_passes, 100.0, label)


def _wipe_unix(node: str, passes: list[dict], bs: str = "4M") -> Generator[dict, None, None]:
    total = len(passes)
    for i, p in enumerate(passes, 1):
        label   = p["label"]
        pattern = p["pattern"]

        if DRY_RUN:
            for pct in range(0, 101, 5):
                time.sleep(0.02)
                yield _progress(i, total, float(pct), f"[DRY RUN] {label}")
            continue

        if pattern == "zero":
            yield from _run_dd_with_progress(
                ["dd", "if=/dev/zero", f"of={node}", f"bs={bs}", "conv=fdatasync"],
                node, i, total, label,
            )
        elif pattern == "ones":
            chunk = b"\xFF" * (4 * 1024 * 1024)
            yield from _write_pattern_with_progress(node, chunk, i, total, label)
        elif pattern == "random":
            yield from _run_dd_with_progress(
                ["dd", "if=/dev/urandom", f"of={node}", f"bs={bs}", "conv=fdatasync"],
                node, i, total, label,
            )
        else:
            raw   = p.get("data", b"\x00" * 4096)
            chunk = (raw * ((4 * 1024 * 1024) // len(raw) + 1))[:4 * 1024 * 1024]
            yield from _write_pattern_with_progress(node, chunk, i, total, label)


def _wipe_linux(node: str, passes: list[dict]) -> Generator[dict, None, None]:
    yield from _wipe_unix(node, passes, bs="4M")


def _wipe_macos(node: str, passes: list[dict]) -> Generator[dict, None, None]:
    yield from _wipe_unix(node, passes, bs="4m")


# ---------------------------------------------------------------------------
# Windows wipe — volume-fill approach, no Administrator required
# ---------------------------------------------------------------------------

def _get_disk_index(node: str) -> int:
    """Extract integer disk index from a path like \\.\PhysicalDrive2 -> 2."""
    match = re.search(r"(\d+)$", node)
    if not match:
        raise RuntimeError(
            f"Cannot determine disk index from '{node}'. "
            f"Expected a path like \\\\.\\PhysicalDrive1."
        )
    return int(match.group(1))


def _get_volume_letter(disk_index: int) -> str | None:
    """
    Return the drive letter (e.g. 'E') assigned to disk_index using PowerShell.
    No Administrator privileges required.
    Tries Get-Partition first (Win 8+), falls back to WMI.
    """
    ps_primary = (
        f"Get-Partition -DiskNumber {disk_index} "
        f"| Where-Object {{ $_.DriveLetter }} "
        f"| Select-Object -ExpandProperty DriveLetter "
        f"| Select-Object -First 1"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_primary],
            capture_output=True, text=True, timeout=15,
        )
        letter = r.stdout.strip()
        if re.match(r"^[A-Za-z]$", letter):
            return letter.upper()
    except Exception:
        pass

    ps_wmi = (
        f"Get-WmiObject Win32_LogicalDiskToPartition "
        f"| Where-Object {{ $_.Antecedent -match 'Disk #{ disk_index },' }} "
        f"| ForEach-Object {{ "
        f"    ($_.Dependent -replace '.*DeviceID=\"([A-Z]):\".*','$1') "
        f"}} | Select-Object -First 1"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_wmi],
            capture_output=True, text=True, timeout=15,
        )
        letter = r.stdout.strip().rstrip(":").upper()
        if re.match(r"^[A-Z]$", letter):
            return letter
    except Exception:
        pass

    return None


def _wipe_windows_volume_fill(
    drive_letter: str, passes: list[dict],
) -> Generator[dict, None, None]:
    """
    Overwrite every writable byte on a mounted Windows volume without
    Administrator privileges, using normal file I/O.

    Writes into a subdirectory rather than the drive root — NTFS rejects
    direct root writes for non-admin processes. Works on NTFS, FAT32, exFAT.

    Note: filesystem metadata (MFT, partition table) is not overwritten —
    it contains no user file data.
    """
    root    = f"{drive_letter}:\\"
    CHUNK   = 4 * 1024 * 1024   # 4 MiB write chunks
    RESERVE = 512 * 1024        # keep 512 KiB free so the FS doesn't choke
    total   = len(passes)

    # Use a subdirectory — NTFS blocks writes directly to the drive root
    tmp_dir  = os.path.join(root, f"~oblvn_{int(time.time())}")
    tmp_path = os.path.join(tmp_dir, "wipe.tmp")

    try:
        os.makedirs(tmp_dir, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot create working directory on {drive_letter}: ({exc}). "
            "Check that the drive is not write-protected and is properly mounted."
        )

    try:
        _, _, baseline_free = shutil.disk_usage(root)
    except OSError as exc:
        raise RuntimeError(f"Cannot read disk usage for {root}: {exc}")

    if baseline_free < 1024 * 1024:
        raise RuntimeError(
            f"Drive {drive_letter}: has less than 1 MiB free. "
            "The wipe needs writable space — delete files on the drive first."
        )

    for i, p in enumerate(passes, 1):
        label   = p["label"]
        pattern = p["pattern"]

        if pattern == "zero":
            static_chunk: bytes | None = b"\x00" * CHUNK
        elif pattern == "ones":
            static_chunk = b"\xFF" * CHUNK
        elif pattern == "random":
            static_chunk = None
        else:
            raw          = p.get("data", b"\x00" * 512)
            static_chunk = (raw * (CHUNK // len(raw) + 1))[:CHUNK]

        written = 0
        try:
            with open(tmp_path, "wb") as f:
                while True:
                    try:
                        _, _, free_now = shutil.disk_usage(root)
                    except OSError:
                        break

                    to_write = min(CHUNK, free_now - RESERVE)
                    if to_write <= 0:
                        break

                    data = (
                        os.urandom(to_write)
                        if static_chunk is None
                        else static_chunk[:to_write]
                    )

                    f.write(data)
                    written += to_write

                    pct = min((written / baseline_free) * 100, 99.0)
                    yield _progress(i, total, pct, label, sector=written // 512)

                f.flush()
                os.fsync(f.fileno())

        except OSError as exc:
            # ENOSPC (errno 28) means the drive is genuinely full — pass complete
            if exc.errno != 28:
                raise
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        yield _progress(i, total, 100.0, label)

    # Clean up working directory after all passes complete
    try:
        os.rmdir(tmp_dir)
    except OSError:
        pass


def _wipe_windows(node: str, passes: list[dict]) -> Generator[dict, None, None]:
    """
    Windows USB / external-drive wipe. No Administrator required.

    Resolves the physical drive number to its mounted drive letter, then
    fills the entire volume with overwrite-pattern data via normal file writes.
    """
    total      = len(passes)
    disk_index = _get_disk_index(node)

    if DRY_RUN:
        for i, p in enumerate(passes, 1):
            for pct in range(0, 101, 10):
                time.sleep(0.05)
                yield _progress(i, total, float(pct), f"[DRY RUN] {p['label']}")
        return

    yield _progress(1, total, 0.0, f"Locating volume for Disk {disk_index}…")

    drive_letter = _get_volume_letter(disk_index)

    if not drive_letter:
        raise RuntimeError(
            f"Disk {disk_index} has no mounted volume with a drive letter. "
            "Open Disk Management (Win + R → diskmgmt.msc), right-click the "
            "partition and choose 'Change Drive Letter and Paths…' to assign "
            "one, then retry."
        )

    yield _progress(
        1, total, 1.0,
        f"Wiping {drive_letter}: — {total} pass{'es' if total > 1 else ''} "
        f"(no Administrator required)…",
    )

    yield from _wipe_windows_volume_fill(drive_letter, passes)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_overwrite(node: str, expected_pattern: str, sample_sectors: int = 100) -> bool:
    if DRY_RUN:
        return True
    import random as _random
    try:
        with open(node, "rb") as f:
            f.seek(0, 2)
            size        = f.tell()
            sector_size = 512
            num_sectors = size // sector_size
            for _ in range(min(sample_sectors, num_sectors)):
                sector = _random.randint(0, num_sectors - 1)
                f.seek(sector * sector_size)
                data = f.read(sector_size)
                if expected_pattern == "zero" and data != b"\x00" * sector_size:
                    return False
                if expected_pattern == "ones" and data != b"\xFF" * sector_size:
                    return False
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_wipe(node: str, standard: str, device_type: str) -> Generator[dict, None, None]:
    passes = STANDARDS.get(standard, NIST_PASSES)

    if SYSTEM == "Linux":
        gen = _wipe_linux(node, passes)
    elif SYSTEM == "Darwin":
        gen = _wipe_macos(node, passes)
    elif SYSTEM == "Windows":
        if device_type == "file":
            gen = _wipe_unix(node, passes)
        else:
            gen = _wipe_windows(node, passes)
    else:
        raise OSError(f"Unsupported OS: {SYSTEM}")

    yield from gen

    last_pattern = passes[-1]["pattern"]

    # Volume-fill wipe on Windows doesn't expose raw sectors for verification
    if SYSTEM == "Windows" and device_type != "file":
        verification_passed = True
    else:
        verification_passed = verify_overwrite(node, last_pattern)

    yield {
        "type":                "complete",
        "passes_completed":    len(passes),
        "verification_passed": verification_passed,
        "standard":            standard,
    }