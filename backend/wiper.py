import os
import re
import shutil
import subprocess
import time
from collections.abc import Generator

from backend.config import config
from backend.hw.patterns import NIST_PASSES, STANDARDS, passes_for


def _is_usb_write_protected() -> bool:
    """
    Check the Windows StorageDevicePolicy registry key that silently
    write-protects ALL removable drives system-wide.
    """
    try:
        import winreg
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
DRY_RUN = config.DRY_RUN
FREE_SPACE_NOTES = [
    "fills free space on the mounted volume only",
    "existing files, filesystem metadata, slack space, the partition table, HPA/DCO areas and flash over-provisioning are not touched",
    "this is not a NIST 800-88 Clear or Purge; run OBLVN as Administrator or use the Linux agent for a device sanitize",
]


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


def run_free_space_fill(node: str, standard: str) -> Generator[dict, None, None]:
    passes = passes_for(standard)
    yield from _wipe_windows(node, passes)
    yield {
        "type": "complete",
        "ok": True,
        "technique": "free_space_fill",
        "nist_category": "none",
        "passes_completed": len(passes),
        "verification_passed": None,
        "standard": standard,
        "record": {
            "platform": "Windows",
            "technique": "free_space_fill",
            "nist_category": "none",
            "notes": FREE_SPACE_NOTES,
            "verification": {"check": "none", "passed": None, "reason": "volume-level writes cannot be read back by sector"},
        },
    }
