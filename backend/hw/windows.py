import ctypes
import re
import subprocess

from backend.hw.model import Disk, WipeError


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ps(script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def disk_index(node: str) -> int:
    m = re.search(r"PhysicalDrive(\d+)$", node)
    if not m:
        raise WipeError(f"cannot read a disk number from {node}")
    return int(m.group(1))


def boot_disks() -> set[int]:
    r = _ps("Get-Disk | Where-Object { $_.IsBoot -or $_.IsSystem } | Select-Object -ExpandProperty Number")
    return {int(x) for x in r.stdout.split() if x.strip().isdigit()}


def exact_size(index: int) -> int:
    r = _ps(f"(Get-Disk -Number {index}).Size")
    try:
        return int(r.stdout.strip())
    except ValueError:
        raise WipeError(f"cannot read the size of disk {index}")


def prepare(disk: Disk) -> tuple[Disk, list[dict]]:
    if not is_admin():
        raise WipeError("raw device wipes on Windows need an Administrator terminal")
    index = disk_index(disk.node)
    if index in boot_disks():
        raise WipeError(f"refusing to wipe disk {index}: it hosts the Windows boot or system volume")
    script = (
        f"Set-Disk -Number {index} -IsReadOnly $false -ErrorAction SilentlyContinue; "
        f"Set-Disk -Number {index} -IsOffline $false -ErrorAction SilentlyContinue; "
        f"Clear-Disk -Number {index} -RemoveData -RemoveOEM -Confirm:$false"
    )
    r = _ps(script, timeout=300)
    record = {"cmd": script, "exit_code": r.returncode, "stdout": r.stdout[-2000:], "stderr": r.stderr[-2000:]}
    if r.returncode != 0 and "has not been initialized" not in r.stderr:
        raise WipeError(f"Clear-Disk failed on disk {index}: {r.stderr.strip()[:300]}")
    disk.size_bytes = exact_size(index)
    return disk, [record]
