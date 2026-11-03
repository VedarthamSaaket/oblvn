import os
import platform

from backend.hw.inventory import find_disk
from backend.hw.model import Disk, WipeError
from backend.hw.runner import run

SYSTEM = platform.system()


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise WipeError("hardware wipes must run as root (sudo)")


def _unmount(disk: Disk) -> list[dict]:
    records = []
    if SYSTEM == "Darwin":
        r = run(["diskutil", "unmountDisk", "force", disk.node], timeout=60)
        records.append(r.record())
        if r.code != 0:
            raise WipeError(f"could not unmount {disk.node}: {(r.err or r.out).strip()[:300]}")
        return records
    for mount in sorted(disk.mountpoints, key=len, reverse=True):
        r = run(["umount", mount], timeout=60)
        records.append(r.record())
        if r.code != 0:
            raise WipeError(f"could not unmount {mount}: {(r.err or r.out).strip()[:300]}")
    return records


def check(node: str) -> tuple[Disk, list[dict]]:
    require_root()
    disk = find_disk(node)
    if disk is None:
        raise WipeError(f"{node} is no longer attached")
    if disk.is_system:
        raise WipeError(f"refusing to wipe {node}: it {disk.system_reason}")
    if disk.holders:
        raise WipeError(f"{node} is in use by {', '.join(disk.holders)}; close LVM, dm-crypt or RAID first")
    records = _unmount(disk) if disk.mountpoints or SYSTEM == "Darwin" else []
    again = find_disk(node)
    if again is None:
        raise WipeError(f"{node} disappeared after unmount")
    if SYSTEM == "Linux" and again.mountpoints:
        raise WipeError(f"{node} is still mounted at {', '.join(again.mountpoints)}")
    if again.is_system:
        raise WipeError(f"refusing to wipe {node}: it {again.system_reason}")
    return again, records
