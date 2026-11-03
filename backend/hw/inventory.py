import os
import platform
import plistlib
import re

from backend.hw.model import Disk
from backend.hw.runner import ToolError, run

SYSTEM = platform.system()
SYSTEM_MOUNTS = {"/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home", "[SWAP]"}
LIVE_PREFIXES = ("/run/live", "/lib/live", "/cdrom", "/run/initramfs")
HOLDER_TYPES = {"lvm", "crypt", "dm", "mpath", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "md"}
TRANSPORTS = {"nvme": "nvme", "sata": "sata", "ata": "sata", "sas": "sas", "usb": "usb", "scsi": "sas"}


def _flag(value) -> bool:
    return value in (True, 1, "1", "true", "True")


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def classify(transport: str, rotational: bool, name: str = "") -> str:
    if transport == "nvme" or name.startswith("nvme"):
        return "nvme"
    if transport == "usb":
        return "usb_flash"
    return "hdd" if rotational else "ssd"


def _mounts_of(blk: dict) -> list[str]:
    mounts = blk.get("mountpoints")
    if mounts is None:
        mounts = [blk.get("mountpoint")]
    return [m for m in mounts if m]


def _walk(blk: dict, mounts: list[str], holders: list[str], parts: list[str]) -> None:
    for child in blk.get("children") or []:
        path = child.get("path") or f"/dev/{child['name']}"
        ctype = (child.get("type") or "").lower()
        if ctype == "part":
            parts.append(path)
        elif ctype in HOLDER_TYPES or ctype.startswith("raid"):
            holders.append(path)
        mounts.extend(_mounts_of(child))
        _walk(child, mounts, holders, parts)


def _system_reason(mounts: list[str]) -> str | None:
    for m in mounts:
        if m in SYSTEM_MOUNTS:
            return f"hosts {m}"
        if m.startswith(LIVE_PREFIXES):
            return f"hosts the running live system at {m}"
    return None


def _lsblk() -> dict:
    cols = "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,LOG-SEC"
    for extra in ("MOUNTPOINTS", "MOUNTPOINT"):
        r = run(["lsblk", "-J", "-b", "-o", f"{cols},{extra}"], timeout=20)
        if r.code == 0 and r.json():
            return r.json()
    raise ToolError("lsblk failed to list block devices")


def parse_lsblk(data: dict) -> list[Disk]:
    disks = []
    for blk in data.get("blockdevices", []):
        if (blk.get("type") or "").lower() != "disk":
            continue
        size = _int(blk.get("size"))
        if size <= 0:
            continue
        name = blk["name"]
        node = blk.get("path") or f"/dev/{name}"
        transport = TRANSPORTS.get((blk.get("tran") or "").lower(), "unknown")
        rotational = _flag(blk.get("rota"))
        mounts = _mounts_of(blk)
        holders: list[str] = []
        parts: list[str] = []
        _walk(blk, mounts, holders, parts)
        serial = (blk.get("serial") or "").strip()
        disks.append(Disk(
            node=node,
            name=name,
            serial=serial or f"UNKNOWN-{name.upper()}",
            model=(blk.get("model") or "Unknown").strip(),
            size_bytes=size,
            logical_sector=_int(blk.get("log-sec"), 512) or 512,
            transport=transport,
            rotational=rotational,
            removable=_flag(blk.get("rm")),
            device_type=classify(transport, rotational, name),
            is_system=_system_reason(mounts) is not None,
            system_reason=_system_reason(mounts),
            mountpoints=sorted(set(mounts)),
            holders=holders,
            partitions=parts,
            serial_reliable=bool(serial),
        ))
    return disks


def _plist(cmd: list[str]) -> dict:
    r = run(cmd, timeout=20)
    if r.code != 0 or not r.out:
        return {}
    try:
        return plistlib.loads(r.out.encode())
    except Exception:
        return {}


def macos_system_disks() -> dict[str, str]:
    info = _plist(["diskutil", "info", "-plist", "/"])
    marked: dict[str, str] = {}
    parent = info.get("ParentWholeDisk")
    if parent:
        marked[parent] = "boot volume container"
    for store in info.get("APFSPhysicalStores") or []:
        m = re.match(r"(disk\d+)", store.get("APFSPhysicalStore", ""))
        if m:
            marked[m.group(1)] = "physical store of the boot volume"
    return marked


def _macos_containers() -> set[str]:
    data = _plist(["diskutil", "apfs", "list", "-plist"])
    return {c.get("ContainerReference") for c in data.get("Containers", []) if c.get("ContainerReference")}


def _macos_mounts(entry: dict) -> list[str]:
    mounts = [entry.get("MountPoint")] if entry.get("MountPoint") else []
    for p in entry.get("Partitions") or []:
        if p.get("MountPoint"):
            mounts.append(p["MountPoint"])
    return mounts


def list_macos() -> list[Disk]:
    listing = _plist(["diskutil", "list", "-plist"])
    system = macos_system_disks()
    containers = _macos_containers()
    entries = {e.get("DeviceIdentifier"): e for e in listing.get("AllDisksAndPartitions", [])}
    disks = []
    for ident in listing.get("WholeDisks", []):
        if ident in containers:
            continue
        info = _plist(["diskutil", "info", "-plist", ident])
        if not info or info.get("VirtualOrPhysical") == "Virtual":
            continue
        size = _int(info.get("TotalSize") or info.get("Size"))
        if size <= 0:
            continue
        protocol = (info.get("BusProtocol") or "").lower()
        transport = "nvme" if "nvme" in protocol else "usb" if "usb" in protocol else "sata" if "sata" in protocol else "unknown"
        rotational = not info.get("SolidState", False)
        entry = entries.get(ident, {})
        reason = system.get(ident) or ("macOS internal system disk" if entry.get("OSInternal") else None)
        serial = (info.get("MediaSerialNumber") or "").strip()
        disks.append(Disk(
            node=f"/dev/{ident}",
            name=ident,
            serial=serial or info.get("DiskUUID") or f"MAC-{ident.upper()}",
            model=(info.get("MediaName") or info.get("IORegistryEntryName") or "Unknown").strip(),
            size_bytes=size,
            logical_sector=_int(info.get("DeviceBlockSize"), 512) or 512,
            transport=transport,
            rotational=rotational,
            removable=bool(info.get("Removable") or info.get("RemovableMedia")),
            device_type=classify(transport, rotational),
            is_system=reason is not None,
            system_reason=reason,
            mountpoints=_macos_mounts(entry),
            serial_reliable=bool(serial),
        ))
    return disks


def list_disks() -> list[Disk]:
    if SYSTEM == "Linux":
        return parse_lsblk(_lsblk())
    if SYSTEM == "Darwin":
        return list_macos()
    return []


def find_disk(node: str) -> Disk | None:
    real = os.path.realpath(node)
    for d in list_disks():
        if d.node in (node, real):
            return d
    return None


def exact_size(disk: Disk) -> int:
    if SYSTEM == "Linux":
        r = run(["blockdev", "--getsize64", disk.node], timeout=10, check=True)
        return int(r.out.strip())
    if SYSTEM == "Darwin":
        info = _plist(["diskutil", "info", "-plist", disk.node])
        size = _int(info.get("TotalSize") or info.get("Size"))
        if size > 0:
            return size
    raise ToolError(f"cannot determine exact size of {disk.node}")


def raw_node(disk: Disk) -> str:
    if SYSTEM == "Darwin":
        return disk.node.replace("/dev/disk", "/dev/rdisk")
    return disk.node
