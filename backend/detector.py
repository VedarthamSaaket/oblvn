import json
import os
import platform
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

SYSTEM = platform.system()

try:
    from pySMART import Device as SmartDevice
    PYSMART_AVAILABLE = True
except ImportError:
    PYSMART_AVAILABLE = False


class DeviceDetectionError(Exception):
    pass


@dataclass
class Device:
    serial: str
    model: str
    manufacturer: str
    capacity_bytes: int
    capacity_human: str
    device_type: str
    interface: str
    filesystem: str
    node: str
    health: str
    smart_available: bool
    smart_snapshot: dict[str, Any]
    detected_at: str


def _human(b: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if SYSTEM == "Windows" else 0,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, AttributeError):
        return -1, "", ""


def _parse_size(s: str) -> int:
    s = s.strip().upper().replace(",", "")
    mults = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for suffix, m in mults.items():
        if s.endswith(suffix):
            try:
                return int(float(s[:-1]) * m)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _manufacturer(model: str) -> str:
    known = [
        "Samsung", "WDC", "Western Digital", "Seagate", "Toshiba",
        "SanDisk", "Kingston", "Crucial", "Intel", "SK Hynix", "Micron",
        "Hitachi", "HGST", "Apple", "PNY", "Lexar", "Verbatim", "Corsair",
        "ADATA", "Transcend", "Silicon Power",
    ]
    for k in known:
        if k.upper() in model.upper():
            return k
    return model.split()[0] if model else "Unknown"


def _smart_for_node(node: str) -> dict:
    if not PYSMART_AVAILABLE:
        return {"available": False, "health": "Unknown", "attributes": []}
    try:
        d = SmartDevice(node)
        attrs = []
        if d.attributes:
            for a in d.attributes:
                if a:
                    attrs.append({
                        "id": int(a.num),
                        "name": a.name,
                        "value": int(a.value) if a.value else 0,
                        "worst": int(a.worst) if a.worst else 0,
                        "threshold": int(a.thresh) if a.thresh else 0,
                        "raw": str(a.raw),
                        "flags": a.flags_hex,
                    })
        return {
            "available": True,
            "health": "Passed" if d.assessment == "PASS" else "Failed",
            "temperature": d.temperature,
            "firmware": d.firmware,
            "attributes": attrs,
        }
    except Exception:
        return {"available": False, "health": "Unknown", "attributes": []}


def _detect_linux() -> list[Device]:
    code, out, _ = _run([
        "lsblk", "-J", "-o",
        "NAME,MODEL,SERIAL,SIZE,TYPE,TRAN,FSTYPE,VENDOR,ROTA",
    ])
    if code != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    devices = []
    for blk in data.get("blockdevices", []):
        if blk.get("type") != "disk":
            continue
        node = f"/dev/{blk['name']}"
        capacity = _parse_size(blk.get("size", "0"))
        rota = blk.get("rota", "1") == "1"
        tran = (blk.get("tran") or "").upper()
        model = (blk.get("model") or blk.get("vendor") or "Unknown").strip()
        serial = (blk.get("serial") or f"UNKNOWN-{blk['name'].upper()}").strip()
        fstype = blk.get("fstype") or "unknown"

        if tran == "NVME" or "nvme" in blk["name"]:
            dtype, iface = "nvme", "NVMe"
        elif tran == "USB":
            dtype, iface = "usb_flash", "USB"
        elif rota:
            dtype, iface = "hdd", "SATA"
        else:
            dtype, iface = "ssd", "SATA"

        smart = _smart_for_node(node)
        devices.append(Device(
            serial=serial,
            model=model,
            manufacturer=_manufacturer(model),
            capacity_bytes=capacity,
            capacity_human=_human(capacity),
            device_type=dtype,
            interface=iface,
            filesystem=fstype,
            node=node,
            health=smart.get("health", "Unknown"),
            smart_available=smart.get("available", False),
            smart_snapshot=smart,
            detected_at=datetime.now(timezone.utc).isoformat(),
        ))
    return devices


def _detect_macos() -> list[Device]:
    code, out, _ = _run(["diskutil", "list", "-plist"])
    if code != 0:
        return []
    try:
        import plistlib
        data = plistlib.loads(out.encode())
    except Exception:
        return []

    devices = []
    for disk in data.get("WholeDisks", []):
        node = f"/dev/{disk}"
        code2, out2, _ = _run(["diskutil", "info", "-plist", node])
        if code2 != 0:
            continue
        try:
            import plistlib
            info = plistlib.loads(out2.encode())
        except Exception:
            continue

        size = info.get("TotalSize", 0)
        model = (info.get("MediaName") or info.get("IORegistryEntryName") or "Unknown")
        serial = (info.get("DiskUUID") or info.get("MediaSerialNumber") or f"MAC-{disk.upper()}")
        fstype = info.get("FilesystemType") or info.get("VolumeName") or "unknown"
        protocol = (info.get("BusProtocol") or "").upper()

        if "NVME" in protocol:
            dtype, iface = "nvme", "NVMe"
        elif "USB" in protocol:
            dtype, iface = "usb_flash", "USB"
        elif info.get("SolidState"):
            dtype, iface = "ssd", "SATA"
        else:
            dtype, iface = "hdd", "SATA"

        smart = _smart_for_node(node)
        devices.append(Device(
            serial=serial,
            model=model,
            manufacturer=_manufacturer(model),
            capacity_bytes=size,
            capacity_human=_human(size),
            device_type=dtype,
            interface=iface,
            filesystem=fstype,
            node=node,
            health=smart.get("health", "Unknown"),
            smart_available=smart.get("available", False),
            smart_snapshot=smart,
            detected_at=datetime.now(timezone.utc).isoformat(),
        ))
    return devices


def _detect_windows_wmi() -> list[Device]:
    """Primary Windows detection via WMI."""
    import wmi
    devices = []
    c = wmi.WMI()
    for disk in c.Win32_DiskDrive():
        serial = (disk.SerialNumber or "").strip() or f"WIN-{disk.Index}"
        model = (disk.Model or "Unknown").strip()
        size = int(disk.Size or 0)
        media_type = (disk.MediaType or "").lower()
        iface_raw = (disk.InterfaceType or "").upper()

        if "nvme" in model.lower():
            dtype, iface = "nvme", "NVMe"
        elif iface_raw == "USB":
            dtype, iface = "usb_flash", "USB"
        elif "ssd" in model.lower() or "solid" in media_type:
            dtype, iface = "ssd", "SATA"
        else:
            dtype, iface = "hdd", "SATA"

        node = f"\\\\.\\PhysicalDrive{disk.Index}"
        smart = _smart_for_node(node)
        devices.append(Device(
            serial=serial,
            model=model,
            manufacturer=_manufacturer(model),
            capacity_bytes=size,
            capacity_human=_human(size),
            device_type=dtype,
            interface=iface,
            filesystem="unknown",
            node=node,
            health=smart.get("health", "Unknown"),
            smart_available=smart.get("available", False),
            smart_snapshot=smart,
            detected_at=datetime.now(timezone.utc).isoformat(),
        ))
    return devices


def _detect_windows_powershell() -> list[Device]:
    """
    Fallback Windows detection via PowerShell.
    Uses Get-Disk (which exposes DiskNumber = the real PhysicalDrive index)
    combined with Get-PhysicalDisk for health and bus type.
    Falls back to Get-PhysicalDisk alone if Get-Disk is unavailable.
    """
    # Get-Disk gives us DiskNumber (the real index for PhysicalDriveN)
    # and Size. Get-PhysicalDisk gives BusType and HealthStatus.
    # Join on FriendlyName since there's no shared unique key in PS without WMI.
    ps_script = """
$disks = Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle
$physical = Get-PhysicalDisk | Select-Object FriendlyName, SerialNumber, MediaType, BusType, HealthStatus
$result = foreach ($d in $disks) {
    $p = $physical | Where-Object { $_.FriendlyName -eq $d.FriendlyName } | Select-Object -First 1
    [PSCustomObject]@{
        DiskNumber   = $d.Number
        FriendlyName = $d.FriendlyName
        Size         = $d.Size
        SerialNumber = if ($p) { $p.SerialNumber } else { "" }
        MediaType    = if ($p) { $p.MediaType } else { "Unspecified" }
        BusType      = if ($p) { $p.BusType } else { "Unknown" }
        HealthStatus = if ($p) { $p.HealthStatus } else { "Unknown" }
    }
}
$result | ConvertTo-Json -Depth 2
"""
    code, out, err = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        timeout=25,
    )

    if code != 0 or not out.strip():
        print(f"[DETECTOR] Get-Disk join failed ({err.strip()[:120]}), trying Get-PhysicalDisk only...")
        return _detect_windows_powershell_fallback()

    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        print("[DETECTOR] JSON parse failed on Get-Disk output, trying fallback...")
        return _detect_windows_powershell_fallback()

    if isinstance(raw, dict):
        raw = [raw]

    devices = []
    for disk in raw:
        model  = (disk.get("FriendlyName") or "Unknown Disk").strip()
        serial = (disk.get("SerialNumber") or "").strip()
        size   = int(disk.get("Size") or 0)
        media  = (disk.get("MediaType") or "").lower()
        bus    = (disk.get("BusType") or "").upper()
        health = (disk.get("HealthStatus") or "Unknown")
        # DiskNumber is the real Windows disk index — critical for correct node path
        disk_number = disk.get("DiskNumber")
        if disk_number is None:
            print(f"[DETECTOR] Skipping disk with no DiskNumber: {model}")
            continue

        serial = serial or f"PS-{disk_number}"

        if bus == "NVME" or "nvme" in model.lower():
            dtype, iface = "nvme", "NVMe"
        elif bus == "USB":
            dtype, iface = "usb_flash", "USB"
        elif "ssd" in media or "solid" in media:
            dtype, iface = "ssd", "SATA"
        elif "unspecified" in media or "removable" in media:
            dtype, iface = "usb_flash", bus if bus else "USB"
        else:
            dtype, iface = "hdd", bus if bus else "SATA"

        # Use real disk index — not enumerate index
        node = f"\\\\.\\PhysicalDrive{disk_number}"
        smart = _smart_for_node(node)

        devices.append(Device(
            serial=serial,
            model=model,
            manufacturer=_manufacturer(model),
            capacity_bytes=size,
            capacity_human=_human(size),
            device_type=dtype,
            interface=iface,
            filesystem="unknown",
            node=node,
            health=health if health != "Unknown" else smart.get("health", "Unknown"),
            smart_available=smart.get("available", False),
            smart_snapshot=smart,
            detected_at=datetime.now(timezone.utc).isoformat(),
        ))
    return devices


def _detect_windows_powershell_fallback() -> list[Device]:
    """
    Last-resort fallback: Get-PhysicalDisk only.
    DeviceId maps to the PhysicalDrive number on most systems.
    """
    ps_script = (
        "Get-PhysicalDisk | Select-Object -Property "
        "DeviceId,FriendlyName,SerialNumber,Size,MediaType,BusType,HealthStatus "
        "| ConvertTo-Json -Depth 2"
    )
    code, out, err = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        timeout=20,
    )
    if code != 0 or not out.strip():
        print(f"[DETECTOR] PowerShell fallback failed: {err.strip()[:200]}")
        return []

    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return []

    if isinstance(raw, dict):
        raw = [raw]

    devices = []
    for disk in raw:
        model  = (disk.get("FriendlyName") or "Unknown Disk").strip()
        serial = (disk.get("SerialNumber") or "").strip()
        size   = int(disk.get("Size") or 0)
        media  = (disk.get("MediaType") or "").lower()
        bus    = (disk.get("BusType") or "").upper()
        health = (disk.get("HealthStatus") or "Unknown")
        # DeviceId is the PhysicalDrive number on most Windows systems
        device_id = disk.get("DeviceId")
        try:
            disk_number = int(device_id)
        except (TypeError, ValueError):
            # No reliable index — skip rather than guess wrong drive
            print(f"[DETECTOR] Cannot determine disk number for {model}, skipping")
            continue

        serial = serial or f"PS-{disk_number}"

        if bus == "NVME" or "nvme" in model.lower():
            dtype, iface = "nvme", "NVMe"
        elif bus == "USB":
            dtype, iface = "usb_flash", "USB"
        elif "ssd" in media or "solid" in media:
            dtype, iface = "ssd", "SATA"
        elif "unspecified" in media or "removable" in media:
            dtype, iface = "usb_flash", bus if bus else "USB"
        else:
            dtype, iface = "hdd", bus if bus else "SATA"

        node = f"\\\\.\\PhysicalDrive{disk_number}"
        smart = _smart_for_node(node)

        devices.append(Device(
            serial=serial,
            model=model,
            manufacturer=_manufacturer(model),
            capacity_bytes=size,
            capacity_human=_human(size),
            device_type=dtype,
            interface=iface,
            filesystem="unknown",
            node=node,
            health=health if health != "Unknown" else smart.get("health", "Unknown"),
            smart_available=smart.get("available", False),
            smart_snapshot=smart,
            detected_at=datetime.now(timezone.utc).isoformat(),
        ))
    return devices


def _detect_windows() -> list[Device]:
    """Try WMI first, fall back to PowerShell."""
    try:
        devices = _detect_windows_wmi()
        if devices:
            return devices
        print("[DETECTOR] WMI returned no devices, trying PowerShell fallback...")
    except ImportError:
        print("[DETECTOR] wmi package not installed, using PowerShell fallback...")
    except Exception as exc:
        print(f"[DETECTOR] WMI failed ({exc}), using PowerShell fallback...")

    return _detect_windows_powershell()


def detect_devices() -> list[dict]:
    raw: list[Device] = []

    if SYSTEM == "Linux":
        raw = _detect_linux()
    elif SYSTEM == "Darwin":
        raw = _detect_macos()
    elif SYSTEM == "Windows":
        raw = _detect_windows()

    if not raw:
        if SYSTEM == "Windows":
            raise DeviceDetectionError(
                "No storage devices detected.\n\n"
                "On Windows, OBLVN needs to be run as Administrator to access raw drive info.\n"
                "Right-click run.py (or your terminal) and choose 'Run as administrator', then try again.\n\n"
                "If you see a USB drive plugged in but it is not detected, make sure it is formatted "
                "(FAT32/exFAT/NTFS) and try re-inserting it."
            )
        raise DeviceDetectionError(
            "No storage devices detected. "
            "Ensure physical drives are connected and the process has elevated privileges "
            "(sudo on Linux/macOS, Administrator on Windows)."
        )

    return [asdict(d) for d in raw]


def get_device_by_serial(serial: str) -> dict | None:
    for d in detect_devices():
        if d["serial"] == serial:
            return d
    return None