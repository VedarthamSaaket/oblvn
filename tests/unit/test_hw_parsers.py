from backend.hw.capabilities import (nvme_controller, parse_dco, parse_hdparm_identify, parse_hpa,
                                     parse_nvme_id_ctrl, parse_sed)
from backend.hw.executors import parse_ata_sanitize_status, parse_nvme_sanitize_log
from backend.hw.inventory import parse_lsblk
from backend.hw.model import Capabilities
from backend.hw.smart import normalize

LSBLK = {"blockdevices": [
    {"name": "nvme0n1", "path": "/dev/nvme0n1", "type": "disk", "size": 512110190592, "model": "Samsung 980",
     "serial": "S1", "tran": "nvme", "rota": False, "rm": False, "log-sec": 512, "mountpoints": [None],
     "children": [{"name": "nvme0n1p1", "path": "/dev/nvme0n1p1", "type": "part", "mountpoints": ["/boot/efi"]},
                  {"name": "nvme0n1p2", "path": "/dev/nvme0n1p2", "type": "part", "mountpoints": ["/"]}]},
    {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 2000398934016, "model": "WDC WD20",
     "serial": "WD-1", "tran": "sata", "rota": True, "rm": False, "log-sec": 512, "mountpoints": [None],
     "children": [{"name": "sda1", "path": "/dev/sda1", "type": "part", "mountpoints": ["/mnt/data"]}]},
    {"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 32017047552, "model": "Flash", "serial": "",
     "tran": "usb", "rota": "1", "rm": "1", "log-sec": 512, "mountpoints": [None],
     "children": [{"name": "sdb1", "path": "/dev/sdb1", "type": "part", "mountpoints": [None],
                   "children": [{"name": "vg-lv", "path": "/dev/mapper/vg-lv", "type": "lvm", "mountpoints": [None]}]}]},
    {"name": "loop0", "type": "loop", "size": 100},
]}

HDPARM = """
ATA device, with non-removable media
Commands/features:
	Enabled	Supported:
	   *	SANITIZE feature set
	   *	CRYPTO_SCRAMBLE_EXT command
	   *	BLOCK_ERASE_EXT command
Security:
	Master password revision code = 65534
		supported
	not	enabled
	not	locked
		frozen
	not	expired: security count
		supported: enhanced erase
	2min for SECURITY ERASE UNIT. 4min for ENHANCED SECURITY ERASE UNIT.
Logical Unit WWN Device Identifier: 5002538e
"""


def test_lsblk_flags_system_disk_and_holders():
    disks = {d.name: d for d in parse_lsblk(LSBLK)}
    assert set(disks) == {"nvme0n1", "sda", "sdb"}
    assert disks["nvme0n1"].is_system and "/" in disks["nvme0n1"].system_reason
    assert disks["nvme0n1"].device_type == "nvme"
    assert not disks["sda"].is_system and disks["sda"].mountpoints == ["/mnt/data"]
    assert disks["sda"].device_type == "hdd"
    assert disks["sdb"].device_type == "usb_flash"
    assert disks["sdb"].holders == ["/dev/mapper/vg-lv"]
    assert not disks["sdb"].serial_reliable


def test_hdparm_identify_security_and_sanitize():
    caps = Capabilities()
    parse_hdparm_identify(HDPARM, caps)
    assert caps.ata_security and caps.ata_enhanced_erase and caps.ata_frozen
    assert not caps.ata_security_enabled and not caps.ata_locked
    assert caps.ata_erase_minutes == 2 and caps.ata_enhanced_erase_minutes == 4
    assert caps.ata_sanitize == ["crypto", "block"]


def test_hpa_and_dco():
    caps = Capabilities()
    parse_hpa(" max sectors   = 1953523055/1953525168, HPA is enabled", caps)
    parse_dco("DCO Revision: 0x0001\n Real max sectors: 1953525200", caps)
    assert caps.hpa_enabled and caps.dco_hidden


def test_nvme_id_ctrl_bits():
    caps = Capabilities()
    parse_nvme_id_ctrl({"sanicap": 0b011, "fna": 0b100, "oacs": 0b10}, caps)
    assert caps.nvme_sanitize == ["crypto", "block"]
    assert caps.nvme_format and caps.nvme_format_crypto
    assert nvme_controller("/dev/nvme0n1") == "/dev/nvme0"


def test_sed_detection():
    caps = Capabilities()
    parse_sed("/dev/nvme0 SED --2--- Samsung SSD 980 PRO 1TB", caps)
    assert caps.sed_opal
    other = Capabilities()
    parse_sed("/dev/sda NO --- WDC WD20", other)
    assert not other.sed_opal


def test_nvme_sanitize_log_states():
    assert parse_nvme_sanitize_log({"nvme0": {"sstat": 2, "sprog": 32767}})[0] == "running"
    assert parse_nvme_sanitize_log({"sstat": 0x101, "sprog": 65535}) == ("done", 100.0)
    assert parse_nvme_sanitize_log({"sstat": 3, "sprog": 0})[0] == "failed"


def test_ata_sanitize_status():
    assert parse_ata_sanitize_status("State: SD2 Sanitize in progress\nProgress: 0x1999 (10%)") == ("running", 10.0)
    assert parse_ata_sanitize_status("Last Sanitize Operation Completed Without Error")[0] == "done"


def test_smart_normalize_ata_and_nvme():
    snap = normalize({
        "smart_status": {"passed": True}, "serial_number": "X1", "temperature": {"current": 41},
        "power_on_time": {"hours": 1200},
        "ata_smart_attributes": {"table": [{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100,
                                            "thresh": 10, "raw": {"value": 3}, "flags": {"string": "PO--CK"}}]},
        "nvme_smart_health_information_log": {"critical_warning": 0, "percentage_used": 3, "media_errors": 0},
    })
    assert snap["available"] and snap["health"] == "Passed" and snap["serial"] == "X1"
    assert snap["attributes"][0]["raw"] == "3" and snap["nvme"]["percentage_used"] == 3
    assert normalize({})["available"] is False
