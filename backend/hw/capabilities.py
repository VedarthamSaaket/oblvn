import re

from backend.hw.model import Capabilities, Disk
from backend.hw.runner import ToolError, have, run

SANICAP_BITS = {"crypto": 0, "block": 1, "overwrite": 2}
SCSI_SANITIZE_SA = {"overwrite": 1, "block": 2, "crypto": 3}


def nvme_controller(node: str) -> str:
    return re.sub(r"n\d+$", "", node)


def parse_nvme_id_ctrl(data: dict, caps: Capabilities) -> None:
    sanicap = int(data.get("sanicap", 0) or 0)
    fna = int(data.get("fna", 0) or 0)
    oacs = int(data.get("oacs", 0) or 0)
    caps.nvme_sanitize = [k for k, bit in SANICAP_BITS.items() if sanicap & (1 << bit)]
    caps.nvme_format = bool(oacs & (1 << 1))
    caps.nvme_format_crypto = caps.nvme_format and bool(fna & (1 << 2))


def _security_section(text: str) -> list[list[str]]:
    lines = text.splitlines()
    out: list[list[str]] = []
    inside = False
    for line in lines:
        if line.startswith("Security:"):
            inside = True
            continue
        if inside:
            if line and not line[0].isspace():
                break
            if line.strip():
                out.append(line.split())
    return out


def parse_hdparm_identify(text: str, caps: Capabilities) -> None:
    for tokens in _security_section(text):
        joined = " ".join(tokens)
        if tokens == ["supported"]:
            caps.ata_security = True
        elif tokens == ["enabled"]:
            caps.ata_security_enabled = True
        elif tokens == ["locked"]:
            caps.ata_locked = True
        elif tokens == ["frozen"]:
            caps.ata_frozen = True
        elif joined == "supported: enhanced erase":
            caps.ata_enhanced_erase = True
        m = re.search(r"(\d+)min for SECURITY ERASE UNIT", joined)
        if m:
            caps.ata_erase_minutes = int(m.group(1))
        m = re.search(r"(\d+)min for ENHANCED SECURITY ERASE UNIT", joined)
        if m:
            caps.ata_enhanced_erase_minutes = int(m.group(1))
    features = {
        "crypto": r"^\s*\*\s+CRYPTO_SCRAMBLE_EXT command",
        "block": r"^\s*\*\s+BLOCK_ERASE_EXT command",
        "overwrite": r"^\s*\*\s+OVERWRITE_EXT command",
    }
    if re.search(r"^\s*\*\s+SANITIZE feature set", text, re.M):
        caps.ata_sanitize = [k for k, pat in features.items() if re.search(pat, text, re.M)]


def parse_hpa(text: str, caps: Capabilities) -> None:
    m = re.search(r"max sectors\s*=\s*(\d+)/(\d+)", text)
    if m:
        caps.hpa_current_sectors = int(m.group(1))
        caps.hpa_native_sectors = int(m.group(2))


def parse_dco(text: str, caps: Capabilities) -> None:
    m = re.search(r"Real max sectors:\s*(\d+)", text)
    if m:
        caps.dco_real_max_sectors = int(m.group(1))


def parse_sed(text: str, caps: Capabilities) -> None:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("/dev/") and parts[1] == "SED":
            caps.sed_opal = True


def _probe_nvme(disk: Disk, caps: Capabilities) -> None:
    if not have("nvme"):
        caps.notes.append("nvme-cli not installed, NVMe firmware sanitize unavailable")
        return
    r = run(["nvme", "id-ctrl", nvme_controller(disk.node), "-o", "json"], timeout=20)
    if r.code == 0:
        parse_nvme_id_ctrl(r.json(), caps)
    else:
        caps.notes.append(f"nvme id-ctrl failed: {r.err.strip()[:200]}")


def _probe_ata(disk: Disk, caps: Capabilities) -> None:
    if not have("hdparm"):
        caps.notes.append("hdparm not installed, ATA secure erase and sanitize unavailable")
        return
    r = run(["hdparm", "-I", disk.node], timeout=20)
    if r.code != 0 or "Security:" not in r.out:
        caps.notes.append("drive did not answer ATA IDENTIFY (common behind USB bridges)")
        return
    parse_hdparm_identify(r.out, caps)
    parse_hpa(run(["hdparm", "-N", disk.node], timeout=20).out, caps)
    parse_dco(run(["hdparm", "--dco-identify", disk.node], timeout=20).out, caps)


def _probe_scsi(disk: Disk, caps: Capabilities) -> None:
    if not have("sg_opcodes"):
        caps.notes.append("sg3_utils not installed, SCSI sanitize unavailable")
        return
    supported = []
    for name, sa in SCSI_SANITIZE_SA.items():
        r = run(["sg_opcodes", f"--opcode=0x48,{sa}", disk.node], timeout=20)
        if r.code == 0 and "not supported" not in r.out.lower():
            supported.append(name)
    caps.scsi_sanitize = supported


def _probe_sed(disk: Disk, caps: Capabilities) -> None:
    if not have("sedutil-cli"):
        return
    r = run(["sedutil-cli", "--isValidSED", disk.node], timeout=20)
    parse_sed(r.out, caps)


def probe(disk: Disk) -> Capabilities:
    caps = Capabilities()
    probes = {
        "nvme": [_probe_nvme, _probe_sed],
        "sata": [_probe_ata, _probe_sed],
        "sas": [_probe_scsi, _probe_sed],
        "usb": [_probe_ata],
    }.get(disk.transport, [])
    for fn in probes:
        try:
            fn(disk, caps)
        except ToolError as exc:
            caps.notes.append(str(exc))
    return caps
