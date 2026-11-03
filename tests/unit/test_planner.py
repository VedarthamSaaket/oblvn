import pytest

from backend.hw.model import Capabilities, Disk, PlanError
from backend.hw.planner import plan


def disk(device_type="nvme", transport="nvme"):
    return Disk(node="/dev/x", name="x", serial="S", model="M", size_bytes=10 ** 9, logical_sector=512,
                transport=transport, rotational=device_type == "hdd", removable=False, device_type=device_type,
                is_system=False, system_reason=None)


def test_crypto_erase_prefers_nvme_sanitize():
    p = plan(disk(), Capabilities(nvme_sanitize=["crypto", "block"], nvme_format=True, nvme_format_crypto=True),
             "crypto_erase", "nist_800_88")
    assert p.technique == "nvme_sanitize_crypto" and p.nist_category == "purge"
    assert [s.kind for s in p.steps] == ["nvme_sanitize", "verify"]
    assert p.steps[-1].params["check"] == "changed"


def test_crypto_erase_without_support_refuses():
    with pytest.raises(PlanError):
        plan(disk("ssd", "sata"), Capabilities(ata_sanitize=["block"]), "crypto_erase", "nist_800_88")


def test_crypto_erase_needs_linux_agent_when_firmware_disallowed():
    with pytest.raises(PlanError, match="Linux agent"):
        plan(disk(), Capabilities(nvme_sanitize=["crypto"]), "crypto_erase", "nist_800_88", firmware_allowed=False)


def test_frozen_ata_skips_secure_erase_and_falls_back():
    caps = Capabilities(ata_security=True, ata_enhanced_erase=True, ata_frozen=True)
    p = plan(disk("ssd", "sata"), caps, "full_sanitization", "dod_5220_22m")
    assert p.technique == "overwrite" and p.nist_category == "clear"
    assert any("frozen" in n for n in p.notes)
    assert sum(1 for s in p.steps if s.kind == "overwrite") == 3


def test_full_sanitization_hdd_adds_hpa_removal_and_keyed_overwrite():
    caps = Capabilities(ata_sanitize=["overwrite"], hpa_current_sectors=100, hpa_native_sectors=200)
    p = plan(disk("hdd", "sata"), caps, "full_sanitization", "gutmann", {"verify": "full"})
    kinds = [s.kind for s in p.steps]
    assert kinds == ["remove_hpa", "ata_sanitize", "overwrite", "verify"]
    assert p.technique == "ata_sanitize_overwrite+overwrite" and p.verify_mode == "full"


def test_sed_psid_requires_psid():
    caps = Capabilities(sed_opal=True)
    with pytest.raises(PlanError, match="psid"):
        plan(disk("ssd", "sata"), caps, "crypto_erase", "nist_800_88")
    p = plan(disk("ssd", "sata"), caps, "crypto_erase", "nist_800_88", {"psid": "ABC123"})
    assert p.technique == "sed_psid_revert"


def test_usb_binary_overwrite_is_clear_with_flash_note():
    p = plan(disk("usb_flash", "usb"), Capabilities(), "binary_overwrite", "nist_800_88")
    assert p.nist_category == "clear" and p.notes
