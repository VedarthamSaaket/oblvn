import pytest

from backend.hw import pipeline
from backend.hw.model import Cancelled, Disk, PlanError


def disk(device_type="nvme"):
    return Disk(node="/dev/sim0", name="sim0", serial="SIM", model="Sim", size_bytes=10 ** 10, logical_sector=512,
                transport="nvme" if device_type == "nvme" else "sata", rotational=device_type == "hdd",
                removable=False, device_type=device_type, is_system=False, system_reason=None)


def test_dry_run_crypto_erase_completes_with_record():
    events = list(pipeline.run(disk(), "crypto_erase", "nist_800_88", dry_run=True))
    done = events[-1]
    assert done["type"] == "complete" and done["technique"] == "nvme_sanitize_crypto"
    assert done["record"]["nist_category"] == "purge"
    assert done["verification_passed"] is True
    assert any(e["type"] == "progress" for e in events[:-1])


def test_dry_run_full_sanitization_hdd():
    done = list(pipeline.run(disk("hdd"), "full_sanitization", "dod_5220_22m", dry_run=True))[-1]
    assert done["technique"] == "ata_sanitize_overwrite+overwrite"
    assert done["record"]["telemetry"]["overwrite_passes"] == 1


def test_dry_run_usb_crypto_erase_raises_plan_error():
    with pytest.raises(PlanError):
        list(pipeline.run(disk("usb_flash"), "crypto_erase", "nist_800_88", dry_run=True))


def test_dry_run_cancel_propagates():
    def cancel():
        raise Cancelled("stop")
    with pytest.raises(Cancelled):
        list(pipeline.run(disk(), "binary_overwrite", "nist_800_88", cancel_check=cancel, dry_run=True))
