from backend.hw.model import Capabilities, Disk, Plan, PlanError, Step
from backend.hw.patterns import passes_for

FIRMWARE = {
    "nvme_sanitize_crypto": ("nvme_sanitize", {"action": "crypto"}, "purge"),
    "nvme_sanitize_block": ("nvme_sanitize", {"action": "block"}, "purge"),
    "nvme_sanitize_overwrite": ("nvme_sanitize", {"action": "overwrite"}, "purge"),
    "nvme_format_crypto": ("nvme_format", {"ses": 2}, "purge"),
    "ata_sanitize_crypto": ("ata_sanitize", {"action": "crypto"}, "purge"),
    "ata_sanitize_block": ("ata_sanitize", {"action": "block"}, "purge"),
    "ata_sanitize_overwrite": ("ata_sanitize", {"action": "overwrite"}, "purge"),
    "ata_secure_erase_enhanced": ("ata_secure_erase", {"enhanced": True}, "purge"),
    "ata_secure_erase": ("ata_secure_erase", {"enhanced": False}, "purge"),
    "scsi_sanitize_crypto": ("scsi_sanitize", {"action": "crypto"}, "purge"),
    "scsi_sanitize_block": ("scsi_sanitize", {"action": "block"}, "purge"),
    "scsi_sanitize_overwrite": ("scsi_sanitize", {"action": "overwrite"}, "purge"),
    "sed_psid_revert": ("sed_psid_revert", {}, "purge"),
}

CRYPTO_TECHNIQUES = [
    "sed_psid_revert",
    "nvme_sanitize_crypto",
    "nvme_format_crypto",
    "ata_sanitize_crypto",
    "scsi_sanitize_crypto",
]

PURGE_ORDER = {
    "nvme": ["nvme_sanitize_crypto", "nvme_sanitize_block", "nvme_format_crypto",
             "sed_psid_revert", "nvme_sanitize_overwrite"],
    "ssd": ["ata_sanitize_crypto", "ata_sanitize_block", "sed_psid_revert",
            "scsi_sanitize_crypto", "scsi_sanitize_block", "ata_secure_erase_enhanced"],
    "hdd": ["ata_sanitize_overwrite", "ata_sanitize_crypto", "sed_psid_revert",
            "scsi_sanitize_crypto", "scsi_sanitize_overwrite",
            "ata_secure_erase_enhanced", "ata_secure_erase"],
    "usb_flash": [],
}


def supported(technique: str, caps: Capabilities, options: dict) -> tuple[bool, str | None]:
    kind, params, _ = FIRMWARE[technique]
    if kind == "nvme_sanitize":
        return params["action"] in caps.nvme_sanitize, None
    if kind == "nvme_format":
        return caps.nvme_format_crypto, None
    if kind == "ata_sanitize":
        return params["action"] in caps.ata_sanitize, None
    if kind == "ata_secure_erase":
        if not caps.ata_security or (params["enhanced"] and not caps.ata_enhanced_erase):
            return False, None
        if caps.ata_frozen:
            return False, "ATA security is frozen by the BIOS; suspend and resume the machine or hot-plug the drive, then retry"
        if caps.ata_security_enabled or caps.ata_locked:
            return False, "ATA security is already enabled or locked with an unknown password"
        return True, None
    if kind == "scsi_sanitize":
        return params["action"] in caps.scsi_sanitize, None
    if kind == "sed_psid_revert":
        if not caps.sed_opal:
            return False, None
        if not options.get("psid"):
            return False, "drive is an Opal SED; pass options.psid (printed on the drive label) to use a PSID revert"
        return True, None
    return False, None


def _ata_prep(disk: Disk, caps: Capabilities) -> list[Step]:
    steps = []
    if caps.dco_hidden:
        steps.append(Step("Restore DCO hidden area", "restore_dco", weight=0.05))
    if caps.hpa_enabled:
        steps.append(Step("Remove host protected area", "remove_hpa",
                          {"native_sectors": caps.hpa_native_sectors}, weight=0.05))
    return steps


def _firmware_step(technique: str) -> Step:
    kind, params, _ = FIRMWARE[technique]
    return Step(technique.replace("_", " "), kind, dict(params), weight=1.0)


def _overwrite_steps(standard: str) -> list[Step]:
    passes = passes_for(standard)
    return [
        Step(p["label"], "overwrite", {"index": i, "pattern": p["pattern"], "standard": standard}, weight=1.0)
        for i, p in enumerate(passes)
    ]


def _verify_step(mode: str, check: str) -> Step:
    return Step(f"Verify ({mode} read-back)", "verify", {"mode": mode, "check": check}, weight=0.2)


def _pick(order: list[str], caps: Capabilities, options: dict) -> tuple[str | None, list[str]]:
    blocked = []
    for technique in order:
        ok, why = supported(technique, caps, options)
        if ok:
            return technique, blocked
        if why:
            blocked.append(f"{technique}: {why}")
    return None, blocked


def plan(disk: Disk, caps: Capabilities, method: str, standard: str,
         options: dict | None = None, firmware_allowed: bool = True) -> Plan:
    options = options or {}
    verify_mode = "full" if options.get("verify") == "full" else "sample"
    flash = disk.device_type in ("ssd", "nvme", "usb_flash")
    prep = _ata_prep(disk, caps) if disk.transport == "sata" else []

    if method == "crypto_erase":
        technique, blocked = _pick(CRYPTO_TECHNIQUES, caps, options) if firmware_allowed else (None, [])
        if not technique:
            reason = "; ".join(blocked) if blocked else "no firmware crypto erase reported by the drive"
            if not firmware_allowed:
                reason = "firmware sanitize commands need the OBLVN Linux agent"
            raise PlanError(f"Crypto erase is not possible on this drive: {reason}. Use binary_overwrite or full_sanitization.")
        return Plan(
            technique=technique,
            nist_category="purge",
            steps=prep + [_firmware_step(technique), _verify_step(verify_mode, "changed")],
            rationale=f"{technique} destroys the drive's media encryption key in firmware",
            verify_mode=verify_mode,
            notes=blocked,
        )

    if method == "binary_overwrite":
        notes = ["software overwrite cannot reach remapped sectors or flash over-provisioning"] if flash else []
        return Plan(
            technique="overwrite",
            nist_category="clear",
            steps=prep + _overwrite_steps(standard) + [_verify_step(verify_mode, "pattern")],
            rationale=f"{standard} software overwrite of every addressable sector",
            verify_mode=verify_mode,
            notes=notes,
        )

    if method == "full_sanitization":
        order = PURGE_ORDER.get(disk.device_type, [])
        technique, blocked = _pick(order, caps, options) if firmware_allowed else (None, [])
        if technique:
            return Plan(
                technique=f"{technique}+overwrite",
                nist_category=FIRMWARE[technique][2],
                steps=prep + [_firmware_step(technique)] + _overwrite_steps("nist_800_88")
                + [_verify_step(verify_mode, "pattern")],
                rationale=f"{technique} purge, then a keyed overwrite so every sampled sector can be checked exactly",
                verify_mode=verify_mode,
                notes=blocked,
            )
        notes = blocked + ["no firmware purge available, fell back to software overwrite"]
        if not firmware_allowed:
            notes.append("firmware sanitize commands need the OBLVN Linux agent")
        if flash:
            notes.append("software overwrite cannot reach remapped sectors or flash over-provisioning")
        return Plan(
            technique="overwrite",
            nist_category="clear",
            steps=prep + _overwrite_steps(standard) + [_verify_step(verify_mode, "pattern")],
            rationale=f"{standard} software overwrite of every addressable sector",
            verify_mode=verify_mode,
            notes=notes,
        )

    raise PlanError(f"Unknown wipe method: {method}")
