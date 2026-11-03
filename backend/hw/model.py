from dataclasses import asdict, dataclass, field


class WipeError(RuntimeError):
    def __init__(self, message: str, record: dict | None = None):
        super().__init__(message)
        self.record = record or {}


class PlanError(WipeError):
    pass


class Cancelled(RuntimeError):
    pass


@dataclass
class Disk:
    node: str
    name: str
    serial: str
    model: str
    size_bytes: int
    logical_sector: int
    transport: str
    rotational: bool
    removable: bool
    device_type: str
    is_system: bool
    system_reason: str | None
    mountpoints: list[str] = field(default_factory=list)
    holders: list[str] = field(default_factory=list)
    partitions: list[str] = field(default_factory=list)
    serial_reliable: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Capabilities:
    nvme_sanitize: list[str] = field(default_factory=list)
    nvme_format: bool = False
    nvme_format_crypto: bool = False
    ata_security: bool = False
    ata_enhanced_erase: bool = False
    ata_frozen: bool = False
    ata_security_enabled: bool = False
    ata_locked: bool = False
    ata_erase_minutes: int | None = None
    ata_enhanced_erase_minutes: int | None = None
    ata_sanitize: list[str] = field(default_factory=list)
    hpa_current_sectors: int | None = None
    hpa_native_sectors: int | None = None
    dco_real_max_sectors: int | None = None
    scsi_sanitize: list[str] = field(default_factory=list)
    sed_opal: bool = False
    raw_overwrite: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def hpa_enabled(self) -> bool:
        return bool(self.hpa_current_sectors and self.hpa_native_sectors
                    and self.hpa_current_sectors < self.hpa_native_sectors)

    @property
    def dco_hidden(self) -> bool:
        native = self.hpa_native_sectors or 0
        return bool(self.dco_real_max_sectors and native and self.dco_real_max_sectors > native)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hpa_enabled"] = self.hpa_enabled
        d["dco_hidden"] = self.dco_hidden
        return d


@dataclass
class Step:
    name: str
    kind: str
    params: dict = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class Plan:
    technique: str
    nist_category: str
    steps: list[Step]
    rationale: str
    verify_mode: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "nist_category": self.nist_category,
            "steps": [asdict(s) for s in self.steps],
            "rationale": self.rationale,
            "verify_mode": self.verify_mode,
            "notes": self.notes,
        }
