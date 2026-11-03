def _rep(seq: list[int]) -> bytes:
    return (bytes(seq) * 171)[:512]


DOD_PASSES = [
    {"pattern": "zero", "label": "Pass 1/3 — 0x00 overwrite"},
    {"pattern": "ones", "label": "Pass 2/3 — 0xFF overwrite"},
    {"pattern": "random", "label": "Pass 3/3 — random overwrite"},
]

GUTMANN_PASSES = (
    [{"pattern": "random", "label": f"Pass {i} — random"} for i in range(1, 5)]
    + [
        {"pattern": "bytes", "data": bytes([0x55] * 512), "label": "Pass 5 — 0x55"},
        {"pattern": "bytes", "data": bytes([0xAA] * 512), "label": "Pass 6 — 0xAA"},
        {"pattern": "bytes", "data": _rep([0x92, 0x49, 0x24]), "label": "Pass 7"},
        {"pattern": "bytes", "data": _rep([0x49, 0x24, 0x92]), "label": "Pass 8"},
        {"pattern": "bytes", "data": _rep([0x24, 0x92, 0x49]), "label": "Pass 9"},
    ]
    + [
        {"pattern": "bytes", "data": bytes([v] * 512), "label": f"Pass {10 + i} — 0x{v:02X}"}
        for i, v in enumerate(range(0x00, 0x100, 0x11))
    ]
    + [
        {"pattern": "bytes", "data": _rep([0x92, 0x49, 0x24]), "label": "Pass 26"},
        {"pattern": "bytes", "data": _rep([0x49, 0x24, 0x92]), "label": "Pass 27"},
        {"pattern": "bytes", "data": _rep([0x24, 0x92, 0x49]), "label": "Pass 28"},
        {"pattern": "bytes", "data": _rep([0x6D, 0xB6, 0xDB]), "label": "Pass 29"},
        {"pattern": "bytes", "data": _rep([0xB6, 0xDB, 0x6D]), "label": "Pass 30"},
        {"pattern": "bytes", "data": _rep([0xDB, 0x6D, 0xB6]), "label": "Pass 31"},
    ]
    + [{"pattern": "random", "label": f"Pass {i} — random"} for i in range(32, 36)]
)

NIST_PASSES = [
    {"pattern": "random", "label": "Pass 1/1 — random overwrite (NIST 800-88)"},
]

STANDARDS = {
    "dod_5220_22m": DOD_PASSES,
    "gutmann": GUTMANN_PASSES,
    "nist_800_88": NIST_PASSES,
}


def passes_for(standard: str) -> list[dict]:
    return STANDARDS.get(standard, NIST_PASSES)


def static_chunk(p: dict, size: int) -> bytes | None:
    pattern = p["pattern"]
    if pattern == "zero":
        return bytes(size)
    if pattern == "ones":
        return b"\xFF" * size
    if pattern == "random":
        return None
    raw = p.get("data") or b"\x00"
    return (raw * (size // len(raw) + 1))[:size]
