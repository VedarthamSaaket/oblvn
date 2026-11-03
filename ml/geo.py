import ipaddress
import math
from functools import lru_cache

from ml.paths import DATA_DIR

GEO_DIR = DATA_DIR / "geo"
EARTH_KM = 6371.0
MAX_PLAUSIBLE_KMH = 1000.0
MIN_TRAVEL_KM = 500.0

_readers: dict[str, object] = {}


def _reader(kind: str):
    if kind not in _readers:
        path = GEO_DIR / f"dbip-{kind}-lite.mmdb"
        if not path.exists():
            _readers[kind] = None
        else:
            import maxminddb
            _readers[kind] = maxminddb.open_database(str(path))
    return _readers[kind]


def available() -> bool:
    return _reader("city") is not None


def _public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)


@lru_cache(maxsize=4096)
def lookup(ip: str | None) -> dict | None:
    if not ip or not _public(ip):
        return None
    city, asn = _reader("city"), _reader("asn")
    if city is None:
        return None
    rec = city.get(ip) or {}
    loc = rec.get("location") or {}
    a = (asn.get(ip) if asn else None) or {}
    if not rec and not a:
        return None
    return {
        "country": (rec.get("country") or {}).get("iso_code"),
        "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
        "asn": a.get("autonomous_system_number"),
        "asn_org": a.get("autonomous_system_organization"),
    }


def distance_km(a: dict, b: dict) -> float | None:
    if None in (a.get("lat"), a.get("lon"), b.get("lat"), b.get("lon")):
        return None
    p1, p2 = math.radians(a["lat"]), math.radians(b["lat"])
    dp = p2 - p1
    dl = math.radians(b["lon"] - a["lon"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_KM * math.asin(math.sqrt(h))


def travel(prev: dict | None, cur: dict | None, hours: float) -> dict | None:
    if not prev or not cur:
        return None
    km = distance_km(prev, cur)
    if km is None:
        return None
    kmh = km / max(hours, 1 / 60)
    return {
        "km": round(km, 1),
        "hours": round(hours, 3),
        "kmh": round(kmh, 1),
        "impossible": km >= MIN_TRAVEL_KM and kmh > MAX_PLAUSIBLE_KMH,
    }
