import argparse
import gzip
import shutil
from datetime import date

import httpx

from ml.paths import DATA_DIR

GEO_DIR = DATA_DIR / "geo"
BASE_URL = "https://download.db-ip.com/free"
KINDS = ("city", "asn")


def _months(today: date) -> list[str]:
    first = today.replace(day=1)
    prev = (first.replace(year=first.year - 1, month=12) if first.month == 1
            else first.replace(month=first.month - 1))
    return [first.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def fetch(kind: str, today: date | None = None) -> str:
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    target = GEO_DIR / f"dbip-{kind}-lite.mmdb"
    for month in _months(today or date.today()):
        url = f"{BASE_URL}/dbip-{kind}-lite-{month}.mmdb.gz"
        with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
            if r.status_code != 200:
                continue
            partial = GEO_DIR / f"{kind}.mmdb.gz.part"
            with open(partial, "wb") as f:
                for chunk in r.iter_bytes(4 * 1024 * 1024):
                    f.write(chunk)
        with gzip.open(partial, "rb") as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        partial.unlink()
        (GEO_DIR / f"dbip-{kind}-lite.version").write_text(month)
        return f"{kind}: {month} saved to {target}"
    raise SystemExit(f"no DB-IP {kind} lite file found for {_months(today or date.today())}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Download DB-IP Lite city and ASN databases (CC BY 4.0) into ml/data/geo")
    ap.parse_args()
    for kind in KINDS:
        print(fetch(kind))


if __name__ == "__main__":
    main()
