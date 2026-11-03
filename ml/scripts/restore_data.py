import argparse
import gzip
import hashlib
import shutil

import httpx

from ml.paths import DATA_DIR

REPO = "VedarthamSaaket/oblvn"
TAG = "ml-data-2026-11-03"
GEO = DATA_DIR / "geo"
PROCESSED = DATA_DIR / "processed"
TARGETS = {
    "dbip-city-lite.mmdb.gz": GEO / "dbip-city-lite.mmdb",
    "dbip-asn-lite.mmdb.gz": GEO / "dbip-asn-lite.mmdb",
    "dbip-city-lite.version": GEO / "dbip-city-lite.version",
    "dbip-asn-lite.version": GEO / "dbip-asn-lite.version",
    "drive_health.parquet": PROCESSED / "drive_health.parquet",
}


def _url(tag: str, name: str) -> str:
    return f"https://github.com/{REPO}/releases/download/{tag}/{name}"


def _sums(tag: str) -> dict[str, str]:
    r = httpx.get(_url(tag, "SHA256SUMS"), follow_redirects=True, timeout=60)
    r.raise_for_status()
    return {name: digest for digest, name in (line.split() for line in r.text.splitlines() if line.strip())}


def _download(tag: str, name: str, expected: str) -> bytes:
    with httpx.stream("GET", _url(tag, name), follow_redirects=True, timeout=300) as r:
        r.raise_for_status()
        data = b"".join(r.iter_bytes(4 * 1024 * 1024))
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise SystemExit(f"{name}: checksum mismatch ({digest} != {expected})")
    return data


def restore(tag: str = TAG, force: bool = False) -> None:
    sums = _sums(tag)
    for name, target in TARGETS.items():
        if target.exists() and not force:
            print(f"{name}: already at {target}, skipped (use --force to replace)")
            continue
        data = _download(tag, name, sums[name])
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".part")
        if name.endswith(".gz"):
            tmp.write_bytes(gzip.decompress(data))
        else:
            tmp.write_bytes(data)
        shutil.move(tmp, target)
        print(f"{name}: verified and saved to {target}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Restore geo databases and the drive health training table from the GitHub release")
    ap.add_argument("--tag", default=TAG)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    restore(args.tag, args.force)


if __name__ == "__main__":
    main()
