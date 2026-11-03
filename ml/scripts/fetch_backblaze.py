import argparse
import zipfile

import httpx

from ml.paths import RAW_DIR

BASE_URL = "https://f001.backblazeb2.com/file/Backblaze-Hard-Drive-Data"


def fetch(quarter: str) -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    archive = RAW_DIR / f"data_{quarter}.zip"
    target = RAW_DIR / quarter
    if target.exists() and any(target.rglob("*.csv")):
        print(f"{quarter}: already extracted at {target}")
        return
    if not archive.exists():
        url = f"{BASE_URL}/data_{quarter}.zip"
        print(f"{quarter}: downloading {url}")
        partial = archive.with_suffix(".part")
        with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            done = 0
            with open(partial, "wb") as f:
                for chunk in r.iter_bytes(8 * 1024 * 1024):
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        print(f"\r{quarter}: {done / total * 100:5.1f}%", end="", flush=True)
        print()
        partial.rename(archive)
    print(f"{quarter}: extracting")
    with zipfile.ZipFile(archive) as z:
        members = [m for m in z.namelist() if m.endswith(".csv") and "__MACOSX" not in m]
        target.mkdir(parents=True, exist_ok=True)
        for m in members:
            with z.open(m) as src, open(target / m.rsplit("/", 1)[-1], "wb") as dst:
                while block := src.read(8 * 1024 * 1024):
                    dst.write(block)
    print(f"{quarter}: {len(members)} daily files in {target}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Download Backblaze drive stats quarters into ml/data/raw")
    ap.add_argument("--quarter", action="append", required=True, help="for example Q1_2024, repeatable")
    for q in ap.parse_args().quarter:
        fetch(q)


if __name__ == "__main__":
    main()
