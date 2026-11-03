import argparse
from datetime import date

import httpx

from ml.paths import RAW_DIR
from ml.scripts.fetch_backblaze import BASE_URL, fetch


def quarters_back(today: date, count: int) -> list[str]:
    year, q = today.year, (today.month - 1) // 3 + 1
    out = []
    for _ in range(count):
        out.append(f"Q{q}_{year}")
        q -= 1
        if q == 0:
            q, year = 4, year - 1
    return out


def published(quarter: str) -> bool:
    r = httpx.head(f"{BASE_URL}/data_{quarter}.zip", timeout=30, follow_redirects=True)
    return r.status_code == 200


def local() -> list[str]:
    return sorted(p.name for p in RAW_DIR.glob("Q?_????") if any(p.glob("*.csv")))


def main() -> None:
    ap = argparse.ArgumentParser(description="Find Backblaze quarters that are published but not downloaded yet")
    ap.add_argument("--download", action="store_true", help="download the missing quarters too")
    ap.add_argument("--lookback", type=int, default=6)
    args = ap.parse_args()
    have = set(local())
    missing = [q for q in quarters_back(date.today(), args.lookback) if q not in have and published(q)]
    print(f"on disk: {', '.join(sorted(have)) or 'none'}")
    print(f"published but missing: {', '.join(missing) or 'none'}")
    if args.download:
        for q in missing:
            fetch(q)
        if missing:
            quarters = ' '.join(f'--quarter {q}' for q in sorted(have | set(missing)))
            print(f"next: python -m ml.scripts.prepare_backblaze {quarters} && python -m ml.train --what drive_health")


if __name__ == "__main__":
    main()
