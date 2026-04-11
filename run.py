import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# 1. GTK Fontconfig setup
gtk_dir = r"C:\Program Files\GTK3-Runtime Win64"
fonts_dir = rf"{gtk_dir}\etc\fonts"
fonts_file = rf"{fonts_dir}\fonts.conf"

if not os.path.exists(fonts_file):
    print("\n" + "="*60)
    print(f"❌ FATAL: Cannot find GTK Fontconfig at:\n{fonts_file}")
    print("Check where you actually installed GTK3 and update 'gtk_dir' in run.py!")
    print("="*60 + "\n")
    sys.exit(1)

os.environ["FONTCONFIG_PATH"] = fonts_dir
os.environ["FONTCONFIG_FILE"] = fonts_file

import uvicorn


def parse_args():
    p = argparse.ArgumentParser(description="OBLVN Secure Data Obliteration Platform")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true")
    return p.parse_args()


def check_env():
    from backend.config import config
    missing = config.validate()
    if missing:
        print("\n[OBLVN] Missing required environment variables:")
        for k in missing:
            print(f"         {k}")
        print("\n  Fill in your .env file with real Supabase credentials.\n")
        sys.exit(1)


def _start_tk_worker():
    """
    Start the long-lived tkinter worker thread and wait for it to be ready.
    Must be called before uvicorn.run() blocks the main thread.
    """
    from backend import tk_worker
    tk_worker.start()


def main():
    args = parse_args()
    os.environ["OBLVN_DRY_RUN"] = "1" if args.dry_run else "0"
    os.environ["OBLVN_PORT"] = str(args.port)

    data_dir = Path(os.path.expanduser("~/.oblvn"))
    for sub in ("logs", "certs", "ots"):
        (data_dir / sub).mkdir(parents=True, exist_ok=True)

    check_env()

    if args.dry_run:
        print("[OBLVN] DRY-RUN MODE, no data will be destroyed")

    # Start tkinter worker BEFORE uvicorn blocks the main thread
    _start_tk_worker()

    if not args.no_browser:
        def open_later():
            time.sleep(3.0)
            webbrowser.open(f"http://localhost:{args.port}/")
        threading.Thread(target=open_later, daemon=True).start()

    print(f"[OBLVN] Running at http://localhost:{args.port}")

    uvicorn.run(
        "backend.server:app",
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
        loop="asyncio",
    )


if __name__ == "__main__":
    main()