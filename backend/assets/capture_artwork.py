import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
VIEW_W, VIEW_H = 1440, 900
PANEL_W, PANEL_H = 380, 820


def capture(url: str, chrome: str, scale: int, out: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        shot = Path(tmp) / "page.png"
        subprocess.run([
            chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
            f"--window-size={VIEW_W},{VIEW_H}", f"--force-device-scale-factor={scale}",
            "--virtual-time-budget=8000", f"--screenshot={shot}", url,
        ], check=True, capture_output=True)
        img = Image.open(shot).convert("RGB")
        left = (VIEW_W - PANEL_W) * scale
        panel = img.crop((left, 0, left + PANEL_W * scale, PANEL_H * scale))
        panel.save(out, optimize=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Capture the app's ArtworkPanel exactly as the browser renders it")
    ap.add_argument("--url", default="http://localhost:5199/app/login")
    ap.add_argument("--chrome", default=os.environ.get("CHROME", DEFAULT_CHROME))
    ap.add_argument("--scale", type=int, default=4)
    ap.add_argument("--out", type=Path, default=HERE / "artwork_panel.png")
    args = ap.parse_args()
    path = capture(args.url, args.chrome, args.scale, args.out)
    print(f"saved {path} ({Image.open(path).size[0]}x{Image.open(path).size[1]})")


if __name__ == "__main__":
    main()
