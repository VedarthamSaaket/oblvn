import os
import platform
from pathlib import Path

SYSTEM = platform.system()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = Path(os.environ.get("OBLVN_FONT_DIR", str(PROJECT_ROOT / "backend" / "assets" / "fonts")))

_configured = False


def configure_fontconfig() -> None:
    global _configured
    if _configured or SYSTEM != "Windows":
        _configured = True
        return
    gtk_dir = Path(os.environ.get("OBLVN_GTK_DIR", r"C:\Program Files\GTK3-Runtime Win64"))
    fonts_dir = gtk_dir / "etc" / "fonts"
    fonts_file = fonts_dir / "fonts.conf"
    if fonts_file.exists():
        os.environ.setdefault("FONTCONFIG_PATH", str(fonts_dir))
        os.environ.setdefault("FONTCONFIG_FILE", str(fonts_file))
    else:
        print(f"[OBLVN] GTK fontconfig not found at {fonts_file}; set OBLVN_GTK_DIR. PDF export may fail.")
    _configured = True


def font_face(family: str, filename: str, weight: int) -> str:
    path = FONT_DIR / filename
    if not path.exists():
        return ""
    return f"@font-face {{ font-family: '{family}'; src: url('{path.as_uri()}'); font-weight: {weight}; }}"


def weasy_html():
    configure_fontconfig()
    from weasyprint import HTML
    return HTML
