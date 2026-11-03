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


ALLOWED_FETCH_ROOTS = (PROJECT_ROOT / "backend" / "assets", PROJECT_ROOT / "backend" / "templates")


def _fetcher_class():
    from urllib.parse import unquote, urlparse
    from weasyprint.urls import URLFetcher

    class SafeURLFetcher(URLFetcher):
        def __init__(self):
            super().__init__(allowed_protocols={"file", "data"})

        def fetch(self, url, headers=None):
            parsed = urlparse(url)
            if parsed.scheme == "file":
                path = Path(unquote(parsed.path)).resolve()
                roots = [r.resolve() for r in ALLOWED_FETCH_ROOTS] + [FONT_DIR.resolve()]
                if not any(path == r or r in path.parents for r in roots):
                    raise ValueError("blocked file outside OBLVN assets while rendering PDF")
            elif parsed.scheme != "data":
                raise ValueError(f"blocked {parsed.scheme or 'relative'} URL while rendering PDF")
            return super().fetch(url, headers)

    return SafeURLFetcher


def safe_url_fetcher():
    return _fetcher_class()()


def weasy_html():
    configure_fontconfig()
    from functools import partial
    from weasyprint import HTML
    return partial(HTML, url_fetcher=safe_url_fetcher())
