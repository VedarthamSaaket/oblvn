import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_health(api):
    r = api.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "database": "ok"}


def test_landing_page(api):
    assert api.get("/").status_code == 200


def test_protected_routes_need_auth(api):
    for path in ("/api/jobs", "/api/devices", "/api/anomalies", "/api/audit", "/api/agents", "/api/auth/me"):
        assert api.get(path).status_code == 401, path


def test_real_config_is_valid():
    import os
    test_keys = {"MONGODB_URI", "MONGODB_DB", "OBLVN_JWT_SECRET", "OBLVN_SECRET_KEY", "FLASK_ENV", "OBLVN_DRY_RUN",
                 "OBLVN_LOCAL_OPS", "OBLVN_DATA_DIR", "OBLVN_ML_MODELS"}
    env = {k: v for k, v in os.environ.items() if k not in test_keys}
    out = subprocess.run([sys.executable, "-c", "from backend.config import Config; print(Config.validate())"],
                         capture_output=True, text=True, cwd=ROOT, env=env)
    assert out.stdout.strip() == "[]", out.stdout + out.stderr


def test_command_line_entry_points():
    for cmd in (["run.py", "--help"], ["-m", "agent", "--help"]):
        out = subprocess.run([sys.executable, *cmd], capture_output=True, text=True, cwd=ROOT, timeout=60)
        assert out.returncode == 0, out.stderr


def test_certificate_template_and_assets_exist():
    for rel in ("backend/templates/certificate.html", "backend/assets/artwork_panel.png",
                "backend/assets/fonts/PlayfairDisplay-900-normal.ttf"):
        assert (ROOT / rel).exists(), rel
