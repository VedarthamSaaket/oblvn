import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
TEST_ENV = ROOT / ".env.test"


def configured() -> bool:
    values = dotenv_values(TEST_ENV) if TEST_ENV.exists() else {}
    return bool(values.get("MONGODB_URI")) and values.get("MONGODB_DB") == "oblvn_test"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_frontend() -> None:
    dist = ROOT / "frontend" / "dist" / "index.html"
    marker = ROOT / "frontend" / "dist" / ".same-origin-build"
    if dist.exists() and marker.exists():
        return
    env = {**os.environ, "VITE_API_BASE_URL": "/api"}
    subprocess.run(["./node_modules/.bin/vite", "build"], cwd=ROOT / "frontend", env=env, check=True,
                   capture_output=True)
    marker.write_text("built with VITE_API_BASE_URL=/api\n")


def drop_test_database(uri: str) -> None:
    from pymongo import MongoClient
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    try:
        db = client["oblvn_test"]
        for name in db.list_collection_names():
            db.drop_collection(name)
    finally:
        client.close()


class LiveServer:
    def __init__(self, serve_frontend: bool = False):
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.tmp = Path(tempfile.mkdtemp(prefix="oblvn_live_"))
        self.wipe_root = self.tmp / "files"
        self.wipe_root.mkdir()
        self.log = self.tmp / "server.log"
        self.serve_frontend = serve_frontend
        self.proc = None
        test = dotenv_values(TEST_ENV)
        self.mongodb_uri = test["MONGODB_URI"]
        self.env = {
            **os.environ,
            **{k: v for k, v in dotenv_values(ROOT / ".env").items() if v is not None},
            "MONGODB_URI": test["MONGODB_URI"],
            "MONGODB_DB": "oblvn_test",
            "FLASK_ENV": "testing",
            "OBLVN_DRY_RUN": "1",
            "OBLVN_REQUIRE_EMAIL_VERIFICATION": "false",
            "SMTP_HOST": "",
            "OBLVN_OTS_ENABLED": "false",
            "OBLVN_LOCAL_OPS": "loopback",
            "OBLVN_FILE_WIPE_ROOTS": str(self.wipe_root),
            "OBLVN_DATA_DIR": str(self.tmp / "data"),
            "OBLVN_ML_MODELS": str(self.tmp / "models"),
            "OBLVN_ALLOWED_ORIGINS": self.url,
            "OBLVN_COOKIE_SECURE": "false",
            "PYTHONUNBUFFERED": "1",
        }

    def start(self) -> "LiveServer":
        drop_test_database(self.mongodb_uri)
        if self.serve_frontend:
            build_frontend()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.server:app", "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "warning"],
            cwd=ROOT, env=self.env, stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early:\n{self.log.read_text()[-2000:]}")
            try:
                if httpx.get(f"{self.url}/api/health", timeout=2).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise RuntimeError(f"server did not become healthy:\n{self.log.read_text()[-2000:]}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        drop_test_database(self.mongodb_uri)
