import json
import platform
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from agent import VERSION
from agent.config import SPOOL_DIR, AgentConfig


def _verify(ca_bundle: str | None):
    return ca_bundle or True


def check_server_url(server: str, allow_insecure: bool = False) -> str:
    url = urlparse(server)
    if url.scheme not in ("http", "https") or not url.netloc:
        raise ValueError(f"server must be an http(s) URL, got {server!r}")
    if url.scheme == "http" and url.hostname not in ("localhost", "127.0.0.1", "::1"):
        if not allow_insecure:
            raise ValueError(f"{server} is plain http; use https, or pass --allow-insecure-http on a trusted network")
        print(f"[agent] warning: {server} is plain http; the agent token will travel unencrypted")
    return server.rstrip("/")


def pair(server: str, code: str, ca_bundle: str | None = None, allow_insecure: bool = False) -> AgentConfig:
    server = check_server_url(server, allow_insecure)
    r = httpx.post(f"{server}/api/agents/register", json={
        "code": code,
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "version": VERSION,
    }, timeout=30, verify=_verify(ca_bundle))
    if r.status_code != 201:
        raise RuntimeError(f"pairing failed ({r.status_code}): {r.text[:300]}")
    data = r.json()
    return AgentConfig(server=server, agent_id=data["agent_id"], token=data["token"],
                       name=data.get("name", ""), ca_bundle=ca_bundle, allow_insecure=allow_insecure)


class AgentClient:
    def __init__(self, cfg: AgentConfig):
        check_server_url(cfg.server, cfg.allow_insecure)
        self.cfg = cfg
        self.http = httpx.Client(
            base_url=cfg.server,
            headers={"Authorization": f"Agent {cfg.token}"},
            timeout=30,
            verify=_verify(cfg.ca_bundle),
        )

    def heartbeat(self, devices: list[dict]) -> None:
        self.http.post("/api/agents/heartbeat", json={"devices": devices, "version": VERSION}).raise_for_status()

    def next_job(self) -> dict | None:
        r = self.http.get("/api/agents/jobs/next")
        r.raise_for_status()
        return r.json().get("job")

    def progress(self, job_id: str, event: dict) -> bool:
        try:
            r = self.http.post(f"/api/agents/jobs/{job_id}/progress", json=event)
            r.raise_for_status()
            return bool(r.json().get("cancel"))
        except httpx.HTTPError as exc:
            print(f"[agent] progress post failed: {exc}")
            return False

    def result(self, job_id: str, body: dict) -> None:
        payload = json.loads(json.dumps(body, default=str))
        for attempt in range(5):
            try:
                r = self.http.post(f"/api/agents/jobs/{job_id}/result", json=payload)
                if r.status_code in (200, 409):
                    return
            except httpx.HTTPError as exc:
                print(f"[agent] result post failed ({exc}), attempt {attempt + 1}/5")
            time.sleep(5 * (attempt + 1))
        self.spool(job_id, payload)

    def spool(self, job_id: str, payload: dict) -> None:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        (SPOOL_DIR / f"{job_id}.json").write_text(json.dumps(payload))
        print(f"[agent] result for {job_id} spooled to {SPOOL_DIR}")

    def flush_spool(self) -> None:
        if not SPOOL_DIR.exists():
            return
        for path in sorted(SPOOL_DIR.glob("*.json")):
            try:
                r = self.http.post(f"/api/agents/jobs/{path.stem}/result", content=path.read_bytes(),
                                   headers={"Content-Type": "application/json"})
                if r.status_code in (200, 404, 409):
                    Path(path).unlink()
            except httpx.HTTPError:
                return
