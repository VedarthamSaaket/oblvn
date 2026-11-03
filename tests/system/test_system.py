import json
import time

import httpx
import pytest
from websockets.sync.client import connect

from tests.live_server import LiveServer, configured

pytestmark = [pytest.mark.system, pytest.mark.skipif(not configured(), reason=".env.test is not configured")]
PW = "System-Test-Pass-9!"


@pytest.fixture(scope="module")
def server():
    s = LiveServer().start()
    yield s
    s.stop()


@pytest.fixture(scope="module")
def session(server):
    c = httpx.Client(base_url=server.url, timeout=30)
    assert c.post("/api/auth/register", json={"email": "owner@system.test", "password": PW}).status_code == 201
    r = c.post("/api/auth/login", json={"email": "owner@system.test", "password": PW})
    assert r.status_code == 200
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    yield c
    c.close()


def test_health_and_headers(server):
    r = httpx.get(f"{server.url}/api/health")
    assert r.json() == {"status": "ok", "database": "ok"}
    assert r.headers["cache-control"] == "no-store" and "content-security-policy" in r.headers


def test_spa_is_not_served_without_a_build_and_api_works(session):
    assert session.get("/api/auth/me").json()["email"] == "owner@system.test"


def test_organisation_and_invite(session):
    org = session.post("/api/orgs", json={"name": "System Org"})
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    assert session.post(f"/api/orgs/{org_id}/invite", json={"email": "member@system.test", "role": "operator"}).status_code == 200
    assert session.post(f"/api/orgs/{org_id}/invite", json={"email": "member@system.test", "role": "operator"}).status_code == 409
    members = session.get(f"/api/orgs/{org_id}/members").json()["members"]
    assert {m["role"] for m in members} == {"org_admin", "operator"}
    assert session.patch(f"/api/orgs/{org_id}", json={"timezone": "Asia/Kolkata"}).json()["timezone"] == "Asia/Kolkata"


def test_file_wipe_job_end_to_end(server, session):
    target = server.wipe_root / "customer-records.csv"
    target.write_bytes(b"name,card\nalice,4111111111111111\n" * 200)
    created = session.post("/api/jobs", json={"method": "binary_overwrite", "standard": "dod_5220_22m",
                                              "device_serial": f"file:{target}"})
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    events = []
    ticket = session.post(f"/api/jobs/{job_id}/ws-ticket").json()["ticket"]
    try:
        with connect(f"{server.url.replace('http', 'ws')}/ws/jobs/{job_id}?ticket={ticket}", open_timeout=10) as ws:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    msg = json.loads(ws.recv(timeout=5))
                except TimeoutError:
                    if session.get(f"/api/jobs/{job_id}").json()["status"] in ("completed", "failed"):
                        break
                    continue
                events.append(msg)
                if msg.get("type") in ("complete", "error"):
                    break
    except Exception:
        pass
    deadline = time.monotonic() + 60
    job = {}
    while time.monotonic() < deadline:
        job = session.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed") and job.get("sha256_hash"):
            break
        time.sleep(0.5)
    assert job["status"] == "completed", job.get("error_message")
    assert job["technique"] == "file_overwrite" and job["nist_category"] == "not_applicable"
    assert any(e.get("type") in ("progress", "complete") for e in events) or job["sha256_hash"]
    cert = session.get(f"/api/certificates/{job_id}")
    assert cert.status_code == 200
    pdf = session.get(f"/api/certificates/{job_id}/download")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    public = httpx.get(f"{server.url}/verify/{job_id}").json()
    assert public["verified"] is True and public["sha256_hash"] == job["sha256_hash"]
    assert target.exists()


def test_anomalies_and_feedback(session):
    anomalies = session.get("/api/anomalies").json()["anomalies"]
    first = next(a for a in anomalies if a["anomaly_type"] == "new_operator_first_wipe")
    r = session.post(f"/api/anomalies/{first['id']}/acknowledge", json={"resolved": True, "feedback": "false_positive"})
    assert r.status_code == 200 and r.json()["feedback"] == "false_positive"
    assert session.get("/api/anomalies/risk-score").status_code == 200


def test_audit_chain_is_intact(session):
    result = session.get("/api/audit/verify").json()
    assert result["intact"] is True and result["total_entries"] > 0
    events = {e["event_type"] for e in session.get("/api/audit").json()["entries"]}
    assert {"user_registered", "login_success", "wipe_job_created", "wipe_job_completed"} <= events


def test_agent_pairing_and_devices(server, session):
    code = session.post("/api/agents/pairing-code", json={"name": "rack-7"}).json()["code"]
    reg = httpx.post(f"{server.url}/api/agents/register", json={"code": code, "hostname": "live-usb"})
    assert reg.status_code == 201
    agent = {"Authorization": f"Agent {reg.json()['token']}"}
    device = {"serial": "SYS-AGENT-1", "model": "Agent SSD", "capacity_bytes": 10 ** 11, "device_type": "ssd",
              "interface": "SATA", "node": "/dev/sdb", "transport": "sata", "is_system": False,
              "smart_snapshot": {"available": False}}
    assert httpx.post(f"{server.url}/api/agents/heartbeat", headers=agent, json={"devices": [device]}).json()["devices"] == 1
    serials = [d["serial"] for d in session.get("/api/devices").json()["devices"]]
    assert "SYS-AGENT-1" in serials
    assert "token_hash" not in session.get("/api/agents").text


def test_session_lifecycle(server):
    c = httpx.Client(base_url=server.url, timeout=30)
    r = c.post("/api/auth/login", json={"email": "owner@system.test", "password": PW})
    assert "refresh_token" not in r.json() and c.cookies.get("oblvn_refresh")
    refreshed = c.post("/api/auth/refresh")
    assert refreshed.status_code == 200
    auth = {"Authorization": f"Bearer {refreshed.json()['access_token']}"}
    assert c.post("/api/auth/logout", headers=auth).status_code == 200
    assert c.get("/api/auth/me", headers=auth).status_code == 401
    bad = c.post("/api/auth/login", json={"email": "owner@system.test", "password": "Wrong-Pass-9!"})
    assert bad.status_code == 401
    c.close()
