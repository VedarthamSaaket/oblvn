import pytest

from tests.conftest import bearer

USER = "66666666-6666-6666-6666-666666666666"
DEVICE = {"serial": "AGENT-SER-1", "model": "Agent Disk", "capacity_bytes": 10 ** 10, "device_type": "nvme",
          "interface": "NVMe", "node": "/dev/nvme1n1", "transport": "nvme", "is_system": False,
          "smart_snapshot": {"available": False}}


@pytest.fixture(autouse=True)
def no_local_devices(monkeypatch):
    from backend import server
    from backend.detector import DeviceDetectionError

    def none():
        raise DeviceDetectionError("no local disks in tests")
    monkeypatch.setattr(server, "detect_devices", none)
    monkeypatch.setattr(server, "get_device_by_serial", lambda serial: None)


def test_requires_auth(api):
    assert api.get("/api/jobs").status_code == 401
    assert api.get("/api/agents/jobs/next").status_code == 401


def test_file_job_outside_roots_is_rejected(api, tmp_path, monkeypatch):
    monkeypatch.setenv("OBLVN_FILE_WIPE_ROOTS", str(tmp_path / "allowed"))
    (tmp_path / "allowed").mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    r = api.post("/api/jobs", headers=bearer(USER), json={
        "method": "binary_overwrite", "standard": "nist_800_88", "device_serial": f"file:{victim}"})
    assert r.status_code == 400 and "outside" in r.json()["detail"]
    assert victim.exists()


def test_system_device_is_refused(api, monkeypatch):
    from backend import server
    monkeypatch.setattr(server, "get_device_by_serial",
                        lambda s: {**DEVICE, "is_system": True, "system_reason": "hosts /"})
    r = api.post("/api/jobs", headers=bearer(USER), json={
        "method": "crypto_erase", "standard": "nist_800_88", "device_serial": DEVICE["serial"]})
    assert r.status_code == 400 and "hosts /" in r.json()["detail"]


def test_verify_endpoint_hides_unfinished_jobs(api, fake_db):
    fake_db.tables["wipe_jobs"] = [{"id": "77777777-7777-7777-7777-777777777777", "status": "failed",
                                    "sha256_hash": None}]
    assert api.get("/verify/77777777-7777-7777-7777-777777777777").status_code == 404


def test_agent_end_to_end(api, fake_db, monkeypatch):
    from backend import jobs
    fake_db.users[USER] = "op@example.com"
    monkeypatch.setattr(jobs, "generate_certificate", lambda job, user, org, approver, record: {
        "certificate_id": job["id"], "pdf_path": "/tmp/x.pdf", "ots_path": None,
        "fields": {"sha256_hash": "a" * 64, "verify_url": "http://x/verify"}})
    monkeypatch.setattr(jobs.threading, "Thread", _InlineThread)
    import backend.agent_api as agent_api
    monkeypatch.setattr(agent_api.threading, "Thread", _InlineThread)

    code = api.post("/api/agents/pairing-code", headers=bearer(USER), json={"name": "rack-1"}).json()["code"]
    reg = api.post("/api/agents/register", json={"code": code, "hostname": "live", "platform": "Linux"})
    assert reg.status_code == 201
    agent = {"Authorization": f"Agent {reg.json()['token']}"}
    assert api.post("/api/agents/register", json={"code": code}).status_code == 400

    assert api.post("/api/agents/heartbeat", headers=agent, json={"devices": [DEVICE]}).json()["devices"] == 1
    devices = api.get("/api/devices", headers=bearer(USER)).json()["devices"]
    assert devices[0]["serial"] == DEVICE["serial"] and devices[0]["agent_name"] == "rack-1"

    created = api.post("/api/jobs", headers=bearer(USER), json={
        "method": "crypto_erase", "standard": "nist_800_88", "device_serial": DEVICE["serial"]})
    assert created.status_code == 201
    job = created.json()
    assert job["agent_id"] == reg.json()["agent_id"] and job["status"] == "queued"

    claimed = api.get("/api/agents/jobs/next", headers=agent).json()["job"]
    assert claimed["id"] == job["id"] and claimed["device"]["node"] == "/dev/nvme1n1"
    assert api.get("/api/agents/jobs/next", headers=agent).json()["job"] is None
    assert api.post(f"/api/agents/jobs/{job['id']}/progress", headers=agent,
                    json={"type": "progress", "overall_pct": 50}).json() == {"cancel": False}

    record = {"technique": "nvme_sanitize_crypto", "nist_category": "purge", "passes_completed": 1,
              "verification": {"check": "changed", "passed": True},
              "telemetry": {"total_seconds": 4.2, "bytes_written": 0}}
    assert api.post(f"/api/agents/jobs/{job['id']}/result", headers=agent,
                    json={"ok": True, "record": record}).status_code == 200
    row = next(j for j in fake_db.tables["wipe_jobs"] if j["id"] == job["id"])
    assert row["status"] == "completed" and row["nist_category"] == "purge" and row["sha256_hash"] == "a" * 64


def test_agent_failed_verification_never_completes(api, fake_db, monkeypatch):
    from backend import jobs
    import backend.agent_api as agent_api
    monkeypatch.setattr(agent_api.threading, "Thread", _InlineThread)
    called = []
    monkeypatch.setattr(jobs, "generate_certificate", lambda *a: called.append(a))
    fake_db.tables["agents"] = [{"id": "88888888-8888-8888-8888-888888888888", "user_id": USER, "org_id": None,
                                 "name": "a", "token_hash": agent_api._hash("tok"), "revoked_at": None}]
    fake_db.tables["wipe_jobs"] = [{"id": "99999999-9999-9999-9999-999999999999", "status": "running",
                                    "user_id": USER, "org_id": None, "device_serial": "S",
                                    "agent_id": "88888888-8888-8888-8888-888888888888"}]
    r = api.post("/api/agents/jobs/99999999-9999-9999-9999-999999999999/result",
                 headers={"Authorization": "Agent tok"},
                 json={"ok": True, "record": {"verification": {"passed": False}}})
    assert r.status_code == 200
    assert fake_db.tables["wipe_jobs"][0]["status"] == "failed" and not called


def test_approve_requires_pending_status(api, fake_db):
    org = "12121212-1212-1212-1212-121212121212"
    fake_db.tables["org_memberships"] = [{"user_id": USER, "org_id": org, "role": "team_lead"}]
    fake_db.tables["wipe_jobs"] = [{"id": "13131313-1313-1313-1313-131313131313", "org_id": org,
                                    "status": "completed", "agent_id": None}]
    r = api.post("/api/jobs/13131313-1313-1313-1313-131313131313/approve", headers=bearer(USER), json={"org_id": org})
    assert r.status_code == 409


class _InlineThread:
    def __init__(self, target=None, args=(), kwargs=None, **_):
        self.target, self.args, self.kwargs = target, args, kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)
