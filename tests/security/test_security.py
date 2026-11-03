import time

import jwt
import pyotp
import pytest

from backend.accounts import mailer, service
from backend.accounts.service import AuthError
from backend.config import config, mongo_uri_problem
from backend.db import UnsafeValue
from tests.conftest import bearer

PW = "Correct-Horse-9!"
USER = "77777777-7777-7777-7777-777777777771"
OTHER = "77777777-7777-7777-7777-777777777772"


@pytest.fixture
def client(fake_db, monkeypatch):
    from fastapi.testclient import TestClient
    from backend.server import app, limiter
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", False)
    limiter.reset()
    with TestClient(app) as c:
        yield c


def _session(client, email="sec@b.io"):
    client.post("/api/auth/register", json={"email": email, "password": PW})
    r = client.post("/api/auth/login", json={"email": email, "password": PW})
    return r, {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestS2NoSqlInjection:
    def test_query_builder_rejects_operator_objects(self, fake_db):
        q = fake_db.svc.table("users").select("*")
        for call in (lambda: q.eq("email", {"$ne": None}), lambda: q.in_("email", [{"$gt": ""}]),
                     lambda: q.gte("created_at", {"$where": "1"}), lambda: q.order("$natural")):
            with pytest.raises(UnsafeValue):
                call()

    def test_documents_with_operator_keys_are_refused(self, fake_db):
        with pytest.raises(UnsafeValue):
            fake_db.svc.table("anomalies").insert({"anomaly_type": "x", "severity": "low",
                                                   "details": {"$where": "sleep(1000)"}}).execute()

    def test_login_with_operator_object_is_rejected(self, client):
        _session(client)
        r = client.post("/api/auth/login", json={"email": {"$ne": None}, "password": {"$ne": None}})
        assert r.status_code == 422

    def test_job_with_operator_serial_is_not_created(self, client, fake_db):
        _, auth = _session(client)
        r = client.post("/api/jobs", headers=auth, json={"method": "crypto_erase", "standard": "nist_800_88",
                                                          "device_serial": {"$ne": None}})
        assert r.status_code == 400 and fake_db.db.wipe_jobs.count_documents({}) == 0


class TestS1LocalOperations:
    def test_remote_clients_cannot_touch_server_disks_or_files(self, api, fake_db, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "LOCAL_OPS", "loopback")
        monkeypatch.setenv("OBLVN_FILE_WIPE_ROOTS", str(tmp_path))
        victim = tmp_path / "f.txt"
        victim.write_text("keep")
        r = api.post("/api/jobs", headers=bearer(USER), json={"method": "binary_overwrite", "standard": "nist_800_88",
                                                               "device_serial": f"file:{victim}"})
        assert r.status_code == 403 and victim.exists()
        for path in ("/api/utils/select-files", "/api/utils/select-folder", "/api/utils/select-items"):
            assert api.post(path, headers=bearer(USER)).status_code == 403
        assert api.get("/api/devices/refresh", headers=bearer(USER)).status_code == 403
        assert api.get("/api/devices", headers=bearer(USER)).json() == {"devices": []}

    def test_loopback_detection(self):
        from types import SimpleNamespace
        from backend.local_ops import is_loopback
        for host, expected in (("127.0.0.1", True), ("::1", True), ("localhost", True), ("10.0.0.5", False),
                               ("testclient", False), ("", False)):
            assert is_loopback(SimpleNamespace(client=SimpleNamespace(host=host))) is expected


class TestS3RefreshCookie:
    def test_refresh_token_only_in_httponly_cookie(self, client):
        r, auth = _session(client)
        assert "refresh_token" not in r.json()
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api/auth" in cookie
        refreshed = client.post("/api/auth/refresh")
        assert refreshed.status_code == 200 and "refresh_token" not in refreshed.json()
        out = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"})
        assert "oblvn_refresh=" in out.headers["set-cookie"] and "max-age=0" in out.headers["set-cookie"].lower()
        assert client.post("/api/auth/refresh").status_code == 401

    def test_secure_flag_in_production(self, client, monkeypatch):
        monkeypatch.setattr(config, "COOKIE_SECURE", True)
        r, _ = _session(client, "prod@b.io")
        assert "secure" in r.headers["set-cookie"].lower()


class TestS4WebSocketTickets:
    def test_tokens_in_url_are_refused_and_tickets_are_single_use(self, client, fake_db):
        _, auth = _session(client)
        uid = fake_db.db.users.find_one({"email": "sec@b.io"})["_id"]
        job = fake_db.svc.table("wipe_jobs").insert({"user_id": uid, "method": "crypto_erase", "standard": "nist_800_88",
                                                     "device_serial": "S", "device_model": "M", "device_capacity_bytes": 1,
                                                     "device_type": "nvme"}).execute().data[0]
        token = auth["Authorization"][7:]
        from starlette.websockets import WebSocketDisconnect
        with pytest.raises(Exception):
            with client.websocket_connect(f"/ws/jobs/{job['id']}?token={token}"):
                pass
        ticket = client.post(f"/api/jobs/{job['id']}/ws-ticket", headers=auth).json()["ticket"]
        with client.websocket_connect(f"/ws/jobs/{job['id']}?ticket={ticket}") as ws:
            ws.send_text("ping")
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/jobs/{job['id']}?ticket={ticket}") as ws:
                ws.receive_text()

    def test_other_users_cannot_get_a_ticket(self, client, fake_db):
        _, auth = _session(client)
        job = fake_db.svc.table("wipe_jobs").insert({"user_id": OTHER, "method": "crypto_erase", "standard": "nist_800_88",
                                                     "device_serial": "S", "device_model": "M", "device_capacity_bytes": 1,
                                                     "device_type": "nvme"}).execute().data[0]
        assert client.post(f"/api/jobs/{job['id']}/ws-ticket", headers=auth).status_code == 403

    def test_ticket_is_bound_to_its_job(self):
        from backend import realtime
        t = realtime.issue_ticket("u", "job-a")
        assert realtime.redeem_ticket(t, "job-b") is None and realtime.redeem_ticket(t, "job-a") is None


class TestS5S6HeadersAndDefaults:
    def test_security_headers(self, client):
        r = client.get("/api/health")
        h = r.headers
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert h["x-xss-protection"] == "0" and h["cache-control"] == "no-store"
        assert h["cross-origin-opener-policy"] == "same-origin-allow-popups"
        csp = h["content-security-policy"]
        script = next(p for p in csp.split("; ") if p.startswith("script-src"))
        assert "'unsafe-inline'" not in script and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
        assert "server" not in h

    def test_api_docs_are_not_public_outside_development(self, client):
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404

    def test_default_environment_is_production(self):
        import os
        import subprocess
        import sys
        env = {**os.environ, "FLASK_ENV": ""}
        out = subprocess.run([sys.executable, "-c", "from backend.config import Config as C; "
                              "print(C.ENV, C.DEBUG, C.COOKIE_SECURE)"], capture_output=True, text=True, env=env)
        assert out.stdout.split() == ["production", "False", "True"], out.stderr

    def test_errors_do_not_leak_details_outside_debug(self, monkeypatch):
        import backend.config as cfg
        from backend.security import safe_error_detail
        monkeypatch.setattr(cfg.config, "DEBUG", False)
        assert safe_error_detail(RuntimeError("mongodb://user:pw@host internal"), "generic") == "generic"


class TestS7NoSecretsInResponses:
    def test_psid_redacted_everywhere(self, client, fake_db):
        _, auth = _session(client)
        uid = fake_db.db.users.find_one({"email": "sec@b.io"})["_id"]
        job = fake_db.svc.table("wipe_jobs").insert({"user_id": uid, "method": "crypto_erase", "standard": "nist_800_88",
                                                     "device_serial": "S", "device_model": "M", "device_capacity_bytes": 1,
                                                     "device_type": "ssd", "options": {"psid": "SECRETPSID123"},
                                                     "status": "completed", "sha256_hash": "a" * 64}).execute().data[0]
        for path in ("/api/jobs", f"/api/jobs/{job['id']}", f"/api/certificates/{job['id']}"):
            body = client.get(path, headers=auth).text
            assert "SECRETPSID123" not in body and "psid_set" in body

    def test_profile_and_agents_hide_hashes(self, client, fake_db):
        _, auth = _session(client)
        me = client.get("/api/auth/me", headers=auth).text
        for word in ("password_hash", "mfa_secret", "recovery_codes", "argon2"):
            assert word not in me
        code = client.post("/api/agents/pairing-code", headers=auth, json={"name": "a"}).json()["code"]
        client.post("/api/agents/register", json={"code": code})
        assert "token_hash" not in client.get("/api/agents", headers=auth).text


class TestS8Transport:
    def test_mongodb_uri_must_use_tls_for_remote_hosts(self):
        assert mongo_uri_problem("mongodb+srv://u:p@cluster.mongodb.net/") is None
        assert mongo_uri_problem("mongodb://localhost:27017") is None
        assert mongo_uri_problem("mongodb://db.example.com:27017/?tls=true") is None
        assert mongo_uri_problem("mongodb://db.example.com:27017") is not None

    def test_smtp_refuses_credentials_without_tls(self, monkeypatch):
        for k, v in {"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "a@example.com", "SMTP_USER": "u",
                     "SMTP_STARTTLS": False, "SMTP_SSL": False}.items():
            monkeypatch.setattr(config, k, v)
        with pytest.raises(RuntimeError, match="without TLS"):
            mailer.send("x@example.com", "verify_email", "https://x")

    def test_agent_refuses_plain_http_to_remote_servers(self):
        from agent.client import check_server_url
        assert check_server_url("https://oblvn.example.com/") == "https://oblvn.example.com"
        assert check_server_url("http://localhost:8000")
        with pytest.raises(ValueError):
            check_server_url("http://oblvn.example.com")
        assert check_server_url("http://10.0.0.2:8000", allow_insecure=True)


class TestTokens:
    def test_tampered_tokens_are_rejected(self, client, fake_db):
        r, auth = _session(client)
        good = auth["Authorization"][7:]
        claims = jwt.decode(good, options={"verify_signature": False})
        forged = {
            "wrong secret": jwt.encode(claims, "x" * 48, algorithm="HS256"),
            "alg none": jwt.encode(claims, None, algorithm="none"),
            "expired": jwt.encode({**claims, "exp": int(time.time()) - 10}, config.JWT_SECRET, algorithm="HS256"),
            "wrong audience": jwt.encode({**claims, "aud": "anon"}, config.JWT_SECRET, algorithm="HS256"),
            "wrong issuer": jwt.encode({**claims, "iss": "supabase"}, config.JWT_SECRET, algorithm="HS256"),
            "other user": jwt.encode({**claims, "sub": OTHER, "sid": "nope"}, config.JWT_SECRET, algorithm="HS256"),
        }
        for name, token in forged.items():
            assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401, name
        assert client.get("/api/auth/me", headers=auth).status_code == 200


class TestS9S10AuthLimits:
    def test_two_factor_step_locks_after_five_wrong_codes(self, fake_db, monkeypatch):
        monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", False)
        service.sign_up("mfa@b.io", PW)
        uid = service.get_user_by_email("mfa@b.io")["id"]
        secret = service.mfa_setup(uid)["secret"]
        service.mfa_enable(uid, pyotp.TOTP(secret).now())
        step = service.sign_in("mfa@b.io", PW)
        for _ in range(4):
            with pytest.raises(AuthError) as e:
                service.sign_in_mfa(step["mfa_token"], "000000")
            assert e.value.code == "mfa_invalid"
        with pytest.raises(AuthError) as e:
            service.sign_in_mfa(step["mfa_token"], "000000")
        assert e.value.code == "mfa_expired"
        with pytest.raises(AuthError):
            service.sign_in_mfa(step["mfa_token"], pyotp.TOTP(secret).at(time.time() + 30))

    def test_overlong_password_is_rejected(self, client):
        r = client.post("/api/auth/register", json={"email": "long@b.io", "password": "Aa1!" + "x" * 200})
        assert r.status_code == 400 and "128" in r.json()["detail"]

    def test_login_is_rate_limited(self, client):
        codes = [client.post("/api/auth/login", json={"email": "rl@b.io", "password": "x"}).status_code for _ in range(25)]
        assert 429 in codes


class TestS11PdfRendering:
    def test_pdf_cannot_read_local_files_or_urls(self, tmp_path):
        from backend.platform_env import weasy_html
        secret = tmp_path / "secret.txt"
        secret.write_text("TOP-SECRET-VALUE")
        html = (f'<img src="file://{secret}"><img src="http://169.254.169.254/latest/meta-data/">'
                f'<link rel="attachment" href="file://{secret}"><p>ok</p>')
        assert b"TOP-SECRET-VALUE" not in weasy_html()(string=html).write_pdf()

    def test_audit_pdf_escapes_values(self, fake_db):
        from backend import audit
        audit.log_event("<script>alert(1)</script>", {}, user_id=None)
        rows = audit.export_json(None, None, None, user_id=None) if False else None
        html_rows = []
        original = audit.weasy_html

        def capture():
            def render(string, **kw):
                html_rows.append(string)
                return original()(string="<p>ok</p>")
            return render
        audit.weasy_html = capture
        try:
            fake_db.db.audit_log.update_many({}, {"$set": {"user_id": USER}})
            audit.export_pdf(None, None, None, user_id=USER)
        finally:
            audit.weasy_html = original
        assert rows is None and html_rows and "<script>alert(1)</script>" not in html_rows[0]
        assert "&lt;script&gt;" in html_rows[0]


class TestS12S13:
    def test_verify_is_rate_limited(self, client):
        codes = [client.get("/verify/11111111-1111-1111-1111-111111111111").status_code for _ in range(65)]
        assert 429 in codes

    def test_org_update_validation_and_last_admin(self, api, fake_db):
        org = "88888888-8888-8888-8888-888888888888"
        fake_db.tables["organisations"] = [{"id": org, "name": "Acme"}]
        fake_db.tables["org_memberships"] = [{"id": "m1", "user_id": USER, "org_id": org, "role": "org_admin"}]
        for bad in ({"audit_retention_days": "forever"}, {"name": "x" * 300}, {"timezone": "Mars/Base"},
                    {"work_start_hour": 30}, {"approval_gate_enabled": "yes"}, {"data_minimisation_config": {"$set": 1}}):
            assert api.patch(f"/api/orgs/{org}", headers=bearer(USER), json=bad).status_code == 400, bad
        ok = api.patch(f"/api/orgs/{org}", headers=bearer(USER), json={"timezone": "Asia/Kolkata", "work_start_hour": 9})
        assert ok.status_code == 200 and ok.json()["timezone"] == "Asia/Kolkata"
        assert api.delete(f"/api/orgs/{org}/members/{USER}", headers=bearer(USER)).status_code == 409
        assert api.patch(f"/api/orgs/{org}/members/{USER}/role", headers=bearer(USER),
                         json={"role": "operator"}).status_code == 409
