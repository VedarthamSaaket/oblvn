import time
from datetime import timedelta

import pyotp
import pytest

from backend.accounts import mailer, mfa, service
from backend.accounts.passwords import HASHER, hash_password, verify_password
from backend.accounts.service import AuthError
from backend.accounts.tokens import decode_access, digest
from backend.auth import validate_token
from backend.config import config

PW = "Correct-Horse-9!"


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, kind, link, **ctx: sent.append((to, kind, link)) or True)
    return sent


@pytest.fixture
def verified(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", False)


def token_from(link):
    return link.split("token=")[1].split("&")[0]


def test_argon2id_hashing():
    h = hash_password(PW)
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verify_password(h, PW) and not verify_password(h, "wrong")
    assert not verify_password(None, PW) and not verify_password("!unusable:x", PW)
    assert HASHER.time_cost == 3 and HASHER.memory_cost == 65536


def test_signup_requires_verification_then_login(fake_db, outbox, monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", True)
    r = service.sign_up("New@Example.com", PW)
    assert r["confirm_email"] and outbox[-1][1] == "verify_email" and outbox[-1][0] == "new@example.com"
    with pytest.raises(AuthError) as e:
        service.sign_in("new@example.com", PW)
    assert e.value.code == "email_not_confirmed"
    raw = token_from(outbox[-1][2])
    assert service.verify_email(raw)["email_confirmed_at"]
    with pytest.raises(AuthError):
        service.verify_email(raw)
    session = service.sign_in("new@example.com", PW)
    claims = decode_access(session["access_token"])
    assert claims["sub"] == session["user"]["id"] and claims["aud"] == "authenticated" and claims["iss"] == "oblvn"
    assert claims["exp"] - claims["iat"] == config.ACCESS_TOKEN_TTL
    assert validate_token(session["access_token"])["sub"] == session["user"]["id"]


def test_duplicate_signup_does_not_reveal_account(fake_db, outbox, verified):
    service.sign_up("a@b.io", PW)
    again = service.sign_up("a@b.io", "Other-Pass-1!")
    assert again["confirm_email"] is True and again["user"] is None


def test_lockout_after_threshold(fake_db, outbox, verified, monkeypatch):
    monkeypatch.setattr(config, "LOCKOUT_THRESHOLD", 3)
    service.sign_up("lock@b.io", PW)
    for _ in range(3):
        with pytest.raises(AuthError) as e:
            service.sign_in("lock@b.io", "bad")
        assert e.value.code == "invalid_credentials"
    with pytest.raises(AuthError) as e:
        service.sign_in("lock@b.io", PW)
    assert e.value.code == "locked" and e.value.status == 423
    with pytest.raises(AuthError) as e:
        service.sign_in("nobody@b.io", PW)
    assert e.value.code == "invalid_credentials"


def test_refresh_rotation_and_reuse_detection(fake_db, outbox, verified):
    service.sign_up("r@b.io", PW)
    first = service.sign_in("r@b.io", PW)
    second = service.refresh(first["refresh_token"])
    assert second["refresh_token"] != first["refresh_token"]
    assert validate_token(second["access_token"])
    with pytest.raises(AuthError) as e:
        service.refresh(first["refresh_token"])
    assert e.value.code == "refresh_reuse"
    assert validate_token(second["access_token"]) is None
    with pytest.raises(AuthError):
        service.refresh(second["refresh_token"])


def test_sign_out_revokes_access_immediately(fake_db, outbox, verified):
    service.sign_up("o@b.io", PW)
    s = service.sign_in("o@b.io", PW)
    sid = decode_access(s["access_token"])["sid"]
    service.sign_out(sid)
    assert validate_token(s["access_token"]) is None


def test_password_reset_revokes_sessions(fake_db, outbox, verified):
    service.sign_up("p@b.io", PW)
    s = service.sign_in("p@b.io", PW)
    service.request_password_reset("p@b.io")
    service.request_password_reset("ghost@b.io")
    assert [k for _, k, _ in outbox] == ["reset_password"]
    service.reset_password(token_from(outbox[-1][2]), "Brand-New-Pass-7!")
    assert validate_token(s["access_token"]) is None
    with pytest.raises(AuthError):
        service.sign_in("p@b.io", PW)
    assert service.sign_in("p@b.io", "Brand-New-Pass-7!")["access_token"]


def test_expired_token_rejected(fake_db, outbox, verified):
    service.sign_up("e@b.io", PW)
    service.request_password_reset("e@b.io")
    fake_db.db.auth_tokens.update_many({}, {"$set": {"expires_at": service._now() - timedelta(seconds=1)}})
    with pytest.raises(AuthError) as e:
        service.reset_password(token_from(outbox[-1][2]), "Brand-New-Pass-7!")
    assert e.value.code == "invalid_token"


def test_invite_creates_unusable_account_until_accepted(fake_db, outbox):
    r = service.invite("Invitee@B.io", "Acme", "team_lead")
    assert r["created"] and outbox[-1][1] == "invite" and "&invite=1" in outbox[-1][2]
    with pytest.raises(AuthError):
        service.sign_in("invitee@b.io", "")
    service.reset_password(token_from(outbox[-1][2]), "Invite-Accept-1!", "invite")
    assert service.sign_in("invitee@b.io", "Invite-Accept-1!")["user"]["email"] == "invitee@b.io"


def test_mfa_enroll_login_replay_and_recovery(fake_db, outbox, verified):
    service.sign_up("m@b.io", PW)
    uid = service.get_user_by_email("m@b.io")["id"]
    setup = service.mfa_setup(uid)
    assert setup["otpauth_uri"].startswith("otpauth://totp/OBLVN:m%40b.io") and setup["qr_png_base64"]
    stored = fake_db.db.users.find_one({"_id": uid})["mfa_pending_secret"]
    assert setup["secret"] not in stored and mfa.decrypt(stored) == setup["secret"]
    totp = pyotp.TOTP(setup["secret"])
    with pytest.raises(AuthError):
        service.mfa_enable(uid, "000000")
    codes = service.mfa_enable(uid, totp.now())
    assert len(codes) == 10
    step1 = service.sign_in("m@b.io", PW)
    assert step1["mfa_required"] and "access_token" not in step1
    with pytest.raises(AuthError):
        service.sign_in_mfa(step1["mfa_token"], totp.now())
    later = totp.at(time.time() + 30)
    session = service.sign_in_mfa(step1["mfa_token"], later)
    assert decode_access(session["access_token"])["amr"] == ["pwd", "mfa"]
    step2 = service.sign_in("m@b.io", PW)
    assert service.sign_in_mfa(step2["mfa_token"], codes[0])["access_token"]
    step3 = service.sign_in("m@b.io", PW)
    with pytest.raises(AuthError):
        service.sign_in_mfa(step3["mfa_token"], codes[0])
    assert digest(codes[0]) not in fake_db.db.users.find_one({"_id": uid})["recovery_codes"]


def test_mailer_escapes_and_uses_smtp(monkeypatch):
    subject, text, page = mailer.render("invite", "https://x/app/reset-password?token=t&invite=1",
                                        org="<script>", role="team lead")
    assert "&lt;script&gt;" in page and "<script>" not in page and "token=t&amp;invite=1" in page
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["host"] = (host, port)

        def starttls(self, context):
            sent["tls"] = True

        def login(self, user, password):
            sent["login"] = user

        def send_message(self, msg):
            sent["to"] = msg["To"]
            sent["subject"] = msg["Subject"]

        def quit(self):
            pass
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    for k, v in {"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "no-reply@example.com", "SMTP_USER": "u",
                 "SMTP_PASSWORD": "p", "SMTP_SSL": False, "SMTP_STARTTLS": True, "SMTP_PORT": 587}.items():
        monkeypatch.setattr(config, k, v)
    assert mailer.send("to@example.com", "verify_email", "https://x/verify?token=abc")
    assert sent == {"host": ("smtp.example.com", 587), "tls": True, "login": "u", "to": "to@example.com",
                    "subject": "Confirm your OBLVN account"}


def test_auth_http_flow(fake_db, outbox, monkeypatch):
    from fastapi.testclient import TestClient
    from backend.server import app
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", True)
    with TestClient(app) as client:
        r = client.post("/api/auth/register", json={"email": "flow@b.io", "password": PW})
        assert r.status_code == 201 and r.json()["confirm_email"] is True
        assert client.post("/api/auth/login", json={"email": "flow@b.io", "password": PW}).status_code == 403
        v = client.get(f"/api/auth/verify-email?token={token_from(outbox[-1][2])}", follow_redirects=False)
        assert v.status_code == 303 and v.headers["location"].endswith("/app/login?verified=1")
        bad = client.post("/api/auth/login", json={"email": "flow@b.io", "password": "Wrong-Pass-1!"})
        assert bad.status_code == 401 and bad.json()["detail"] == "Invalid login credentials"
        ok = client.post("/api/auth/login", json={"email": "flow@b.io", "password": PW}).json()
        auth = {"Authorization": f"Bearer {ok['access_token']}"}
        assert client.get("/api/auth/me", headers=auth).json()["email"] == "flow@b.io"
        new = client.post("/api/auth/refresh", json={"refresh_token": ok["refresh_token"]}).json()
        assert client.post("/api/auth/refresh", json={"refresh_token": ok["refresh_token"]}).status_code == 401
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 401
        events = [e["event_type"] for e in fake_db.tables["audit_log"]]
        assert "user_registered" in events and "email_verified" in events and "login_failed" in events
        assert "refresh_token_reuse" in events


def _claims(uid="fb-uid-1", email="g@b.io", verified=True, project="oblvn-test"):
    return {"sub": uid, "email": email, "email_verified": verified, "name": "G User",
            "iss": f"https://securetoken.google.com/{project}", "aud": project}


@pytest.fixture
def firebase(monkeypatch):
    monkeypatch.setattr(config, "FIREBASE_PROJECT_ID", "oblvn-test")
    state = {"claims": _claims()}

    def fake_verify(token, request, audience):
        assert audience == "oblvn-test"
        if token != "good":
            raise ValueError("bad token")
        return state["claims"]
    from google.oauth2 import id_token
    monkeypatch.setattr(id_token, "verify_firebase_token", fake_verify)
    return state


def test_firebase_creates_account_and_session(fake_db, firebase):
    r = service.sign_in_firebase("good")
    assert r["is_new"] and decode_access(r["access_token"])["amr"] == ["google"]
    user = fake_db.db.users.find_one({"email": "g@b.io"})
    assert user["firebase_uid"] == "fb-uid-1" and user["email_confirmed_at"] and user["password_hash"].startswith("!")
    again = service.sign_in_firebase("good")
    assert not again["is_new"] and again["user"]["id"] == r["user"]["id"]
    with pytest.raises(AuthError):
        service.sign_in("g@b.io", "")


def test_firebase_links_existing_password_account(fake_db, firebase, outbox, verified):
    service.sign_up("g@b.io", PW)
    r = service.sign_in_firebase("good")
    assert not r["is_new"]
    assert service.get_user(r["user"]["id"])["providers"] == ["password", "google"]
    assert service.sign_in("g@b.io", PW)["access_token"]


def test_firebase_rejections(fake_db, firebase, monkeypatch):
    with pytest.raises(AuthError) as e:
        service.sign_in_firebase("forged")
    assert e.value.code == "firebase_invalid"
    firebase["claims"] = _claims(verified=False)
    with pytest.raises(AuthError):
        service.sign_in_firebase("good")
    firebase["claims"] = _claims(project="someone-else")
    with pytest.raises(AuthError):
        service.sign_in_firebase("good")
    firebase["claims"] = _claims()
    service.sign_in_firebase("good")
    firebase["claims"] = _claims(uid="other-google-account")
    with pytest.raises(AuthError) as e:
        service.sign_in_firebase("good")
    assert e.value.code == "firebase_conflict"
    monkeypatch.setattr(config, "FIREBASE_PROJECT_ID", "")
    with pytest.raises(AuthError) as e:
        service.sign_in_firebase("good")
    assert e.value.status == 503


def test_firebase_respects_mfa(fake_db, firebase):
    first = service.sign_in_firebase("good")
    uid = first["user"]["id"]
    secret = service.mfa_setup(uid)["secret"]
    service.mfa_enable(uid, pyotp.TOTP(secret).now())
    step = service.sign_in_firebase("good")
    assert step["mfa_required"] and "access_token" not in step
    session = service.sign_in_mfa(step["mfa_token"], pyotp.TOTP(secret).at(time.time() + 30))
    assert decode_access(session["access_token"])["amr"] == ["google", "mfa"]


def test_firebase_http_route(fake_db, firebase):
    from fastapi.testclient import TestClient
    from backend.server import app
    with TestClient(app) as client:
        ok = client.post("/api/auth/firebase", json={"id_token": "good"})
        assert ok.status_code == 200 and ok.json()["is_new"] is True and ok.json()["access_token"]
        assert client.post("/api/auth/firebase", json={"id_token": "forged"}).status_code == 401
        events = [(e["event_type"], (e["event_payload"] if isinstance(e["event_payload"], str) else "")) for e in fake_db.tables["audit_log"]]
        assert any(t == "user_registered" and "google" in p for t, p in events)
        assert any(t == "login_success" for t, _ in events)
