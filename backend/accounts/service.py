from datetime import datetime, timedelta, timezone

from backend.accounts import mailer, mfa
from backend.accounts.passwords import hash_password, needs_rehash, unusable, verify_password
from backend.accounts.tokens import digest, issue_access, new_secret
from backend.config import config
from backend.db import DuplicateKey, get_database, get_service_client

TOKEN_TTL = {"verify_email": timedelta(hours=24), "reset_password": timedelta(hours=1),
             "invite": timedelta(days=7), "mfa_login": timedelta(minutes=5)}


class AuthError(Exception):
    def __init__(self, status: int, message: str, code: str):
        super().__init__(message)
        self.status = status
        self.code = code


INVALID = AuthError(401, "Invalid login credentials", "invalid_credentials")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _users():
    return get_database()["users"]


def _public(user: dict) -> dict:
    return {"id": user["_id"], "email": user["email"], "email_confirmed_at": user.get("email_confirmed_at"),
            "mfa_enabled": bool(user.get("mfa_enabled")), "created_at": user.get("created_at"),
            "last_sign_in_at": user.get("last_sign_in_at")}


def get_user(user_id: str) -> dict | None:
    u = _users().find_one({"_id": user_id})
    return _public(u) if u else None


def get_user_by_email(email: str) -> dict | None:
    u = _users().find_one({"email": email.strip().lower()})
    return _public(u) if u else None


def _link(path: str, token: str) -> str:
    return f"{config.PUBLIC_URL.rstrip('/')}{path}?token={token}"


def _issue_token(user_id: str, purpose: str, extra: dict | None = None) -> str:
    raw = new_secret(32)
    get_service_client().table("auth_tokens").insert({
        "user_id": user_id, "purpose": purpose, "token_hash": digest(raw),
        "expires_at": _now() + TOKEN_TTL[purpose], **(extra or {}),
    }).execute()
    return raw


def _consume_token(raw: str, purpose: str) -> dict:
    coll = get_database()["auth_tokens"]
    doc = coll.find_one_and_update(
        {"token_hash": digest(raw or ""), "purpose": purpose, "used_at": None, "expires_at": {"$gt": _now()}},
        {"$set": {"used_at": _now()}},
    )
    if not doc:
        raise AuthError(400, "This link is invalid or has expired", "invalid_token")
    return doc


def sign_up(email: str, password: str) -> dict:
    email = email.strip().lower()
    confirmed = None if config.REQUIRE_EMAIL_VERIFICATION else _now().isoformat()
    try:
        row = get_service_client().table("users").insert({
            "email": email, "password_hash": hash_password(password), "email_confirmed_at": confirmed,
        }).execute().data[0]
    except DuplicateKey:
        existing = get_user_by_email(email)
        if existing and not existing["email_confirmed_at"]:
            send_verification(existing["id"])
        return {"user": None, "confirm_email": True}
    if not confirmed:
        send_verification(row["id"])
        return {"user": None, "confirm_email": True, "user_id": row["id"]}
    return {"user": {"id": row["id"], "email": email}, "confirm_email": False, "user_id": row["id"]}


def send_verification(user_id: str) -> None:
    user = get_user(user_id)
    if user and not user["email_confirmed_at"]:
        mailer.send(user["email"], "verify_email", _link("/api/auth/verify-email", _issue_token(user_id, "verify_email")))


def verify_email(raw: str) -> dict:
    doc = _consume_token(raw, "verify_email")
    _users().update_one({"_id": doc["user_id"], "email_confirmed_at": None},
                        {"$set": {"email_confirmed_at": _now().isoformat()}})
    return get_user(doc["user_id"])


def _start_session(user: dict, amr: list[str], family: str | None = None) -> dict:
    refresh = new_secret()
    expires = _now() + timedelta(seconds=config.REFRESH_TOKEN_TTL)
    session = get_service_client().table("sessions").insert({
        "user_id": user["_id"], "refresh_hash": digest(refresh), "family": family or new_secret(12),
        "expires_at": expires, "amr": amr,
    }).execute().data[0]
    _users().update_one({"_id": user["_id"]}, {"$set": {"last_sign_in_at": _now().isoformat()}})
    return {
        "access_token": issue_access({"id": user["_id"], "email": user["email"]}, session["id"], amr),
        "refresh_token": refresh,
        "expires_in": config.ACCESS_TOKEN_TTL,
        "token_type": "bearer",
        "user": {"id": user["_id"], "email": user["email"]},
    }


def _failed(user: dict) -> None:
    count = int(user.get("failed_logins") or 0) + 1
    update = {"failed_logins": count}
    if count >= config.LOCKOUT_THRESHOLD:
        update["locked_until"] = _now() + timedelta(minutes=config.LOCKOUT_MINUTES)
        update["failed_logins"] = 0
    _users().update_one({"_id": user["_id"]}, {"$set": update})


def sign_in(email: str, password: str) -> dict:
    user = _users().find_one({"email": email.strip().lower()})
    if not verify_password(user.get("password_hash") if user else None, password):
        if user:
            _failed(user)
        raise INVALID
    locked = user.get("locked_until")
    if locked and (locked if locked.tzinfo else locked.replace(tzinfo=timezone.utc)) > _now():
        raise AuthError(423, "Too many failed attempts. Try again in a few minutes.", "locked")
    if not user.get("email_confirmed_at"):
        raise AuthError(403, "Email not confirmed. Check your inbox for the confirmation link.", "email_not_confirmed")
    updates = {"failed_logins": 0, "locked_until": None}
    if needs_rehash(user["password_hash"]):
        updates["password_hash"] = hash_password(password)
    _users().update_one({"_id": user["_id"]}, {"$set": updates})
    if user.get("mfa_enabled"):
        return {"mfa_required": True, "mfa_token": _issue_token(user["_id"], "mfa_login"),
                "user": {"id": user["_id"], "email": user["email"]}}
    return _start_session(user, ["pwd"])


def sign_in_mfa(mfa_token: str, code: str) -> dict:
    coll = get_database()["auth_tokens"]
    doc = coll.find_one({"token_hash": digest(mfa_token or ""), "purpose": "mfa_login", "used_at": None,
                         "expires_at": {"$gt": _now()}})
    if not doc:
        raise AuthError(401, "Two-factor session expired. Sign in again.", "mfa_expired")
    user = _users().find_one({"_id": doc["user_id"]})
    if not user or not _check_second_factor(user, code):
        raise AuthError(401, "Invalid two-factor code", "mfa_invalid")
    coll.update_one({"_id": doc["_id"]}, {"$set": {"used_at": _now()}})
    return _start_session(user, ["pwd", "mfa"])


def _check_second_factor(user: dict, code: str) -> bool:
    secret = mfa.decrypt(user["mfa_secret"]) if user.get("mfa_secret") else None
    step = mfa.verify_code(secret, code, user.get("mfa_last_step")) if secret else None
    if step is not None:
        _users().update_one({"_id": user["_id"]}, {"$set": {"mfa_last_step": step}})
        return True
    hashed = digest((code or "").strip().lower())
    if hashed in (user.get("recovery_codes") or []):
        _users().update_one({"_id": user["_id"]}, {"$pull": {"recovery_codes": hashed}})
        return True
    return False


def refresh(raw: str) -> dict:
    sessions = get_database()["sessions"]
    current = sessions.find_one({"refresh_hash": digest(raw or "")})
    if not current:
        raise AuthError(401, "Token refresh failed", "invalid_refresh")
    expires = current["expires_at"] if current["expires_at"].tzinfo else current["expires_at"].replace(tzinfo=timezone.utc)
    if current.get("revoked_at"):
        sessions.update_many({"family": current["family"], "revoked_at": None},
                             {"$set": {"revoked_at": _now(), "revoke_reason": "refresh_token_reuse"}})
        raise AuthError(401, "Token refresh failed", "refresh_reuse")
    if expires <= _now():
        raise AuthError(401, "Token refresh failed", "refresh_expired")
    user = _users().find_one({"_id": current["user_id"]})
    if not user:
        raise AuthError(401, "Token refresh failed", "invalid_refresh")
    fresh = _start_session(user, current.get("amr") or ["pwd"], family=current["family"])
    new = sessions.find_one({"refresh_hash": digest(fresh["refresh_token"])})
    sessions.update_one({"_id": current["_id"]}, {"$set": {"revoked_at": _now(), "replaced_by": new["_id"]}})
    return fresh


def session_active(session_id: str) -> bool:
    s = get_database()["sessions"].find_one({"_id": session_id}, {"revoked_at": 1, "family": 1})
    if not s:
        return False
    if not s.get("revoked_at"):
        return True
    return get_database()["sessions"].count_documents({"family": s["family"], "revoked_at": None}) > 0


def sign_out(session_id: str) -> None:
    s = get_database()["sessions"].find_one({"_id": session_id})
    if s:
        get_database()["sessions"].update_many({"family": s["family"], "revoked_at": None},
                                               {"$set": {"revoked_at": _now(), "revoke_reason": "sign_out"}})


def revoke_all(user_id: str, reason: str) -> None:
    get_database()["sessions"].update_many({"user_id": user_id, "revoked_at": None},
                                           {"$set": {"revoked_at": _now(), "revoke_reason": reason}})


def request_password_reset(email: str) -> None:
    user = get_user_by_email(email)
    if user:
        mailer.send(user["email"], "reset_password", _link("/app/reset-password", _issue_token(user["id"], "reset_password")))


def reset_password(raw: str, new_password: str, purpose: str = "reset_password") -> dict:
    doc = _consume_token(raw, purpose)
    updates = {"password_hash": hash_password(new_password), "failed_logins": 0, "locked_until": None}
    if purpose == "invite" or not get_user(doc["user_id"])["email_confirmed_at"]:
        updates["email_confirmed_at"] = _now().isoformat()
    _users().update_one({"_id": doc["user_id"]}, {"$set": updates})
    revoke_all(doc["user_id"], "password_reset")
    return get_user(doc["user_id"])


def invite(email: str, org_name: str, role: str) -> dict:
    email = email.strip().lower()
    user = get_user_by_email(email)
    created = False
    if not user:
        row = get_service_client().table("users").insert({"email": email, "password_hash": unusable()}).execute().data[0]
        user, created = get_user(row["id"]), True
    if created or not user["email_confirmed_at"]:
        token = _issue_token(user["id"], "invite")
        mailer.send(email, "invite", _link("/app/reset-password", token) + "&invite=1", org=org_name, role=role.replace("_", " "))
    return {"user": user, "created": created}


def mfa_setup(user_id: str) -> dict:
    user = _users().find_one({"_id": user_id})
    secret = mfa.new_secret()
    _users().update_one({"_id": user_id}, {"$set": {"mfa_pending_secret": mfa.encrypt(secret)}})
    return mfa.provisioning(secret, user["email"])


def mfa_enable(user_id: str, code: str) -> list[str]:
    user = _users().find_one({"_id": user_id})
    pending = user.get("mfa_pending_secret")
    if not pending:
        raise AuthError(400, "Start two-factor setup first", "mfa_not_started")
    step = mfa.verify_code(mfa.decrypt(pending), code, None)
    if step is None:
        raise AuthError(400, "Invalid two-factor code", "mfa_invalid")
    codes, hashed = mfa.recovery_codes()
    _users().update_one({"_id": user_id}, {"$set": {"mfa_enabled": True, "mfa_secret": pending, "mfa_last_step": step,
                                                     "recovery_codes": hashed}, "$unset": {"mfa_pending_secret": ""}})
    return codes


def mfa_disable(user_id: str, code: str) -> None:
    user = _users().find_one({"_id": user_id})
    if not user.get("mfa_enabled") or not _check_second_factor(user, code):
        raise AuthError(400, "Invalid two-factor code", "mfa_invalid")
    _users().update_one({"_id": user_id}, {"$set": {"mfa_enabled": False, "mfa_secret": None, "recovery_codes": []}})
