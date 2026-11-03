from typing import Any

from fastapi import HTTPException, Request

from backend.accounts.service import session_active
from backend.accounts.tokens import decode_access
from backend.db import get_service_client

ROLES = {"org_admin": 3, "team_lead": 2, "operator": 1, "individual": 0}


def validate_token(token: str) -> dict[str, Any] | None:
    payload = decode_access(token)
    if not payload:
        return None
    try:
        if not session_active(payload["sid"]):
            return None
    except Exception:
        return None
    return payload


def get_user_role(user_id: str, org_id: str | None) -> str:
    if not org_id:
        return "individual"
    r = (get_service_client().table("org_memberships").select("role")
         .eq("user_id", user_id).eq("org_id", org_id).maybe_single().execute())
    return r.data["role"] if r.data else "individual"


def current_user(request: Request) -> dict:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization token")
    token = header[7:]
    payload = validate_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"user_id": payload.get("sub"), "token": token, "payload": payload, "session_id": payload.get("sid")}
