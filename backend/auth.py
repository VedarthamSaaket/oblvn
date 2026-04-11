from typing import Any
import requests
from jose import jwt
from jose.exceptions import JWTError

from backend.config import config
from backend.supabase_client import get_service_client

ROLES = {"org_admin": 3, "team_lead": 2, "operator": 1, "individual": 0}

# Supabase JWKS endpoint (public keys for ES256 verification)
JWKS_URL = f"{config.SUPABASE_URL}/auth/v1/.well-known/jwks.json"

_jwks_cache: dict[str, Any] | None = None


def _get_jwks() -> dict[str, Any]:
    global _jwks_cache
    if _jwks_cache is None:
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache


def validate_token(token: str) -> dict[str, Any] | None:
    try:
        jwks = _get_jwks()

        # Verify ES256 token using Supabase public keys
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["ES256"],
            audience="authenticated",
            issuer=f"{config.SUPABASE_URL}/auth/v1",
            options={"verify_exp": True},
        )

        return payload

    except JWTError:
        return None
    except Exception:
        return None


def get_user_role(user_id: str, org_id: str | None) -> str:
    if not org_id:
        return "individual"

    svc = get_service_client()
    r = (
        svc.table("org_memberships")
        .select("role")
        .eq("user_id", user_id)
        .eq("org_id", org_id)
        .maybe_single()
        .execute()
    )

    return r.data["role"] if r.data else "individual"