import hashlib
import secrets
import time

import jwt

from backend.config import config

ALGORITHM = "HS256"
ISSUER = "oblvn"
AUDIENCE = "authenticated"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret(nbytes: int = 48) -> str:
    return secrets.token_urlsafe(nbytes)


def issue_access(user: dict, session_id: str, amr: list[str]) -> str:
    now = int(time.time())
    claims = {
        "sub": user["id"],
        "email": user["email"],
        "role": "authenticated",
        "aud": AUDIENCE,
        "iss": ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + config.ACCESS_TOKEN_TTL,
        "sid": session_id,
        "amr": amr,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm=ALGORITHM)


def decode_access(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER,
                          options={"require": ["exp", "sub", "sid", "iat"]})
    except jwt.PyJWTError:
        return None
