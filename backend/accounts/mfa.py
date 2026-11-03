import base64
import io
import secrets

import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.accounts.tokens import digest
from backend.config import config

ISSUER = "OBLVN"
RECOVERY_CODES = 10


def _key() -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"oblvn-mfa", info=b"totp-secret").derive(
        config.SECRET_KEY.encode())


def encrypt(secret: str) -> str:
    nonce = secrets.token_bytes(12)
    return base64.b64encode(nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), b"totp")).decode()


def decrypt(blob: str) -> str:
    raw = base64.b64decode(blob)
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], b"totp").decode()


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning(secret: str, email: str) -> dict:
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)
    import qrcode
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {"secret": secret, "otpauth_uri": uri, "qr_png_base64": base64.b64encode(buf.getvalue()).decode()}


def verify_code(secret: str, code: str, last_step: int | None) -> int | None:
    totp = pyotp.TOTP(secret)
    code = (code or "").replace(" ", "")
    if not code.isdigit():
        return None
    import time
    now = int(time.time())
    for offset in (-1, 0, 1):
        step = now // 30 + offset
        if last_step is not None and step <= last_step:
            continue
        if totp.at(step * 30) == code:
            return step
    return None


def recovery_codes() -> tuple[list[str], list[str]]:
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_CODES)]
    return codes, [digest(c) for c in codes]
