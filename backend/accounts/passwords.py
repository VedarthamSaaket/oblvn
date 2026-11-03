from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
UNUSABLE_PREFIX = "!unusable:"
_DUMMY = HASHER.hash("oblvn-timing-equaliser")


def hash_password(password: str) -> str:
    return HASHER.hash(password)


def unusable() -> str:
    import secrets
    return UNUSABLE_PREFIX + secrets.token_hex(16)


def verify_password(stored: str | None, password: str) -> bool:
    if not stored or stored.startswith(UNUSABLE_PREFIX):
        try:
            HASHER.verify(_DUMMY, password)
        except VerificationError:
            pass
        return False
    try:
        return HASHER.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        return HASHER.check_needs_rehash(stored)
    except InvalidHashError:
        return True
