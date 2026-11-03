import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from backend.hw.patterns import static_chunk


class Keystream:
    def __init__(self, key: bytes | None = None, nonce: bytes | None = None):
        self._key = bytearray(key or secrets.token_bytes(32))
        self.nonce = nonce or secrets.token_bytes(8)

    def at(self, offset: int, length: int) -> bytes:
        lead = offset % 16
        start = offset - lead
        iv = self.nonce + (start // 16).to_bytes(8, "big")
        enc = Cipher(algorithms.AES(bytes(self._key)), modes.CTR(iv)).encryptor()
        return enc.update(bytes(length + lead))[lead:]

    def destroy(self) -> None:
        for i in range(len(self._key)):
            self._key[i] = 0

    @property
    def destroyed(self) -> bool:
        return not any(self._key)


def tiled(unit: bytes, offset: int, length: int) -> bytes:
    period = len(unit)
    start = offset % period
    reps = (start + length) // period + 1
    return (unit * reps)[start:start + length]


def source_for(p: dict, keystream: Keystream | None = None):
    if p["pattern"] == "random":
        ks = keystream or Keystream()
        return ks.at, ks
    unit = static_chunk(p, 4096 if p["pattern"] != "bytes" else len(p.get("data") or b"\x00"))
    return (lambda offset, length: tiled(unit, offset, length)), None
