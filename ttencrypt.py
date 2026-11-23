import gzip
import hashlib
import os
from dataclasses import dataclass

from Crypto.Cipher import AES


class SealError(ValueError):
    pass


@dataclass(frozen=True)
class _Envelope:
    nonce: bytes
    sealed: bytes

    @classmethod
    def open(cls, blob):
        if len(blob) < 6 + 32 + 16:
            raise SealError("payload too short for TTEncrypt")
        head, rest = blob[:6], blob[6:]
        if head != b"\x74\x63\x05\x10\x00\x00":
            raise SealError("bad TTEncrypt magic: %s" % head.hex())
        nonce, sealed = rest[:32], rest[32:]
        if len(sealed) % 16:
            raise SealError("ciphertext length is not a multiple of 16")
        return cls(nonce, sealed)

    def close(self):
        return b"\x74\x63\x05\x10\x00\x00" + self.nonce + self.sealed


def _cipher_for(nonce):
    seasoning = bytes.fromhex(
        "4dd4c2e6b8316209"
        "0e52b3c7a6733ba4"
        "1cb2462b829ab58a"
        "196b39db57177524"
        "f49baf7f08e8d68d"
        "26a72e37c1a95a2f"
        "1f05a51892aef294"
        "9732b62a38aadd58"
    )
    stir = hashlib.sha512(hashlib.sha512(nonce).digest() + seasoning).digest()
    return AES.new(stir[:16], AES.MODE_CBC, stir[16:32])


def _stuff(buf):
    gap = 16 - (len(buf) % 16)
    return buf + bytes([gap]) * gap


def _strip(buf):
    gap = buf[-1]
    if gap < 1 or gap > 16 or buf[-gap:] != bytes([gap]) * gap:
        raise SealError(
            "bad padding: not a TTEncrypt ciphertext (payloads written by the "
            "original implementation can be corrupt: it lets a salt byte be "
            "256, hashes it as 256, then writes 0 -- roughly 1 in 9 payloads)"
        )
    return buf[:-gap]


def _coerce(value):
    if isinstance(value, str):
        return value.encode("latin-1")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError("expected bytes-like or str")


def _squash(raw):
    packed = gzip.compress(raw, compresslevel=9, mtime=0)
    return (bytes([31, 139, 8]) + bytes(7)) + packed[10:]


def enc(payload, nonce=None):
    raw = payload.encode() if isinstance(payload, str) else bytes(payload)
    packed = _squash(raw)

    nonce = os.urandom(32) if nonce is None else _coerce(nonce)
    if len(nonce) != 32:
        raise SealError("nonce must be 32 bytes")

    framed = hashlib.sha512(packed).digest() + packed
    return _Envelope(nonce, _cipher_for(nonce).encrypt(_stuff(framed))).close()


def dec(blob, encoding="utf-8"):
    env = _Envelope.open(_coerce(blob))
    framed = _strip(_cipher_for(env.nonce).decrypt(env.sealed))
    raw = gzip.decompress(framed[64:])
    return raw if encoding is None else raw.decode(encoding)


class Vault:
    def __init__(self, nonce=None):
        self.nonce = nonce

    def encrypt(self, payload, nonce=None):
        return enc(payload, self.nonce if nonce is None else nonce)

    def decrypt(self, blob, encoding="utf-8"):
        return dec(blob, encoding)
