"""Password hashing, AES-256-GCM encryption, and signed cookies — ported to
be byte-for-byte compatible with express's src/lib/{encryption,auth}.ts so
sessions/settings/passwords interop across the language ports.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

# node-argon2 defaults: m=65536 (KiB), t=3, p=4 — argon2-cffi's defaults match.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+daw"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(hash_: str, password: str) -> bool:
    try:
        return _hasher.verify(hash_, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def dummy_password_check() -> None:
    check_password(_DUMMY_HASH, "dummy")


# --- AES-256-GCM (iv[12] || tag[16] || ciphertext, matching Node's layout) ---

_IV_LEN = 12
_TAG_LEN = 16


def _key() -> bytes:
    return hashlib.sha256(settings.encryption_key.encode()).digest()


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    iv = secrets.token_bytes(_IV_LEN)
    aesgcm = AESGCM(_key())
    sealed = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    ct, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    return base64.b64encode(iv + tag + ct).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        buf = base64.b64decode(ciphertext)
        if len(buf) < _IV_LEN + _TAG_LEN:
            return ciphertext
        iv, tag, ct = buf[:_IV_LEN], buf[_IV_LEN : _IV_LEN + _TAG_LEN], buf[_IV_LEN + _TAG_LEN :]
        aesgcm = AESGCM(_key())
        plain = aesgcm.decrypt(iv, ct + tag, None)
        return plain.decode("utf-8")
    except Exception:
        return ciphertext


# --- Random helpers ---

_ALNUM = string.ascii_letters + string.digits


def random_alnum(length: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(length))


def random_handle() -> str:
    """32 random bytes, base64url — session tokens & challenge handles."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def random_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)


# --- Cookies ---

def cookie_name(suffix: str) -> str:
    return f"{settings.app_uid}_{suffix}"


COOKIE_SESSION = cookie_name("session_token")
COOKIE_DEVICE_UID = cookie_name("device_uid")
COOKIE_TFA = cookie_name("tfa")
COOKIE_WAC = cookie_name("wac")
COOKIE_OAUTH = cookie_name("oauth")


def sign(payload: str) -> str:
    sig = hmac.new(settings.encryption_key.encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def verify_signature(cookie: str) -> str | None:
    idx = cookie.rfind(".")
    if idx < 1:
        return None
    payload, sig = cookie[:idx], cookie[idx + 1 :]
    expected = base64.urlsafe_b64encode(
        hmac.new(settings.encryption_key.encode(), payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


def pack_oauth_state(state: str, nonce: str, code_verifier: str) -> str:
    raw = json.dumps({"state": state, "nonce": nonce, "codeVerifier": code_verifier}).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unpack_oauth_state(payload: str) -> dict | None:
    try:
        pad = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload + pad)
        return json.loads(raw)
    except Exception:
        return None
