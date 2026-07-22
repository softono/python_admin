"""Ports express src/lib/auth/challenge.ts — cache-backed challenge handles
for 2FA, email-change, and WebAuthn ceremonies."""
from __future__ import annotations

import json
from dataclasses import dataclass

from app.core.cache import delete_cache, get_cache, incr_cache, set_cache
from app.core.security import random_handle

_TFA_TTL = 600
_WEBAUTHN_TTL = 300
_TFA_MAX_ATTEMPTS = 5


@dataclass
class TfaPending:
    user_id: str
    remember: bool


def _tfa_key(h: str) -> str:
    return f"auth:tfa:{h}"


def _tfa_attempts_key(h: str) -> str:
    return f"auth:tfa:attempts:{h}"


async def create_tfa_challenge(user_id: str, remember: bool) -> str:
    handle = random_handle()
    await set_cache(_tfa_key(handle), json.dumps({"userId": user_id, "remember": remember}), _TFA_TTL)
    return handle


async def peek_tfa_challenge(handle: str) -> TfaPending | None:
    raw = await get_cache(_tfa_key(handle))
    if not raw:
        return None
    d = json.loads(raw)
    return TfaPending(user_id=d["userId"], remember=d["remember"])


async def consume_tfa_challenge(handle: str) -> TfaPending | None:
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return None
    await delete_cache(_tfa_key(handle))
    await delete_cache(_tfa_attempts_key(handle))
    return pending


async def bump_tfa_attempts(handle: str) -> bool:
    count, _ = await incr_cache(_tfa_attempts_key(handle), _TFA_TTL)
    return count >= _TFA_MAX_ATTEMPTS


async def destroy_tfa_challenge(handle: str) -> None:
    await delete_cache(_tfa_key(handle))
    await delete_cache(_tfa_attempts_key(handle))


# --- email change ---

@dataclass
class EmailChangePending:
    user_id: str
    new_email: str
    new_email_verified: bool = False


def _email_change_key(h: str) -> str:
    return f"account:email-change:{h}"


def _email_change_attempts_key(h: str) -> str:
    return f"account:email-change:attempts:{h}"


async def create_email_change_challenge(user_id: str, new_email: str) -> str:
    handle = random_handle()
    await set_cache(_email_change_key(handle), json.dumps({"userId": user_id, "newEmail": new_email, "newEmailVerified": False}), _TFA_TTL)
    return handle


async def peek_email_change_challenge(handle: str) -> EmailChangePending | None:
    raw = await get_cache(_email_change_key(handle))
    if not raw:
        return None
    d = json.loads(raw)
    return EmailChangePending(user_id=d["userId"], new_email=d["newEmail"], new_email_verified=d["newEmailVerified"])


async def mark_email_change_verified(pending: EmailChangePending, handle: str) -> None:
    pending.new_email_verified = True
    await set_cache(_email_change_key(handle), json.dumps({
        "userId": pending.user_id, "newEmail": pending.new_email, "newEmailVerified": True,
    }), _TFA_TTL)


async def consume_email_change_challenge(handle: str) -> EmailChangePending | None:
    pending = await peek_email_change_challenge(handle)
    if pending is None:
        return None
    await delete_cache(_email_change_key(handle))
    await delete_cache(_email_change_attempts_key(handle))
    return pending


async def bump_email_change_attempts(handle: str) -> bool:
    count, _ = await incr_cache(_email_change_attempts_key(handle), _TFA_TTL)
    return count >= _TFA_MAX_ATTEMPTS


# --- WebAuthn ---

def _webauthn_key(h: str) -> str:
    return f"webauthn:chal:{h}"


async def create_webauthn_challenge(payload: str) -> str:
    handle = random_handle()
    await set_cache(_webauthn_key(handle), payload, _WEBAUTHN_TTL)
    return handle


async def consume_webauthn_challenge(handle: str) -> str | None:
    payload = await get_cache(_webauthn_key(handle))
    if not payload:
        return None
    await delete_cache(_webauthn_key(handle))
    return payload
