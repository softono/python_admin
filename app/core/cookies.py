"""Cookie set/get helpers over a Starlette Response/Request — mirrors
express src/utils/authCookie.ts attrs and names exactly."""
from __future__ import annotations

from fastapi import Request, Response

from app.core.config import settings
from app.core.security import (
    COOKIE_DEVICE_UID,
    COOKIE_OAUTH,
    COOKIE_SESSION,
    COOKIE_TFA,
    COOKIE_WAC,
    pack_oauth_state,
    sign,
    unpack_oauth_state,
    verify_signature,
)

_IS_PROD = settings.app_env == "production"


def _set(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, samesite="lax", secure=_IS_PROD, path="/")


def _clear(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/")


def get_session_token(request: Request) -> str:
    return request.cookies.get(COOKIE_SESSION, "")


def set_session_cookie(response: Response, token: str, remember: bool = False) -> None:
    _set(response, COOKIE_SESSION, token, 30 * 86400 if remember else 86400)


def clear_session_cookie(response: Response) -> None:
    _clear(response, COOKIE_SESSION)


def set_tfa_challenge_cookie(response: Response, handle: str) -> None:
    _set(response, COOKIE_TFA, sign(handle), 600)


def get_tfa_challenge_handle(request: Request) -> str:
    v = request.cookies.get(COOKIE_TFA, "")
    if not v:
        return ""
    payload = verify_signature(v)
    return payload or ""


def clear_tfa_challenge_cookie(response: Response) -> None:
    _clear(response, COOKIE_TFA)


def set_webauthn_challenge_cookie(response: Response, handle: str) -> None:
    _set(response, COOKIE_WAC, sign(handle), 300)


def get_webauthn_challenge_handle(request: Request) -> str:
    v = request.cookies.get(COOKIE_WAC, "")
    if not v:
        return ""
    return verify_signature(v) or ""


def clear_webauthn_challenge_cookie(response: Response) -> None:
    _clear(response, COOKIE_WAC)


def set_oauth_state_cookie(response: Response, state: str, nonce: str, code_verifier: str) -> None:
    payload = pack_oauth_state(state, nonce, code_verifier)
    _set(response, COOKIE_OAUTH, sign(payload), 600)


def get_oauth_state(request: Request) -> dict | None:
    v = request.cookies.get(COOKIE_OAUTH, "")
    if not v:
        return None
    payload = verify_signature(v)
    if not payload:
        return None
    return unpack_oauth_state(payload)


def clear_oauth_state_cookie(response: Response) -> None:
    _clear(response, COOKIE_OAUTH)
