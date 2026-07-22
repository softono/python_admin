"""Passkey (WebAuthn) router — mirrors Go passkey_routes.go."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import (
    clear_webauthn_challenge_cookie,
    get_webauthn_challenge_handle,
    set_session_cookie,
    set_webauthn_challenge_cookie,
)
from app.core.db import get_db
from app.core.deps import Principal, get_current_principal
from app.services import passkey_service
from app.utils.client_info import get_client_info
from app.utils.response import send_error, send_result

router = APIRouter()


# --- Login (public) ---

@router.post("/passkey/login-options")
async def passkey_login_options(response: Response):
    result = await passkey_service.login_options()
    if result.status == 1 and isinstance(result.data, dict):
        if handle := result.data.pop("challengeHandle", None):
            set_webauthn_challenge_cookie(response, handle)
    return send_result(result, response)


@router.post("/passkey/login-verify")
async def passkey_login_verify(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    handle = get_webauthn_challenge_handle(request)
    if not handle:
        return send_error(400, "No challenge found")

    body = await request.json()
    credential = body.get("response") or {}
    result = await passkey_service.login_verify(db, request, credential, handle, get_client_info(request))
    if result.status == 1 and isinstance(result.data, dict):
        if token := result.data.pop("token", None):
            set_session_cookie(response, token, True)
    clear_webauthn_challenge_cookie(response)
    return send_result(result, response)


# --- Management (authenticated) ---

@router.get("/passkey/list")
async def passkey_list(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    return send_result(await passkey_service.list_passkeys(db, principal.user.id))


@router.post("/passkey/delete")
async def passkey_delete(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    body = await request.json()
    passkey_id = body.get("id", "")
    if not passkey_id:
        return send_error(422, "Passkey ID is required")
    return send_result(await passkey_service.delete_passkey(db, get_client_info(request), principal.user.id, passkey_id))


@router.post("/passkey/register-options")
async def passkey_register_options(response: Response, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    result = await passkey_service.register_options(db, principal.user.id)
    if result.status == 1 and isinstance(result.data, dict):
        if handle := result.data.pop("challengeHandle", None):
            set_webauthn_challenge_cookie(response, handle)
    return send_result(result, response)


@router.post("/passkey/register-verify")
async def passkey_register_verify(request: Request, response: Response, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    handle = get_webauthn_challenge_handle(request)
    if not handle:
        return send_error(400, "No challenge found")

    body = await request.json()
    credential = body.get("response") or {}
    name = body.get("name", "")
    result = await passkey_service.register_verify(db, principal.user.id, credential, handle, name, get_client_info(request))
    clear_webauthn_challenge_cookie(response)
    return send_result(result, response)
