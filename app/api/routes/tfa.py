"""TFA router — login-challenge verification (public, gated by signed tfa
cookie) + authenticated 2FA management. Mirrors Go tfa_routes.go."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import (
    clear_tfa_challenge_cookie,
    get_tfa_challenge_handle,
    get_session_token,
    set_session_cookie,
)
from app.core.db import get_db
from app.core.deps import Principal, get_current_principal
from app.services import tfa_service
from app.services.challenge_service import peek_tfa_challenge
from app.services.session_service import validate_session
from app.utils.client_info import get_client_info
from app.utils.response import ApiResult, send_error, send_result

router = APIRouter()


@router.get("/tfa/methods")
async def tfa_methods(request: Request, db: AsyncSession = Depends(get_db)):
    handle = get_tfa_challenge_handle(request)
    if not handle:
        return send_error(401, "No 2FA challenge found")
    return send_result(await tfa_service.get_challenge_methods(db, handle))


@router.post("/tfa/send-otp")
async def tfa_send_otp(request: Request, db: AsyncSession = Depends(get_db)):
    token = get_session_token(request)
    if token:
        result = await validate_session(db, token)
        if result is not None:
            return send_result(await tfa_service.send_tfa_otp(db, result.user.id))

    handle = get_tfa_challenge_handle(request)
    if not handle:
        return send_error(401, "No 2FA challenge found")
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return send_error(401, "Challenge expired")
    return send_result(await tfa_service.send_tfa_otp(db, pending.user_id))


@router.post("/tfa/verify")
async def tfa_verify(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    handle = get_tfa_challenge_handle(request)
    if not handle:
        return send_error(401, "No 2FA challenge found")

    body = await request.json()
    code = body.get("code", "")
    method = body.get("method", "")
    trust_device_flag = bool(body.get("trust_device", False))
    if not code:
        return send_result(ApiResult(422, 0, "Code is required", {"errors": {"code": "Code is required"}}))

    ci = get_client_info(request)
    if method == "totp":
        result = await tfa_service.verify_totp_login(db, request, handle, code, ci, trust_device_flag)
    elif method == "backup":
        result = await tfa_service.verify_backup_login(db, request, handle, code, ci, trust_device_flag)
    else:
        result = await tfa_service.verify_otp_login(db, request, handle, code, ci, trust_device_flag)

    if result.status == 1 and isinstance(result.data, dict):
        if token := result.data.pop("token", None):
            set_session_cookie(response, token, True)
        clear_tfa_challenge_cookie(response)
    return send_result(result, response)


@router.get("/2fa/status")
async def tfa_status(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    return send_result(await tfa_service.get_status(db, principal.user.id))


@router.post("/2fa/enable")
async def tfa_enable(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    body = await request.json()
    return send_result(await tfa_service.setup(db, principal.user.id, body.get("password", "")))


@router.post("/2fa/disable")
async def tfa_disable(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    body = await request.json()
    return send_result(await tfa_service.disable(db, principal.user.id, body.get("password", ""), get_client_info(request)))


@router.post("/2fa/verify-setup")
async def tfa_verify_setup(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    body = await request.json()
    method = body.get("method") or "totp"
    return send_result(await tfa_service.verify_setup(db, principal.user.id, body.get("code", ""), method, get_client_info(request)))


@router.post("/2fa/backup-codes")
async def tfa_backup_codes(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    body = await request.json()
    return send_result(await tfa_service.regenerate_backup_codes(db, principal.user.id, body.get("password", ""), get_client_info(request)))


@router.post("/2fa/remove-authenticator")
async def tfa_remove_authenticator(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    return send_result(await tfa_service.remove_authenticator(db, principal.user.id, get_client_info(request)))
