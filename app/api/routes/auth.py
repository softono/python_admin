"""Auth router — core session lifecycle (register/login/otp/reset/session).
Mirrors express src/modules/auth/auth.routes.ts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import (
    clear_session_cookie,
    clear_tfa_challenge_cookie,
    get_session_token,
    set_session_cookie,
    set_tfa_challenge_cookie,
)
from app.core.db import get_db
from app.core.deps import Principal, get_current_principal
from app.models.models import UserAccount
from app.services import auth_service
from app.utils.client_info import get_client_info
from app.utils.dates import get_client_timezone
from app.utils.response import ApiResult, send_error, send_result
from app.utils.validate import Validator

router = APIRouter()


def _apply_login_cookies(response: Response, result: ApiResult, remember: bool) -> None:
    if result.status != 1 or not isinstance(result.data, dict):
        return
    if token := result.data.pop("token", None):
        set_session_cookie(response, token, remember)
    elif handle := result.data.pop("tfaHandle", None):
        set_tfa_challenge_cookie(response, handle)


@router.post("/register")
async def register(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    first_name = v.person_name("first_name", "First name")
    last_name = v.person_name("last_name", "Last name")
    email = v.email()
    phone = v.phone()
    password = v.password()
    v.required_string("recaptcha_token", "reCAPTCHA verification is required")
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))

    result = await auth_service.register(db, request, email, password, first_name, last_name, phone)
    if result.status == 1 and isinstance(result.data, dict) and (token := result.data.pop("token", None)):
        set_session_cookie(response, token, False)
    return send_result(result, response)


@router.post("/login")
async def login(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    password = v.login_password()
    remember = v.boolean("remember", False)
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))

    result = await auth_service.login(db, request, email, password, remember, get_client_info(request))
    _apply_login_cookies(response, result, remember)
    return send_result(result, response)


@router.post("/login-otp")
async def login_otp(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    remember = v.boolean("remember", False)
    step = int(body.get("step", 2))
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))

    if step == 1:
        return send_result(await auth_service.send_otp(db, email, "signin"))

    otp = body.get("otp", "")
    result = await auth_service.login_with_otp(db, request, email, otp, remember, get_client_info(request))
    _apply_login_cookies(response, result, remember)
    return send_result(result, response)


@router.post("/otp")
async def send_otp_route(request: Request, db: AsyncSession = Depends(get_db)):
    from app.core.cache import incr_cache
    from app.utils.client_info import get_client_ip

    count, ttl = await incr_cache(f"otp:send:{get_client_ip(request)}", 300)
    if count > 5:
        return send_error(429, "Too many requests")

    body = await request.json()
    v = Validator(body)
    email = v.email()
    otp_type = v.optional_string("type", "verify")
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await auth_service.send_otp(db, email, otp_type))


@router.post("/forgot-password")
async def forgot_password(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await auth_service.forgot_password(db, email))


@router.post("/reset-password")
async def reset_password(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    otp = v.otp()
    password = v.password()
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await auth_service.reset_password(db, email, otp, password))


@router.post("/verify-account")
async def verify_account(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    otp = v.otp()
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await auth_service.verify_account(db, email, otp))


@router.get("/session")
async def get_session(request: Request, db: AsyncSession = Depends(get_db)):
    token = get_session_token(request)
    if not token:
        return send_error(401, "Not authenticated")
    return send_result(await auth_service.get_session(db, token, get_client_timezone(request)))


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    token = get_session_token(request)
    if not token:
        return send_error(401, "Not authenticated")
    result = await auth_service.logout(db, token)
    clear_session_cookie(response)
    return send_result(result, response)


@router.post("/change-password")
async def change_password(
    request: Request, response: Response, db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    body = await request.json()
    v = Validator(body)
    current = v.required_string("current_password", "Current password is required")
    new = v.password("new_password")
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))

    result = await auth_service.change_password(db, principal.user.id, current, new, get_client_info(request))
    if result.status == 1:
        clear_session_cookie(response)
    return send_result(result, response)


@router.post("/set-password")
async def set_password_route(
    request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal),
):
    body = await request.json()
    v = Validator(body)
    password = v.password()
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await auth_service.set_password(db, principal.user.id, password, get_client_info(request)))


@router.get("/list-accounts")
async def list_accounts(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_principal)):
    rows = (await db.execute(select(UserAccount.provider_id).where(UserAccount.user_id == principal.user.id))).scalars().all()
    return send_result(ApiResult(200, 1, "OK", [{"providerId": p} for p in rows]))
