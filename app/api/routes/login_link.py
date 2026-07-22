"""Login-link (magic link + polling) router — mirrors Go loginlink_routes.go."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import incr_cache
from app.core.cookies import clear_tfa_challenge_cookie, get_tfa_challenge_handle, set_session_cookie
from app.core.db import get_db
from app.services import login_link_service
from app.utils.client_info import get_client_info, get_client_ip
from app.utils.response import ApiResult, send_error, send_result
from app.utils.validate import Validator

router = APIRouter()


@router.post("/login-link")
async def login_link_create(request: Request, db: AsyncSession = Depends(get_db)):
    count, _ = await incr_cache(f"login-link:create:{get_client_ip(request)}", 300)
    if count > 5:
        return send_error(429, "Too many requests")

    body = await request.json()
    v = Validator(body)
    email = v.email()
    remember = v.boolean("remember", False)
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))
    return send_result(await login_link_service.create_signin(db, request, email, remember))


@router.post("/tfa/send-login-link")
async def tfa_send_login_link(request: Request, db: AsyncSession = Depends(get_db)):
    handle = get_tfa_challenge_handle(request)
    if not handle:
        return send_error(401, "No 2FA challenge found")
    body = await request.json()
    trust_device_flag = bool(body.get("trust_device", False))
    return send_result(await login_link_service.create_tfa_login_link(db, request, handle, trust_device_flag))


@router.get("/login-link/approve")
async def login_link_approve_get(request: Request, db: AsyncSession = Depends(get_db)):
    count, _ = await incr_cache(f"login-link:approve:{get_client_ip(request)}", 300)
    if count > 20:
        return send_error(429, "Too many requests")

    request_id = request.query_params.get("id", "")
    token = request.query_params.get("token", "")
    if not request_id or not token:
        return send_error(400, "Invalid link")
    return send_result(await login_link_service.get_login_link_approval_info(db, request_id, token))


@router.post("/login-link/approve")
async def login_link_approve_post(request: Request, db: AsyncSession = Depends(get_db)):
    count, _ = await incr_cache(f"login-link:approve:{get_client_ip(request)}", 300)
    if count > 20:
        return send_error(429, "Too many requests")

    body = await request.json()
    request_id = body.get("requestId", "")
    token = body.get("token", "")
    action = body.get("action", "")
    if action not in ("approve", "reject"):
        return send_result(ApiResult(422, 0, "Invalid action", []))
    return send_result(await login_link_service.respond_login_link(db, request_id, token, action))


@router.post("/login-link/poll")
async def login_link_poll(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    request_id = body.get("requestId", "")
    poll_token = body.get("pollToken", "")
    if not request_id or not poll_token:
        return send_result(ApiResult(422, 0, "requestId and pollToken are required", []))

    count, _ = await incr_cache(f"login-link:poll:{request_id}:{get_client_ip(request)}", 300)
    if count > 900:
        return send_error(429, "Too many requests")

    result = await login_link_service.poll_login_link(db, request, request_id, poll_token, get_client_info(request))
    if result.status == 1 and isinstance(result.data, dict) and result.data.get("state") == "success":
        remember = result.data.pop("remember", False)
        if token := result.data.pop("token", None):
            set_session_cookie(response, token, remember)
        clear_tfa_challenge_cookie(response)
    return send_result(result, response)
