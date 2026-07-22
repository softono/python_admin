"""Ports Go internal/modules/auth/loginlink.go — magic-link sign-in with
polling, plus the TFA step-up variant."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import delete_cache, get_cache, set_cache
from app.core.config import settings
from app.core.security import check_password, hash_password, random_handle, random_otp
from app.models.models import STATUS_ACTIVE, User, UserLoginLink
from app.services import session_service
from app.services.challenge_service import consume_tfa_challenge, peek_tfa_challenge
from app.services.common import log_activity, to_safe_user
from app.services.device_service import trust_device
from app.services.mailer_service import send_email
from app.utils.client_info import ClientInfo, device_name, get_client_ip, get_user_agent
from app.utils.response import ApiResult, err, ok


def _context(request: Request) -> tuple[str, str]:
    return get_client_ip(request), device_name(get_user_agent(request))


async def create_signin(db: AsyncSession, request: Request, email: str, remember: bool) -> ApiResult:
    poll_token = random_handle()
    link_token = random_handle()
    code = random_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.login_link_expire_sec)
    ip, dev_name = _context(request)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    request_id = str(uuid.uuid4())

    if user is not None and user.status == STATUS_ACTIVE:
        now = datetime.now(timezone.utc)
        row = UserLoginLink(
            id=str(uuid.uuid4()), purpose="signin", email=email, user_id=user.id,
            poll_token_hash=hash_password(poll_token), link_token_hash=hash_password(link_token),
            code=code, status="pending", device_name=dev_name, ip=ip, remember=remember,
            expires_at=expires_at, created_at=now, updated_at=now,
        )
        db.add(row)
        await db.commit()
        request_id = row.id
        link = f"{settings.app_url}/login/approve?id={request_id}&token={link_token}"
        await send_email(db, user.email, "login-link", {
            "first_name": user.first_name, "last_name": user.last_name,
            "email": user.email, "link": link, "message": "Login",
        })

    return ok("If the email exists, a login link has been sent", {
        "requestId": request_id, "pollToken": poll_token, "code": code,
        "expiresAt": expires_at, "deviceName": dev_name, "location": "",
    })


async def create_tfa_login_link(db: AsyncSession, request: Request, tfa_handle: str, trust_device_flag: bool) -> ApiResult:
    pending = await peek_tfa_challenge(tfa_handle)
    if pending is None:
        return err(401, "Challenge expired")
    user = (await db.execute(select(User).where(User.id == pending.user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")

    poll_token = random_handle()
    link_token = random_handle()
    code = random_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.login_link_expire_sec)
    ip, dev_name = _context(request)
    now = datetime.now(timezone.utc)

    row = UserLoginLink(
        id=str(uuid.uuid4()), purpose="tfa", email=user.email, user_id=user.id,
        poll_token_hash=hash_password(poll_token), link_token_hash=hash_password(link_token),
        code=code, status="pending", device_name=dev_name, ip=ip, remember=pending.remember,
        tfa_handle=tfa_handle, expires_at=expires_at,
        created_at=now, updated_at=now,
    )
    db.add(row)
    await db.commit()
    # `trust_device` has no backing DB column on the shared schema (express's
    # user-login-link.ts declares it but no migration ever added it) — stash
    # it in the cache instead, keyed by link id, read back on finalize.
    if trust_device_flag:
        await set_cache(f"loginlink:trust:{row.id}", "1", settings.login_link_expire_sec)

    link = f"{settings.app_url}/login/approve?id={row.id}&token={link_token}"
    await send_email(db, user.email, "login-link", {
        "first_name": user.first_name, "last_name": user.last_name,
        "email": user.email, "link": link, "message": "Login verification",
    })

    return ok("Login link sent", {
        "requestId": row.id, "pollToken": poll_token, "code": code,
        "expiresAt": expires_at, "deviceName": dev_name, "location": "",
    })


async def _lookup_by_token(db: AsyncSession, request_id: str, link_token: str) -> UserLoginLink | None:
    row = (await db.execute(select(UserLoginLink).where(UserLoginLink.id == request_id))).scalar_one_or_none()
    if row is None:
        return None
    if not check_password(row.link_token_hash, link_token):
        return None
    return row


async def poll_login_link(db: AsyncSession, request: Request, request_id: str, poll_token: str, ci: ClientInfo) -> ApiResult:
    row = (await db.execute(select(UserLoginLink).where(UserLoginLink.id == request_id))).scalar_one_or_none()
    if row is None:
        return ok("ok", {"state": "pending"})
    if not check_password(row.poll_token_hash, poll_token):
        return ok("ok", {"state": "pending"})

    now = datetime.now(timezone.utc)
    if row.status == "pending" and row.expires_at < now:
        row.status = "expired"
        await db.commit()
        return ok("ok", {"state": "expired"})
    if row.status == "pending":
        return ok("ok", {"state": "pending"})
    if row.status == "rejected":
        return ok("ok", {"state": "rejected"})
    if row.status != "approved":
        return ok("ok", {"state": "expired"})

    # Atomically claim: only transition approved -> claimed once.
    result = await db.execute(
        update(UserLoginLink)
        .where(UserLoginLink.id == row.id, UserLoginLink.status == "approved")
        .values(status="claimed", updated_at=now)
    )
    await db.commit()
    if result.rowcount == 0:
        return ok("ok", {"state": "pending"})
    claimed = (await db.execute(select(UserLoginLink).where(UserLoginLink.id == row.id))).scalar_one_or_none()
    return await _finalize_approved_login(db, request, claimed, ci)


async def get_login_link_approval_info(db: AsyncSession, request_id: str, link_token: str) -> ApiResult:
    row = await _lookup_by_token(db, request_id, link_token)
    if row is None:
        return err(404, "Invalid or expired link")
    now = datetime.now(timezone.utc)
    if row.status != "pending" or row.expires_at < now:
        state = "expired" if row.status == "pending" else row.status
        return ok("ok", {"state": state})
    return ok("ok", {"state": "pending", "code": row.code, "deviceName": row.device_name, "location": row.location})


async def respond_login_link(db: AsyncSession, request_id: str, link_token: str, action: str) -> ApiResult:
    row = await _lookup_by_token(db, request_id, link_token)
    if row is None:
        return err(404, "Invalid or expired link")
    now = datetime.now(timezone.utc)
    if row.status != "pending" or row.expires_at < now:
        return err(400, "This link is no longer valid")

    row.status = "approved" if action == "approve" else "rejected"
    if action == "approve":
        row.approved_at = now
    await db.commit()
    message = "Login approved" if action == "approve" else "Login rejected"
    return ok(message)


async def _finalize_approved_login(db: AsyncSession, request: Request, row: UserLoginLink, ci: ClientInfo) -> ApiResult:
    if row.purpose == "tfa" and row.tfa_handle:
        if await consume_tfa_challenge(row.tfa_handle) is None:
            return err(401, "Challenge expired")

    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")

    if row.purpose == "tfa" and await get_cache(f"loginlink:trust:{row.id}"):
        await trust_device(db, request, user.id)
        await delete_cache(f"loginlink:trust:{row.id}")

    token, _ = await session_service.issue_session(db, request, user.id, row.remember)
    activity_type = "LOGIN_SUCCESS" if row.purpose == "tfa" else "LOGIN_WITH_LINK"
    await log_activity(db, activity_type, user.id, ci)

    return ok("Login successful", {
        "state": "success", "token": token, "remember": row.remember, "user": to_safe_user(user),
    })
