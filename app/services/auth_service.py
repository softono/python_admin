"""Ports express src/modules/auth/{auth,account}.service.ts."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import check_password, dummy_password_check, hash_password
from app.models.models import ADMIN_ROLES, STATUS_ACTIVE, User, UserAccount
from app.services import session_service
from app.services.common import log_activity, to_safe_user
from app.services.mailer_service import send_email
from app.services.otp_service import issue_otp, verify_otp
from app.services.setting_service import get_public_settings
from app.utils.client_info import ClientInfo, get_client_ip
from app.utils.response import ApiResult, err, ok


async def get_password_hash(db: AsyncSession, user_id: str) -> str:
    row = (
        await db.execute(select(UserAccount).where(UserAccount.user_id == user_id, UserAccount.provider_id == "credential"))
    ).scalar_one_or_none()
    return row.password if row and row.password else ""


async def _authenticate(
    db: AsyncSession, request: Request, email: str, password: str, remember: bool, ci: ClientInfo, require_admin: bool
) -> ApiResult:
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    role_ok = not require_admin or (user is not None and user.role in ADMIN_ROLES)
    if not user or not role_ok:
        dummy_password_check()
        return err(401, "Invalid email or password")

    if user.status != STATUS_ACTIVE:
        return err(403, "Account is disabled")

    hash_ = await get_password_hash(db, user.id)
    if not hash_:
        dummy_password_check()
        return err(401, "Invalid email or password")

    if not check_password(hash_, password):
        await log_activity(db, "LOGIN_FAILED", user.id, ci)
        return err(401, "Invalid email or password")

    settings_map = await get_public_settings(db)
    if settings_map.get("user_email_verify") == "1" and not user.email_verified:
        otp = await issue_otp(db, "verify", email)
        await send_email(db, email, "otp", {"otp": otp, "message": "Verify your account"})
        return ApiResult(403, 0, "Please verify your email before logging in",
                          {"next": "verify-account", "email": user.email})

    if user.two_factor_enabled:
        from app.services.device_service import is_device_trusted
        from app.utils.client_info import get_device_uid

        device_uid = get_device_uid(request)
        if not await is_device_trusted(db, user.id, device_uid):
            from app.services.challenge_service import create_tfa_challenge

            handle = await create_tfa_challenge(user.id, remember)
            return ApiResult(200, 1, "Two-factor authentication required", {"next": "tfa", "tfaHandle": handle})

    token, _ = await session_service.issue_session(db, request, user.id, remember)
    await log_activity(db, "LOGIN_SUCCESS", user.id, ci)

    return ok("Login successful", {"token": token, "user": to_safe_user(user)})


async def login(db: AsyncSession, request: Request, email: str, password: str, remember: bool, ci: ClientInfo) -> ApiResult:
    return await _authenticate(db, request, email, password, remember, ci, require_admin=False)


async def admin_login(db: AsyncSession, request: Request, email: str, password: str, remember: bool, ci: ClientInfo) -> ApiResult:
    return await _authenticate(db, request, email, password, remember, ci, require_admin=True)


async def logout(db: AsyncSession, token: str) -> ApiResult:
    await session_service.revoke_session(db, token)
    return ok("Logged out")


async def get_session(db: AsyncSession, token: str, tz: str) -> ApiResult:
    from app.utils.dates import date_time_format

    result = await session_service.validate_session(db, token)
    if not result:
        return err(401, "Invalid session")
    user = to_safe_user(result.user)
    user["created_at"] = date_time_format(result.user.created_at, tz)
    return ok("ok", {"user": user, "session": {
        "id": result.session.id, "expires_at": result.session.expires_at,
        "token": result.session.token, "created_at": result.session.created_at,
        "updated_at": result.session.updated_at, "ip_address": result.session.ip_address,
        "user_agent": result.session.user_agent, "user_id": result.session.user_id,
        "device_uid": result.session.device_uid, "remember": result.session.remember,
    }})


async def change_password(db: AsyncSession, user_id: str, current_password: str, new_password: str, ci: ClientInfo) -> ApiResult:
    hash_ = await get_password_hash(db, user_id)
    if not hash_:
        return err(400, "No password set")
    if not check_password(hash_, current_password):
        return err(401, "Current password is incorrect")

    new_hash = hash_password(new_password)
    row = (
        await db.execute(select(UserAccount).where(UserAccount.user_id == user_id, UserAccount.provider_id == "credential"))
    ).scalar_one_or_none()
    if row:
        row.password = new_hash
        await db.commit()

    await session_service.invalidate_user_cache(user_id)
    await session_service.revoke_user_sessions(db, user_id)
    await log_activity(db, "PASSWORD_CHANGED", user_id, ci)
    return ok("Password changed")


async def set_password(db: AsyncSession, user_id: str, new_password: str, ci: ClientInfo) -> ApiResult:
    existing = await get_password_hash(db, user_id)
    if existing:
        return err(400, "A password is already set. Use change password instead.")

    new_hash = hash_password(new_password)
    now = datetime.now(timezone.utc)
    db.add(UserAccount(
        id=str(uuid.uuid4()), account_id=user_id, provider_id="credential", user_id=user_id,
        password=new_hash, created_at=now, updated_at=now,
    ))
    await db.commit()

    await session_service.invalidate_user_cache(user_id)
    await log_activity(db, "PASSWORD_SET", user_id, ci)
    return ok("Password set")


# --- Registration / verify / reset (account.service.ts) ---

async def register(db: AsyncSession, request: Request, email: str, password: str, first_name: str, last_name: str, phone: str) -> ApiResult:
    settings_map = await get_public_settings(db)
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return err(409, "Email already registered")

    password_hash = hash_password(password)
    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()), email=email, email_verified=False, first_name=first_name,
        last_name=last_name, phone=phone, registered_ip=get_client_ip(request),
        created_at=now, updated_at=now, role="USER", status=STATUS_ACTIVE,
    )
    db.add(user)
    await db.flush()
    db.add(UserAccount(
        id=str(uuid.uuid4()), account_id=user.id, provider_id="credential", user_id=user.id,
        password=password_hash, created_at=now, updated_at=now,
    ))
    await db.commit()

    if settings_map.get("user_email_verify") == "1":
        otp = await issue_otp(db, "verify", email)
        await send_email(db, email, "otp", {
            "first_name": first_name, "last_name": last_name, "otp": otp, "message": "Verify your account",
        })
        return ApiResult(201, 1, "Registration successful. Please verify your email.",
                          {"next": "verify-account", "email": email})

    token, _ = await session_service.issue_session(db, request, user.id, False)
    return ApiResult(201, 1, "Registration successful.", {"token": token, "user": to_safe_user(user)})


async def verify_account(db: AsyncSession, email: str, otp: str) -> ApiResult:
    result = await verify_otp(db, "verify", email, otp)
    if not result.valid:
        return err(400, result.message)
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user:
        user.email_verified = True
        await db.commit()
    return ok("Email verified")


async def forgot_password(db: AsyncSession, email: str) -> ApiResult:
    neutral = ok("If the email exists, an OTP has been sent")
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        return neutral
    otp = await issue_otp(db, "reset", user.email)
    await send_email(db, user.email, "otp", {
        "first_name": user.first_name, "last_name": user.last_name, "otp": otp, "message": "Reset your password",
    })
    return neutral


async def reset_password(db: AsyncSession, email: str, otp: str, password: str) -> ApiResult:
    result = await verify_otp(db, "reset", email, otp)
    if not result.valid:
        return err(400, result.message)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        return err(404, "User not found")

    hash_ = hash_password(password)
    now = datetime.now(timezone.utc)
    existing = (
        await db.execute(select(UserAccount).where(UserAccount.user_id == user.id, UserAccount.provider_id == "credential"))
    ).scalar_one_or_none()
    if existing:
        existing.password = hash_
        await db.commit()
    else:
        db.add(UserAccount(
            id=str(uuid.uuid4()), account_id=user.id, provider_id="credential", user_id=user.id,
            password=hash_, created_at=now, updated_at=now,
        ))
        await db.commit()

    await session_service.revoke_user_sessions(db, user.id)
    return ok("Password reset successful")


async def send_otp(db: AsyncSession, email: str, otp_type: str) -> ApiResult:
    purpose = "reset" if otp_type == "reset" else "signin" if otp_type == "signin" else "verify"
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        return ok("OTP sent")
    otp = await issue_otp(db, purpose, email)
    message = {"signin": "Login", "verify": "Verify your account", "reset": "Reset your password"}.get(purpose, "Verification")
    await send_email(db, email, "otp", {
        "first_name": user.first_name, "last_name": user.last_name, "otp": otp, "message": message,
    })
    return ok("OTP sent")


async def login_with_otp(db: AsyncSession, request: Request, email: str, otp: str, remember: bool, ci: ClientInfo) -> ApiResult:
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        return err(401, "Invalid email or OTP")
    if user.status != STATUS_ACTIVE:
        return err(403, "Account is disabled")
    settings_map = await get_public_settings(db)
    if settings_map.get("user_email_verify") == "1" and not user.email_verified:
        return ApiResult(403, 0, "Please verify your email first", {"next": "verify-account", "email": email})

    result = await verify_otp(db, "signin", email, otp)
    if not result.valid:
        return err(401, result.message)

    if user.two_factor_enabled:
        from app.services.challenge_service import create_tfa_challenge

        handle = await create_tfa_challenge(user.id, remember)
        return ApiResult(200, 1, "Two-factor authentication required", {"next": "tfa", "tfaHandle": handle})

    token, _ = await session_service.issue_session(db, request, user.id, remember)
    await log_activity(db, "LOGIN_WITH_OTP", user.id, ci)
    return ok("Login successful", {"token": token, "user": to_safe_user(user)})
