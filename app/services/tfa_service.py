"""Ports Go internal/modules/auth/tfa.go (TOTP + email OTP + backup codes).

Deviation note: mirrors Go's decision to store the TOTP secret as a raw
base32 string (not AES-encrypted like express's totp.ts) — Go already made
this call against the same shared DB/express source, so python follows it
for consistency across the already-verified ports.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import pyotp
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import check_password, hash_password, random_alnum
from app.models.models import User, UserTwoFactor
from app.services import session_service
from app.services.auth_service import get_password_hash
from app.services.challenge_service import (
    bump_tfa_attempts,
    consume_tfa_challenge,
    destroy_tfa_challenge,
    peek_tfa_challenge,
)
from app.services.common import log_activity, to_safe_user
from app.services.device_service import revoke_all_device_trust, trust_device
from app.services.mailer_service import send_email
from app.services.otp_service import issue_otp, verify_otp
from app.utils.client_info import ClientInfo
from app.utils.response import ApiResult, err, ok


async def _get_tfa_record(db: AsyncSession, user_id: str) -> UserTwoFactor | None:
    return (await db.execute(select(UserTwoFactor).where(UserTwoFactor.user_id == user_id))).scalar_one_or_none()


async def _require_tfa_password(db: AsyncSession, user_id: str, password: str) -> ApiResult | None:
    hash_ = await get_password_hash(db, user_id)
    if not hash_:
        return err(400, "No password set for this account")
    if not check_password(hash_, password):
        return err(401, "Invalid password")
    return None


async def _register_tfa_failure(handle: str, message: str) -> ApiResult:
    if await bump_tfa_attempts(handle):
        await destroy_tfa_challenge(handle)
        return err(429, "Too many failed attempts. Please log in again.")
    return err(401, message)


# --- backup codes ---

def _generate_backup_codes() -> tuple[list[str], list[str]]:
    plain = [random_alnum(8).upper() for _ in range(10)]
    hashed = [hash_password(c) for c in plain]
    return plain, hashed


def _verify_backup_code(code: str, hashed_codes: list[str]) -> tuple[bool, list[str]]:
    code = code.strip().upper()
    for i, h in enumerate(hashed_codes):
        if check_password(h, code):
            return True, hashed_codes[:i] + hashed_codes[i + 1 :]
    return False, hashed_codes


# --- setup / disable ---

async def setup(db: AsyncSession, user_id: str, password: str) -> ApiResult:
    if bad := await _require_tfa_password(db, user_id, password):
        return bad

    existing = await _get_tfa_record(db, user_id)
    if existing is not None and existing.verified:
        return err(400, "2FA is already enabled")

    secret = pyotp.random_base32()
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    email = user.email if user else ""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.app_name)

    plain_codes, hashed_codes = _generate_backup_codes()
    hashed_json = json.dumps(hashed_codes)

    if existing is not None:
        existing.secret = secret
        existing.backup_codes = hashed_json
    else:
        import uuid

        db.add(UserTwoFactor(id=str(uuid.uuid4()), user_id=user_id, secret=secret, backup_codes=hashed_json, verified=False))
    await db.commit()

    return ok("Scan the QR code with your authenticator app", {"totpURI": uri, "backupCodes": plain_codes})


async def verify_setup(db: AsyncSession, user_id: str, code: str, method: str, ci: ClientInfo) -> ApiResult:
    record = await _get_tfa_record(db, user_id)
    if record is None:
        return err(400, "2FA not initialized")
    if record.verified:
        return err(400, "2FA already verified")

    if method == "otp":
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is None:
            return err(404, "User not found")
        result = await verify_otp(db, "tfa", user.email, code)
        valid = result.valid
    else:
        valid = pyotp.TOTP(record.secret).verify(code, valid_window=1)

    if not valid:
        return err(400, "Invalid code")

    if method != "otp":
        record.verified = True
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is not None:
        user.two_factor_enabled = True
    await db.commit()

    await session_service.invalidate_user_cache(user_id)
    await log_activity(db, "TFA_ENABLED", user_id, ci)
    return ok("2FA enabled")


async def disable(db: AsyncSession, user_id: str, password: str, ci: ClientInfo) -> ApiResult:
    if bad := await _require_tfa_password(db, user_id, password):
        return bad
    record = await _get_tfa_record(db, user_id)
    if record is not None:
        await db.delete(record)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is not None:
        user.two_factor_enabled = False
    await db.commit()

    await revoke_all_device_trust(db, user_id)
    await session_service.invalidate_user_cache(user_id)
    await log_activity(db, "TFA_DISABLED", user_id, ci)
    return ok("2FA disabled")


async def remove_authenticator(db: AsyncSession, user_id: str, ci: ClientInfo) -> ApiResult:
    record = await _get_tfa_record(db, user_id)
    if record is None or not record.verified:
        return err(400, "Authenticator app is not configured")
    record.verified = False
    await db.commit()

    await session_service.invalidate_user_cache(user_id)
    await log_activity(db, "TFA_AUTHENTICATOR_REMOVED", user_id, ci)
    return ok("Authenticator app removed")


async def get_challenge_methods(db: AsyncSession, handle: str) -> ApiResult:
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return err(401, "Challenge expired")
    record = await _get_tfa_record(db, pending.user_id)
    methods = ["otp", "login_link"]
    if record is not None and record.verified:
        methods.append("totp")
    if record is not None:
        methods.append("backup")
    return ok("ok", {"methods": methods})


async def get_status(db: AsyncSession, user_id: str) -> ApiResult:
    record = await _get_tfa_record(db, user_id)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    enabled = bool(user.two_factor_enabled) if user else False
    verified = record is not None and bool(record.verified)
    return ok("ok", {"two_factor_enabled": enabled, "totp_verified": verified})


async def send_tfa_otp(db: AsyncSession, user_id: str) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")
    otp = await issue_otp(db, "tfa", user.email)
    await send_email(db, user.email, "otp", {
        "first_name": user.first_name, "last_name": user.last_name,
        "email": user.email, "otp": otp, "message": "Login verification",
    })
    return ok("OTP sent")


async def regenerate_backup_codes(db: AsyncSession, user_id: str, password: str, ci: ClientInfo) -> ApiResult:
    if bad := await _require_tfa_password(db, user_id, password):
        return bad
    record = await _get_tfa_record(db, user_id)
    if record is None or not record.verified:
        return err(400, "2FA not enabled")
    plain_codes, hashed_codes = _generate_backup_codes()
    record.backup_codes = json.dumps(hashed_codes)
    await db.commit()
    await log_activity(db, "BACKUP_CODES_REGENERATED", user_id, ci)
    return ok("Backup codes regenerated", {"backupCodes": plain_codes})


# --- login-challenge verification ---

async def _tfa_login_success(db: AsyncSession, request: Request, user_id: str, trust_device_flag: bool, remember: bool, ci: ClientInfo) -> ApiResult:
    if trust_device_flag:
        await trust_device(db, request, user_id)
    token, _ = await session_service.issue_session(db, request, user_id, remember)
    await log_activity(db, "LOGIN_SUCCESS", user_id, ci)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    return ok("Login successful", {"token": token, "user": to_safe_user(user)})


async def verify_totp_login(db: AsyncSession, request: Request, handle: str, code: str, ci: ClientInfo, trust_device_flag: bool) -> ApiResult:
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return err(401, "Challenge expired")
    record = await _get_tfa_record(db, pending.user_id)
    if record is None or not record.verified:
        return err(400, "2FA not configured")
    if not pyotp.TOTP(record.secret).verify(code, valid_window=1):
        return await _register_tfa_failure(handle, "Invalid code")
    await consume_tfa_challenge(handle)
    return await _tfa_login_success(db, request, pending.user_id, trust_device_flag, pending.remember, ci)


async def verify_otp_login(db: AsyncSession, request: Request, handle: str, code: str, ci: ClientInfo, trust_device_flag: bool) -> ApiResult:
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return err(401, "Challenge expired")
    user = (await db.execute(select(User).where(User.id == pending.user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")
    result = await verify_otp(db, "tfa", user.email, code)
    if not result.valid:
        return await _register_tfa_failure(handle, result.message)
    await consume_tfa_challenge(handle)
    return await _tfa_login_success(db, request, pending.user_id, trust_device_flag, pending.remember, ci)


async def verify_backup_login(db: AsyncSession, request: Request, handle: str, code: str, ci: ClientInfo, trust_device_flag: bool) -> ApiResult:
    pending = await peek_tfa_challenge(handle)
    if pending is None:
        return err(401, "Challenge expired")
    record = await _get_tfa_record(db, pending.user_id)
    if record is None:
        return err(400, "2FA not configured")
    hashed_codes = json.loads(record.backup_codes)
    valid, remaining = _verify_backup_code(code, hashed_codes)
    if not valid:
        return await _register_tfa_failure(handle, "Invalid backup code")
    record.backup_codes = json.dumps(remaining)
    await db.commit()

    await consume_tfa_challenge(handle)
    return await _tfa_login_success(db, request, pending.user_id, trust_device_flag, pending.remember, ci)
