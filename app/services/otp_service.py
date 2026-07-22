"""Ports express src/modules/auth/otp.service.ts."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import check_password, hash_password, random_otp
from app.models.models import UserVerification

_MAX_ATTEMPTS = 5


async def issue_otp(db: AsyncSession, purpose: str, email: str) -> str:
    identifier = f"{purpose}:{email.lower()}"
    otp = random_otp()
    hashed = hash_password(otp)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.otp_expire_sec)

    await db.execute(delete(UserVerification).where(UserVerification.identifier == identifier))
    db.add(UserVerification(
        id=str(uuid.uuid4()), identifier=identifier, value=hashed, expires_at=expires_at,
        attempts=0, created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    ))
    await db.commit()
    return otp


@dataclass
class OtpResult:
    valid: bool
    message: str


async def verify_otp(db: AsyncSession, purpose: str, email: str, otp: str) -> OtpResult:
    identifier = f"{purpose}:{email.lower()}"
    now = datetime.now(timezone.utc)
    record = (
        await db.execute(
            select(UserVerification)
            .where(UserVerification.identifier == identifier, UserVerification.expires_at > now)
            .order_by(UserVerification.created_at.desc())
        )
    ).scalars().first()

    if not record:
        return OtpResult(False, "OTP expired or not found")

    record.attempts += 1
    await db.commit()

    if record.attempts > _MAX_ATTEMPTS:
        await db.execute(delete(UserVerification).where(UserVerification.id == record.id))
        await db.commit()
        return OtpResult(False, "Too many failed attempts")

    if not check_password(record.value, otp):
        return OtpResult(False, "Invalid OTP")

    await db.execute(delete(UserVerification).where(UserVerification.id == record.id))
    await db.commit()
    return OtpResult(True, "OTP verified")
