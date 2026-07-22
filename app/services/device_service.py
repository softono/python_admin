"""Ports express src/modules/auth/device.service.ts."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import UserDevice
from app.utils.client_info import get_client_ip, get_device_uid, get_user_agent

_TRUST_DAYS = 30


async def is_device_trusted(db: AsyncSession, user_id: str, device_uid: str) -> bool:
    if not device_uid:
        return False
    now = datetime.now(timezone.utc)
    row = (
        await db.execute(
            select(UserDevice).where(
                UserDevice.user_id == user_id, UserDevice.device_uid == device_uid, UserDevice.expires_at > now
            )
        )
    ).scalar_one_or_none()
    return row is not None


async def trust_device(db: AsyncSession, request: Request, user_id: str) -> None:
    device_uid = get_device_uid(request)
    if not device_uid:
        return
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=_TRUST_DAYS)
    ip, ua = get_client_ip(request), get_user_agent(request)

    existing = (
        await db.execute(select(UserDevice).where(UserDevice.user_id == user_id, UserDevice.device_uid == device_uid))
    ).scalar_one_or_none()
    if existing:
        existing.trusted_at = now
        existing.expires_at = expires_at
        existing.ip_address = ip
        existing.user_agent = ua
        existing.updated_at = now
    else:
        db.add(UserDevice(
            id=str(uuid.uuid4()), user_id=user_id, device_uid=device_uid, ip_address=ip,
            user_agent=ua, trusted_at=now, expires_at=expires_at, created_at=now, updated_at=now,
        ))
    await db.commit()


async def revoke_device_trust(db: AsyncSession, user_id: str, device_uid: str) -> None:
    await db.execute(delete(UserDevice).where(UserDevice.user_id == user_id, UserDevice.device_uid == device_uid))
    await db.commit()


async def revoke_all_device_trust(db: AsyncSession, user_id: str) -> None:
    await db.execute(delete(UserDevice).where(UserDevice.user_id == user_id))
    await db.commit()
