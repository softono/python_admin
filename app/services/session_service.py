"""Ports express src/modules/auth/session.service.ts: opaque token session
lifecycle with cache-backed sliding expiry."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import delete_cache, get_cache, set_cache
from app.core.security import random_handle
from app.models.models import STATUS_ACTIVE, User, UserSession
from app.utils.client_info import get_client_ip, get_device_uid, get_user_agent

_SESSION_TTL = 300
_USER_TTL = 300
_UPDATE_AGE = timedelta(hours=24)


def _session_key(token: str) -> str:
    return f"auth:session:{token}"


def _user_key(user_id: str) -> str:
    return f"auth:user:{user_id}"


def _session_to_dict(s: UserSession) -> dict:
    return {
        "id": s.id, "expires_at": s.expires_at.isoformat(), "token": s.token,
        "created_at": s.created_at.isoformat(), "updated_at": s.updated_at.isoformat(),
        "ip_address": s.ip_address, "user_agent": s.user_agent, "user_id": s.user_id,
        "device_uid": s.device_uid, "remember": s.remember,
    }


def _parse_dt(v: str) -> datetime:
    return datetime.fromisoformat(v)


@dataclass
class SessionWithUser:
    session: UserSession
    user: User


async def issue_session(db: AsyncSession, request: Request, user_id: str, remember: bool = False) -> tuple[str, UserSession]:
    ttl_days = 30 if remember else 1
    token = random_handle()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=ttl_days)

    session = UserSession(
        id=str(uuid.uuid4()), token=token, user_id=user_id, expires_at=expires_at,
        created_at=now, updated_at=now, ip_address=get_client_ip(request),
        user_agent=get_user_agent(request), device_uid=get_device_uid(request), remember=remember,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    await set_cache(_session_key(token), json.dumps(_session_to_dict(session)), _SESSION_TTL)
    return token, session


async def validate_session(db: AsyncSession, token: str) -> SessionWithUser | None:
    session: UserSession | None = None

    cached = await get_cache(_session_key(token))
    if cached:
        d = json.loads(cached)
        session = UserSession(
            id=d["id"], token=d["token"], user_id=d["user_id"],
            expires_at=_parse_dt(d["expires_at"]), created_at=_parse_dt(d["created_at"]),
            updated_at=_parse_dt(d["updated_at"]), ip_address=d["ip_address"],
            user_agent=d["user_agent"], device_uid=d["device_uid"], remember=d["remember"],
        )
    else:
        session = (await db.execute(select(UserSession).where(UserSession.token == token))).scalar_one_or_none()
        if not session:
            return None
        await set_cache(_session_key(token), json.dumps(_session_to_dict(session)), _SESSION_TTL)

    now = datetime.now(timezone.utc)
    expires_at = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        await revoke_session(db, token)
        return None

    updated_at = session.updated_at if session.updated_at.tzinfo else session.updated_at.replace(tzinfo=timezone.utc)
    if now - updated_at > _UPDATE_AGE:
        ttl_days = 30 if session.remember else 1
        new_expiry = now + timedelta(days=ttl_days)
        db_session = await db.get(UserSession, session.id)
        if db_session:
            db_session.expires_at = new_expiry
            db_session.updated_at = now
            await db.commit()
        session.expires_at = new_expiry
        session.updated_at = now
        await set_cache(_session_key(token), json.dumps(_session_to_dict(session)), _SESSION_TTL)

    user: User | None = None
    cached_user = await get_cache(_user_key(session.user_id))
    if cached_user:
        ud = json.loads(cached_user)
        user = User(**{k: (v if k not in ("created_at", "updated_at") else _parse_dt(v)) for k, v in ud.items()})
    else:
        user = await db.get(User, session.user_id)
        if not user:
            return None
        await set_cache(_user_key(user.id), json.dumps(_user_to_dict(user)), _USER_TTL)

    if user.status != STATUS_ACTIVE:
        return None

    return SessionWithUser(session=session, user=user)


def _user_to_dict(u: User) -> dict:
    return {
        "id": u.id, "email": u.email, "email_verified": u.email_verified, "image": u.image,
        "created_at": u.created_at.isoformat(), "updated_at": u.updated_at.isoformat(),
        "two_factor_enabled": u.two_factor_enabled, "role": u.role, "permission": u.permission,
        "status": u.status, "first_name": u.first_name, "last_name": u.last_name,
        "phone": u.phone, "country": u.country, "timezone": u.timezone, "registered_ip": u.registered_ip,
    }


async def revoke_session(db: AsyncSession, token: str) -> None:
    await db.execute(delete(UserSession).where(UserSession.token == token))
    await db.commit()
    await delete_cache(_session_key(token))


async def revoke_user_sessions(db: AsyncSession, user_id: str) -> None:
    tokens = (await db.execute(select(UserSession.token).where(UserSession.user_id == user_id))).scalars().all()
    if tokens:
        await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
        await db.commit()
        for t in tokens:
            await delete_cache(_session_key(t))
    await delete_cache(_user_key(user_id))


async def invalidate_user_cache(user_id: str) -> None:
    await delete_cache(_user_key(user_id))


async def invalidate_session_cache(token: str) -> None:
    await delete_cache(_session_key(token))
