"""Ports express src/modules/setting/settings.service.ts."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import delete_cache, get_cache, set_cache
from app.core.security import decrypt, encrypt
from app.models.models import Setting

_ENCRYPTED_KEYS = {"google_client_secret", "smtp_password", "google_recaptcha_secret_key"}
_CACHE_KEY = "setting:all"
_CACHE_TTL = 3600


async def _load_all(db: AsyncSession) -> dict[str, dict[str, str]]:
    cached = await get_cache(_CACHE_KEY)
    if cached:
        return json.loads(cached)

    rows = (await db.execute(select(Setting))).scalars().all()
    m: dict[str, dict[str, str]] = {}
    for row in rows:
        value = decrypt(row.value) if row.key in _ENCRYPTED_KEYS else row.value
        m[row.key] = {"value": value, "type": row.type}
    await set_cache(_CACHE_KEY, json.dumps(m), _CACHE_TTL)
    return m


async def get_all_settings(db: AsyncSession) -> dict[str, str]:
    m = await _load_all(db)
    return {k: v["value"] for k, v in m.items()}


async def get_public_settings(db: AsyncSession) -> dict[str, str]:
    m = await _load_all(db)
    return {k: v["value"] for k, v in m.items() if v["type"] == "public"}


async def get_setting(db: AsyncSession, key: str) -> str:
    m = await _load_all(db)
    return m.get(key, {}).get("value", "")


async def update_setting(db: AsyncSession, key: str, value: str, type_: str = "private") -> None:
    stored = encrypt(value) if key in _ENCRYPTED_KEYS else value
    existing = (await db.execute(select(Setting).where(Setting.key == key))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if existing:
        existing.value = stored
        existing.type = type_
        existing.updated_at = now
    else:
        # SQLAlchemy sends explicit NULL for unset mapped columns unless
        # server_default is declared — created_at/updated_at must be set here.
        db.add(Setting(key=key, value=stored, type=type_, created_at=now, updated_at=now))
    await db.commit()
    await invalidate_settings_cache()


async def invalidate_settings_cache() -> None:
    await delete_cache(_CACHE_KEY)
