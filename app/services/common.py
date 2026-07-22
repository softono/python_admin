"""Presentation/activity helpers shared by auth + account routers."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import User, UserActivity, activity_label
from app.utils.client_info import ClientInfo


def resolve_user_image(image: str | None) -> str | None:
    if not image:
        return image
    from app.core.config import settings

    return f"{settings.filesystem_url or settings.api_url}/profile/{image}"


def to_safe_user(user: User | None) -> dict[str, Any]:
    if user is None:
        return {}
    return {
        "id": user.id, "email": user.email, "email_verified": user.email_verified,
        "image": resolve_user_image(user.image), "created_at": user.created_at,
        "updated_at": user.updated_at, "two_factor_enabled": user.two_factor_enabled,
        "role": user.role, "permission": user.permission, "status": user.status,
        "first_name": user.first_name, "last_name": user.last_name, "phone": user.phone,
        "country": user.country, "timezone": user.timezone, "registered_ip": user.registered_ip,
    }


async def log_activity(db: AsyncSession, activity_type: str, user_id: str, ci: ClientInfo, data: str = "") -> None:
    if not user_id:
        return
    now = datetime.now(timezone.utc)
    db.add(UserActivity(
        id=str(uuid.uuid4()), user_id=user_id, type=activity_type,
        ip=ci.ip, client=ci.client, device_id=ci.device_id, data=data,
        created_at=now, updated_at=now,
    ))
    await db.commit()


async def log_activity_data(
    db: AsyncSession, activity_type: str, user_id: str, ci: ClientInfo,
    old_data: dict | None, new_data: dict | None,
) -> None:
    data = None
    if old_data is not None and new_data is not None:
        keys = set(old_data) | set(new_data)
        changes = [
            {"field": k, "old": old_data.get(k), "new": new_data.get(k)}
            for k in keys if old_data.get(k) != new_data.get(k)
        ]
        if changes:
            data = json.dumps(changes)
    now = datetime.now(timezone.utc)
    db.add(UserActivity(
        id=str(uuid.uuid4()), user_id=user_id, type=activity_type,
        ip=ci.ip, client=ci.client, device_id=ci.device_id, data=data,
        created_at=now, updated_at=now,
    ))
    await db.commit()


__all__ = ["to_safe_user", "resolve_user_image", "log_activity", "log_activity_data", "activity_label"]
