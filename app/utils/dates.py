"""Server-side date formatting with client-timezone-cookie support (mirrors
express src/lib/date.ts)."""
from __future__ import annotations

import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Request

from app.core.config import settings

_TZ_ALIASES = {
    "Asia/Calcutta": "Asia/Kolkata",
    "Asia/Katmandu": "Asia/Kathmandu",
    "US/Eastern": "America/New_York",
    "US/Central": "America/Chicago",
    "US/Pacific": "America/Los_Angeles",
    "US/Mountain": "America/Denver",
}


def _in_zone(dt: datetime.datetime, tz: str | None) -> datetime.datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    if not tz:
        return dt.astimezone(datetime.timezone.utc)
    try:
        return dt.astimezone(ZoneInfo(tz))
    except ZoneInfoNotFoundError:
        return dt.astimezone(datetime.timezone.utc)


def date_time_format(dt: datetime.datetime | None, tz: str | None = None) -> str:
    if dt is None:
        return ""
    return _in_zone(dt, tz).strftime("%Y-%m-%d %H:%M:%S")


def date_format(dt: datetime.datetime | None, tz: str | None = None) -> str:
    if dt is None:
        return ""
    z = _in_zone(dt, tz)
    return f"{z.strftime('%B')} {z.day}, {z.year}"


def get_client_timezone(request: Request) -> str:
    cookie_name = f"{settings.app_uid}_tz"
    raw = request.cookies.get(cookie_name)
    if not raw:
        return settings.app_timezone
    return _TZ_ALIASES.get(raw, raw)
