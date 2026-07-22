"""Redis-backed cache with an in-memory fallback (mirrors express src/lib/cache.ts)."""
from __future__ import annotations

import time

import redis.asyncio as aioredis

from app.core.config import settings

_use_redis = settings.cache_driver.lower() == "redis"
_redis: aioredis.Redis | None = aioredis.from_url(settings.redis_url) if _use_redis else None

_mem: dict[str, tuple[str, float]] = {}
_mem_counters: dict[str, tuple[int, float]] = {}


async def _redis_ok() -> bool:
    if not _use_redis or _redis is None:
        return False
    try:
        await _redis.ping()
        return True
    except Exception:
        return False


async def set_cache(key: str, value: str, ttl_seconds: int = 60) -> None:
    if await _redis_ok():
        try:
            await _redis.set(key, value, ex=ttl_seconds)
            return
        except Exception:
            pass
    _mem[key] = (value, time.time() + ttl_seconds)


async def get_cache(key: str) -> str | None:
    if await _redis_ok():
        try:
            v = await _redis.get(key)
            return v.decode() if v else None
        except Exception:
            pass
    entry = _mem.get(key)
    if not entry or time.time() > entry[1]:
        _mem.pop(key, None)
        return None
    return entry[0]


async def incr_cache(key: str, window_seconds: int = 60) -> tuple[int, int]:
    """Returns (count, ttl_seconds)."""
    if await _redis_ok():
        try:
            count = await _redis.incr(key)
            if count == 1:
                await _redis.expire(key, window_seconds)
            ttl = await _redis.ttl(key)
            return count, ttl if ttl and ttl > 0 else window_seconds
        except Exception:
            pass
    now = time.time()
    count, expire_at = _mem_counters.get(key, (0, 0.0))
    if now > expire_at:
        _mem_counters[key] = (1, now + window_seconds)
        return 1, window_seconds
    count += 1
    _mem_counters[key] = (count, expire_at)
    return count, max(int(expire_at - now), 0)


async def delete_cache(key: str) -> None:
    if await _redis_ok():
        try:
            await _redis.delete(key)
            return
        except Exception:
            pass
    _mem.pop(key, None)
    _mem_counters.pop(key, None)


async def flush_cache() -> None:
    if await _redis_ok():
        try:
            await _redis.flushall()
            return
        except Exception:
            pass
    _mem.clear()
    _mem_counters.clear()
